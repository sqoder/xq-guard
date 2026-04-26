import { ToolRegistry } from "../toolRegistry"
import { Tool } from "../tools"
import { ToolContext, ToolRunResult } from "./types"

const MCP_TOOL_PATTERN = /^mcp__([^_]+)__(.+)$/

export interface McpToolName {
  serverName: string
  toolName?: string
  isServerWildcard: boolean
}

export function parseMcpToolName(toolName: string): McpToolName | undefined {
  const match = MCP_TOOL_PATTERN.exec(toolName)
  if (!match) return undefined

  return {
    serverName: match[1],
    toolName: match[2] === "*" ? undefined : match[2],
    isServerWildcard: match[2] === "*",
  }
}

export function buildMcpServerRule(serverName: string): string {
  return `mcp__${serverName}__*`
}

export interface McpToolDescriptor {
  name: string
  description?: string
  readOnly?: boolean
  destructive?: boolean
  openWorld?: boolean
  validate?: (input: unknown) => { ok: boolean; msg?: string }
}

export interface McpClientManager {
  listTools(serverName: string): Promise<McpToolDescriptor[]>
  callTool(
    serverName: string,
    toolName: string,
    input: unknown,
    ctx: ToolContext,
  ): Promise<unknown>
}

function normalizeMcpToolName(serverName: string, toolName: string): string {
  const parsed = parseMcpToolName(toolName)
  if (parsed?.serverName === serverName && parsed.toolName) {
    return toolName
  }
  return `mcp__${serverName}__${toolName}`
}

function validateMcpInput(input: unknown): { ok: boolean; msg?: string } {
  if (input === undefined) {
    return { ok: true }
  }
  if (typeof input === "object" && input !== null && !Array.isArray(input)) {
    return { ok: true }
  }
  return { ok: false, msg: "MCP tool input must be an object" }
}

function normalizeMcpCallResult(result: unknown): ToolRunResult {
  if (
    typeof result === "object" &&
    result !== null &&
    "ok" in result &&
    typeof (result as { ok?: unknown }).ok === "boolean"
  ) {
    const ok = (result as { ok: boolean }).ok
    const output = (result as { output?: unknown }).output
    const error = (result as { error?: unknown }).error
    return {
      ok,
      output:
        typeof output === "string"
          ? output
          : output === undefined
            ? ""
            : JSON.stringify(output),
      error:
        typeof error === "string"
          ? error
          : error === undefined
            ? undefined
            : JSON.stringify(error),
    }
  }

  if (typeof result === "string") {
    return {
      ok: true,
      output: result,
    }
  }

  if (result === undefined || result === null) {
    return {
      ok: true,
      output: "(No output)",
    }
  }

  return {
    ok: true,
    output: JSON.stringify(result),
  }
}

export class McpProxyTool extends Tool {
  name: string
  private serverName: string
  private remoteToolName: string
  private manager: McpClientManager
  private customValidate?: (input: unknown) => { ok: boolean; msg?: string }

  constructor(
    name: string,
    serverName: string,
    remoteToolName: string,
    manager: McpClientManager,
    customValidate?: (input: unknown) => { ok: boolean; msg?: string },
  ) {
    super()
    this.name = name
    this.serverName = serverName
    this.remoteToolName = remoteToolName
    this.manager = manager
    this.customValidate = customValidate
  }

  validate(input: unknown) {
    if (this.customValidate) {
      return this.customValidate(input)
    }
    return validateMcpInput(input)
  }

  async run(input: unknown, ctx: ToolContext): Promise<ToolRunResult> {
    try {
      const result = await this.manager.callTool(
        this.serverName,
        this.remoteToolName,
        input,
        ctx,
      )
      return normalizeMcpCallResult(result)
    } catch (error: any) {
      return {
        ok: false,
        output: "",
        error: `MCP call failed: ${error?.message || String(error)}`,
      }
    }
  }
}

function registerMcpDescriptor(
  registry: ToolRegistry,
  manager: McpClientManager,
  serverName: string,
  descriptor: McpToolDescriptor,
) {
  const name = normalizeMcpToolName(serverName, descriptor.name)
  const parsed = parseMcpToolName(name)
  if (!parsed?.toolName) return

  if (registry.has(name)) {
    return
  }

  registry.register(
    new McpProxyTool(
      name,
      parsed.serverName,
      parsed.toolName,
      manager,
      descriptor.validate,
    ),
    {
      source: "mcp",
      mcpServer: parsed.serverName,
      readOnly: descriptor.readOnly,
      destructive: descriptor.destructive,
      openWorld: descriptor.openWorld,
    },
  )
}

export async function registerMcpServerTools(
  registry: ToolRegistry,
  manager: McpClientManager,
  serverName: string,
): Promise<void> {
  const descriptors = await manager.listTools(serverName)
  for (const descriptor of descriptors) {
    registerMcpDescriptor(registry, manager, serverName, descriptor)
  }
}

export class McpToolResolver {
  private serverLoads = new Map<string, Promise<void>>()
  private registry: ToolRegistry
  private manager: McpClientManager

  constructor(registry: ToolRegistry, manager: McpClientManager) {
    this.registry = registry
    this.manager = manager
  }

  async ensureTool(toolName: string): Promise<boolean> {
    if (this.registry.has(toolName)) {
      return true
    }

    const parsed = parseMcpToolName(toolName)
    if (!parsed?.toolName) {
      return false
    }

    await this.loadServer(parsed.serverName)
    return this.registry.has(toolName)
  }

  private async loadServer(serverName: string): Promise<void> {
    const existing = this.serverLoads.get(serverName)
    if (existing) {
      return existing
    }

    const loadPromise = registerMcpServerTools(
      this.registry,
      this.manager,
      serverName,
    )
      .catch(error => {
        this.serverLoads.delete(serverName)
        throw error
      })
    this.serverLoads.set(serverName, loadPromise)
    await loadPromise
  }
}
