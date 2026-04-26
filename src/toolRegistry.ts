import { Tool, BashTool, FileEditTool, FileReadTool, FileWriteTool, WebFetchTool } from "./tools"

export type ToolSource = "builtin" | "custom" | "mcp"

export interface ToolMetadata {
  source: ToolSource
  mcpServer?: string
  readOnly?: boolean
  destructive?: boolean
  openWorld?: boolean
  concurrencySafe?: boolean
}

export interface ToolRegistration {
  tool: Tool
  metadata: ToolMetadata
}

const MCP_TOOL_PATTERN = /^mcp__([^_]+)__(.+)$/

function inferToolMetadata(toolName: string, metadata: Partial<ToolMetadata> = {}): ToolMetadata {
  const existing = { ...metadata }
  if (existing.source) {
    return existing as ToolMetadata
  }

  const match = MCP_TOOL_PATTERN.exec(toolName)
  if (match) {
    return {
      source: "mcp",
      mcpServer: match[1],
      ...existing,
    }
  }

  return {
    source: "custom",
    ...existing,
  }
}

function uniqueExistingPaths(paths: string[]): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const path of paths) {
    if (!path || seen.has(path)) continue
    seen.add(path)
    result.push(path)
  }
  return result
}

function defaultSafePathEntries(): string[] {
  const homeBunBin = process.env.HOME ? `${process.env.HOME}/.bun/bin` : ""
  return uniqueExistingPaths([
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    homeBunBin,
  ].filter(Boolean))
}

export class ToolRegistry {
  private tools = new Map<string, ToolRegistration>()

  register(tool: Tool, metadata: Partial<ToolMetadata> = {}): ToolRegistration {
    const registration: ToolRegistration = {
      tool,
      metadata: inferToolMetadata(tool.name, metadata),
    }
    this.tools.set(tool.name, registration)
    return registration
  }

  registerAll(tools: Record<string, Tool>, metadata: Partial<ToolMetadata> = {}): void {
    for (const tool of Object.values(tools)) {
      this.register(tool, metadata)
    }
  }

  get(toolName: string): Tool | undefined {
    return this.tools.get(toolName)?.tool
  }

  getRegistration(toolName: string): ToolRegistration | undefined {
    return this.tools.get(toolName)
  }

  has(toolName: string): boolean {
    return this.tools.has(toolName)
  }

  list(): Array<{ name: string; metadata: ToolMetadata }> {
    return [...this.tools.entries()].map(([name, registration]) => ({
      name,
      metadata: registration.metadata,
    }))
  }
}

export function createDefaultToolRegistry(extraTools: Record<string, Tool> = {}): ToolRegistry {
  const registry = new ToolRegistry()
  registry.register(new FileReadTool(), {
    source: "builtin",
    readOnly: true,
    concurrencySafe: true,
  })
  registry.register(new BashTool(), {
    source: "builtin",
    openWorld: true,
  })
  registry.register(new FileWriteTool(), {
    source: "builtin",
    destructive: true,
  })
  registry.register(new FileEditTool(), {
    source: "builtin",
    destructive: true,
  })
  registry.register(new WebFetchTool(), {
    source: "builtin",
    openWorld: true,
  })

  registry.registerAll(extraTools)
  return registry
}

export function defaultSafePath(): string {
  const safeEntries = defaultSafePathEntries()
  return safeEntries.length > 0 ? safeEntries.join(":") : "/usr/bin:/bin:/usr/sbin:/sbin"
}
