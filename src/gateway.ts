import { randomUUID } from "crypto"
import { PermissionEngine } from "./engine"
import { createCliPermissionRequestHandler } from "./permissionEvents"
import { buildPermissionSuggestions } from "./permissionSuggestions"
import {
  McpClientManager,
  McpToolResolver,
} from "./permissions/mcp"
import { permissionUpdateFromRule } from "./permissions/permissionUpdate"
import {
  GatewayExecuteResult,
  PermissionDecision,
  PermissionGatewayEvent,
  PermissionRequestHandler,
  PermissionResponse,
  ToolContext,
} from "./types"
import { Tool } from "./tools"
import { ToolRegistry, createDefaultToolRegistry } from "./toolRegistry"

export interface GatewayOptions {
  engine: PermissionEngine
  ctx: ToolContext
  tools?: Record<string, Tool>
  registry?: ToolRegistry
  permissionRequestHandler?: PermissionRequestHandler
  onPermissionEvent?: (event: PermissionGatewayEvent) => void
  mcp?: {
    clientManager: McpClientManager
  }
}

export class PermissionGateway {
  private engine: PermissionEngine
  private ctx: ToolContext
  private registry: ToolRegistry
  private permissionRequestHandler?: PermissionRequestHandler
  private onPermissionEvent?: (event: PermissionGatewayEvent) => void
  private mcpResolver?: McpToolResolver

  constructor(options: GatewayOptions) {
    this.engine = options.engine
    this.ctx = options.ctx
    this.registry = options.registry || createDefaultToolRegistry(options.tools)
    this.permissionRequestHandler = options.permissionRequestHandler
    this.onPermissionEvent = options.onPermissionEvent
    if (options.mcp?.clientManager) {
      this.mcpResolver = new McpToolResolver(
        this.registry,
        options.mcp.clientManager,
      )
    }
  }

  private emitPermissionEvent(event: PermissionGatewayEvent) {
    this.onPermissionEvent?.(event)
  }

  private async resolveTool(toolName: string): Promise<{
    tool?: Tool
    resolutionError?: string
  }> {
    const registered = this.registry.get(toolName)
    if (registered) {
      return { tool: registered }
    }

    if (!this.mcpResolver) {
      return {}
    }

    try {
      const resolved = await this.mcpResolver.ensureTool(toolName)
      if (!resolved) {
        return {}
      }
      return {
        tool: this.registry.get(toolName),
      }
    } catch (error: any) {
      return {
        resolutionError: `MCP tool resolution failed: ${error?.message || String(error)}`,
      }
    }
  }

  async execute(toolName: string, input: any): Promise<GatewayExecuteResult> {
    const { tool, resolutionError } = await this.resolveTool(toolName)

    if (!tool) {
      const decision = {
        behavior: "deny" as const,
        reason: resolutionError || `Tool ${toolName} not found`,
      }
      this.engine.logAudit({
        toolName,
        input: JSON.stringify(input),
        decision,
        time: new Date().toISOString(),
      })
      return { decision }
    }

    const validation = tool.validate(input)
    if (!validation.ok) {
      const decision = {
        behavior: "deny" as const,
        reason: validation.msg || "Invalid input",
      }
      this.engine.logAudit({
        toolName,
        input: JSON.stringify(input),
        decision,
        time: new Date().toISOString(),
      })
      return { decision }
    }

    const toolDecision = await this.evaluateToolPermissions(tool, input)
    if (toolDecision?.behavior === "deny") {
      this.engine.logAudit({
        toolName,
        input: JSON.stringify(input),
        decision: toolDecision,
        time: new Date().toISOString(),
      })
      return { decision: toolDecision }
    }

    let decision = await this.engine.decide(
      toolName,
      JSON.stringify(input),
      this.ctx,
    )
    if (toolDecision?.behavior === "ask" && decision.behavior !== "deny") {
      decision = {
        behavior: "ask",
        reason: toolDecision.reason,
      }
    }

    if (decision.behavior === "ask") {
      decision = await this.handleAsk(
        toolName,
        input,
        decision as { behavior: "ask"; reason: string },
      )
    }

    if (decision.behavior !== "allow") {
      this.engine.logAudit({
        toolName,
        input: JSON.stringify(input),
        decision,
        time: new Date().toISOString(),
      })
      return { decision }
    }

    if (toolName === "FileWrite" || toolName === "FileEdit") {
      const writeSafety = this.engine.checkWriteSafety(input.path, this.ctx, {
        allowCreate: toolName === "FileWrite",
      })
      if (!writeSafety.ok) {
        const deny = {
          behavior: "deny" as const,
          reason: writeSafety.reason || "Unsafe write",
        }
        this.engine.logAudit({
          toolName,
          input: JSON.stringify(input),
          decision: deny,
          time: new Date().toISOString(),
        })
        return { decision: deny }
      }
    }

    const result = await tool.run(input, this.ctx)

    if (toolName === "FileRead" && result.ok) {
      this.engine.recordFileRead(input.path, this.ctx)
    }

    if ((toolName === "FileWrite" || toolName === "FileEdit") && result.ok) {
      this.engine.recordFileRead(input.path, this.ctx)
    }

    this.engine.logAudit({
      toolName,
      input: JSON.stringify(input),
      decision,
      time: new Date().toISOString(),
      result: result.ok ? result.output : result.error,
    })

    return { decision, result }
  }

  private async evaluateToolPermissions(
    tool: Tool,
    input: any,
  ): Promise<PermissionDecision | null> {
    const candidate = tool as Tool & {
      checkPermissions?: (
        input: any,
        ctx: ToolContext,
      ) => Promise<PermissionDecision | null> | PermissionDecision | null
      checkPhysicalSafety?: (
        input: any,
        ctx: ToolContext,
      ) => Promise<PermissionDecision | null> | PermissionDecision | null
    }

    const hasCustomCheckPermissions =
      typeof candidate.checkPermissions === "function" &&
      candidate.checkPermissions !== Tool.prototype.checkPermissions
    const hasCustomCheckPhysicalSafety =
      typeof candidate.checkPhysicalSafety === "function" &&
      candidate.checkPhysicalSafety !== Tool.prototype.checkPhysicalSafety

    if (hasCustomCheckPermissions) {
      return await candidate.checkPermissions(input, this.ctx)
    }

    if (hasCustomCheckPhysicalSafety) {
      return await candidate.checkPhysicalSafety(input, this.ctx)
    }

    return null
  }

  private async handleAsk(
    toolName: string,
    input: any,
    decision: { behavior: "ask"; reason: string },
  ): Promise<PermissionDecision> {
    const suggestions = buildPermissionSuggestions(toolName, input)
    const requestId = randomUUID()
    const requestedEvent = {
      type: "permission.requested" as const,
      requestId,
      toolName,
      input,
      reason: decision.reason,
      suggestions,
      mode: this.ctx.mode,
      cwd: this.ctx.cwd,
    }
    this.emitPermissionEvent(requestedEvent)

    const responder =
      this.permissionRequestHandler ||
      (this.ctx.interactive ? createCliPermissionRequestHandler() : undefined)

    if (!responder) {
      const denied: PermissionDecision = {
        behavior: "deny",
        reason: "Auto-deny in non-interactive mode",
        suggestions,
      }
      this.emitPermissionEvent({
        type: "permission.responded",
        requestId,
        toolName,
        input,
        decision: denied.behavior,
        reason: denied.reason,
      })
      return denied
    }

    let response: PermissionResponse
    try {
      response = await responder(requestedEvent)
    } catch (error: any) {
      const denied: PermissionDecision = {
        behavior: "deny",
        reason: `Permission responder failed: ${error?.message || String(error)}`,
        suggestions,
      }
      this.emitPermissionEvent({
        type: "permission.responded",
        requestId,
        toolName,
        input,
        decision: denied.behavior,
        reason: denied.reason,
      })
      return denied
    }

    const selectedSuggestion =
      typeof response.suggestionKey === "string"
        ? suggestions.find(
            suggestion => suggestion.key === response.suggestionKey,
          )
        : undefined

    if (response.suggestionKey && !selectedSuggestion) {
      const denied: PermissionDecision = {
        behavior: "deny",
        reason: `Unknown permission suggestion key: ${response.suggestionKey}`,
        suggestions,
      }
      this.emitPermissionEvent({
        type: "permission.responded",
        requestId,
        toolName,
        input,
        decision: denied.behavior,
        reason: denied.reason,
        suggestionKey: response.suggestionKey,
      })
      return denied
    }

    let updates: PermissionDecision["updates"]
    let metadata: PermissionDecision["metadata"]
    const ruleToPersist =
      response.rule ||
      (selectedSuggestion &&
      selectedSuggestion.behavior === response.decision
        ? selectedSuggestion.rule
        : undefined)

    if (ruleToPersist) {
      const savedRule = await this.engine.saveRule(ruleToPersist)
      updates = [permissionUpdateFromRule(savedRule)]
      metadata = {
        savedRuleId: savedRule.id,
        savedRuleSource: savedRule.source,
      }
    }

    const permissionDecision: PermissionDecision = {
      behavior: response.decision,
      reason:
        response.reason ||
        (ruleToPersist
          ? `User saved ${response.decision} rule`
          : response.decision === "allow"
            ? "User approved once"
            : "User rejected"),
      suggestions,
      updates,
      metadata,
    }

    this.emitPermissionEvent({
      type: "permission.responded",
      requestId,
      toolName,
      input,
      decision: permissionDecision.behavior,
      reason: permissionDecision.reason,
      suggestionKey: response.suggestionKey,
      suggestionId: selectedSuggestion?.id,
      updates,
      metadata,
    })
    return permissionDecision
  }
}

export function createGateway(options: GatewayOptions) {
  return new PermissionGateway(options)
}
