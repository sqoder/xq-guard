import { PermissionEngine } from "./engine";
import { Tool, FileReadTool, BashTool, FileWriteTool, FileEditTool, WebFetchTool } from "./tools";
import { ToolContext, PermissionDecision, GatewayExecuteResult } from "./types";
import { buildPermissionSuggestions } from "./permissionSuggestions";

export interface GatewayOptions {
  engine: PermissionEngine;
  ctx: ToolContext;
  tools?: Record<string, Tool>;
}

export class PermissionGateway {
  private engine: PermissionEngine;
  private ctx: ToolContext;
  private tools: Record<string, Tool>;

  constructor(options: GatewayOptions) {
    this.engine = options.engine;
    this.ctx = options.ctx;
    this.tools = options.tools || {
      "FileRead": new FileReadTool(),
      "Bash": new BashTool(),
      "FileWrite": new FileWriteTool(),
      "FileEdit": new FileEditTool(),
      "WebFetch": new WebFetchTool()
    };
  }

  async execute(toolName: string, input: any): Promise<GatewayExecuteResult> {
    const tool = this.tools[toolName] || (
      toolName.startsWith("mcp__")
        ? {
            name: toolName,
            checkPhysicalSafety: async () => null,
            run: async () => ({ ok: true, output: "Mock MCP Result" }),
            validate: () => ({ ok: true }),
          } as unknown as Tool
        : null
    );

    if (!tool) {
      const decision = { behavior: "deny" as const, reason: `Tool ${toolName} not found` };
      this.engine.logAudit({
        toolName,
        input: JSON.stringify(input),
        decision,
        time: new Date().toISOString(),
      });
      return { decision };
    }

    const validation = tool.validate(input);
    if (!validation.ok) {
      const decision = { behavior: "deny" as const, reason: validation.msg || "Invalid input" };
      this.engine.logAudit({
        toolName,
        input: JSON.stringify(input),
        decision,
        time: new Date().toISOString(),
      });
      return { decision };
    }

    const safety = await tool.checkPhysicalSafety(input, this.ctx);
    if (safety?.behavior === "deny") {
      this.engine.logAudit({
        toolName,
        input: JSON.stringify(input),
        decision: safety,
        time: new Date().toISOString(),
      });
      return { decision: safety };
    }

    let decision = await this.engine.decide(toolName, JSON.stringify(input), this.ctx);
    if (safety?.behavior === "ask" && decision.behavior !== "deny") {
      decision = {
        behavior: "ask",
        reason: safety.reason,
      };
    }

    if (decision.behavior === "ask") {
      decision = await this.handleAsk(toolName, input, decision as { behavior: "ask"; reason: string });
    }

    if (decision.behavior !== "allow") {
      this.engine.logAudit({
        toolName,
        input: JSON.stringify(input),
        decision,
        time: new Date().toISOString(),
      });
      return { decision };
    }

    if (toolName === "FileWrite" || toolName === "FileEdit") {
      const writeSafety = this.engine.checkWriteSafety(input.path, this.ctx, {
        allowCreate: toolName === "FileWrite",
      });
      if (!writeSafety.ok) {
        const deny = {
          behavior: "deny" as const,
          reason: writeSafety.reason || "Unsafe write",
        };
        this.engine.logAudit({
          toolName,
          input: JSON.stringify(input),
          decision: deny,
          time: new Date().toISOString(),
        });
        return { decision: deny };
      }
    }

    const result = await tool.run(input, this.ctx);

    if (toolName === "FileRead" && result.ok) {
      this.engine.recordFileRead(input.path, this.ctx);
    }

    if (
      (toolName === "FileWrite" || toolName === "FileEdit") &&
      result.ok
    ) {
      this.engine.recordFileRead(input.path, this.ctx);
    }

    this.engine.logAudit({
      toolName,
      input: JSON.stringify(input),
      decision,
      time: new Date().toISOString(),
      result: result.ok ? result.output : result.error,
    });

    return { decision, result };
  }

  private async handleAsk(
    toolName: string,
    input: any,
    decision: { behavior: "ask"; reason: string },
  ): Promise<PermissionDecision> {
    const suggestions = buildPermissionSuggestions(toolName, input);
    if (!this.ctx.interactive) {
      return {
        behavior: "deny" as const,
        reason: "Auto-deny in non-interactive mode",
        suggestions,
      };
    }

    console.log(`\nAgent wants to execute [${toolName}]`);
    console.log(`Input: ${JSON.stringify(input)}`);
    console.log(`Reason: ${decision.reason}`);
    const prompt = suggestions
      .map(suggestion => `(${suggestion.key}) ${suggestion.label}`)
      .join("\n");
    process.stdout.write(`\nAllow?\n${prompt}\n> `);

    return new Promise<PermissionDecision>((resolve) => {
      process.stdin.once('data', async (data) => {
        const answer = data.toString().trim().toLowerCase();
        const suggestion = suggestions.find(candidate => candidate.key === answer);
        if (!suggestion) {
          resolve({
            behavior: "deny" as const,
            reason: "User rejected",
            suggestions,
          });
          return;
        }
        if (suggestion.rule) {
          await this.engine.saveRule(suggestion.rule);
        }
        resolve({
          behavior: suggestion.behavior,
          reason: suggestion.rule
            ? `User saved ${suggestion.behavior} rule`
            : suggestion.behavior === "allow"
              ? "User approved once"
              : "User rejected",
          suggestions,
        });
      });
    });
  }
}

export function createGateway(options: GatewayOptions) {
  return new PermissionGateway(options);
}
