import { PermissionEngine, AuditLog } from "./engine";
import { Tool, FileReadTool, BashTool, FileWriteTool, FileEditTool } from "./tools";
import { ToolContext, PermissionDecision } from "./types";

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
      "FileEdit": new FileEditTool()
    };
  }

  async execute(toolName: string, input: any): Promise<{ decision: PermissionDecision; result?: any }> {
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
    if (!this.ctx.interactive) {
      return {
        behavior: "deny" as const,
        reason: "Auto-deny in non-interactive mode",
      };
    }

    console.log(`\nAgent wants to execute [${toolName}]`);
    console.log(`Input: ${JSON.stringify(input)}`);
    console.log(`Reason: ${decision.reason}`);
    process.stdout.write(
      "\nAllow?\n(y) allow once\n(n) deny\n(a) always allow tool\n(d) always deny this input\n> ",
    );

    return new Promise<PermissionDecision>((resolve) => {
      process.stdin.once('data', async (data) => {
        const answer = data.toString().trim().toLowerCase();
        if (answer === "y") {
          resolve({ behavior: "allow" as const, reason: "User approved once" });
        } else if (answer === "a") {
          await this.engine.saveRule({
            tool: toolName,
            behavior: "allow",
            source: "user",
          });
          resolve({ behavior: "allow" as const, reason: "User saved allow rule" });
        } else if (answer === "d") {
          const pattern = input.path || input.cmd || JSON.stringify(input);
          await this.engine.saveRule({
            tool: toolName,
            pattern,
            behavior: "deny",
            source: "user",
          });
          resolve({ behavior: "deny" as const, reason: "User saved deny rule" });
        } else {
          resolve({ behavior: "deny" as const, reason: "User rejected" });
        }
      });
    });
  }
}

export function createGateway(options: GatewayOptions) {
  return new PermissionGateway(options);
}
