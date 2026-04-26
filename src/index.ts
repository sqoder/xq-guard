import { PermissionEngine } from "./engine";
import { FileReadTool, BashTool, FileWriteTool, FileEditTool, Tool } from "./tools";
import { ToolContext } from "./types";
import { join } from "path";

const engine = new PermissionEngine(process.cwd());
const tools: Record<string, Tool> = {
  "FileRead": new FileReadTool(),
  "Bash": new BashTool(),
  "FileWrite": new FileWriteTool(),
  "FileEdit": new FileEditTool()
};

const ctx: ToolContext = {
  mode: "default",
  cwd: process.cwd(),
  allowedPaths: [process.cwd()],
  interactive: false,
};

async function executeAsAgent(toolName: string, input: any) {
  const tool = tools[toolName] || (
    toolName.startsWith("mcp__")
      ? {
          name: toolName,
          checkPhysicalSafety: async () => null,
          run: async () => "Mock MCP Result",
          validate: () => ({ ok: true }),
        } as unknown as Tool
      : null
  );

  if (!tool) {
    const decision = { behavior: "deny" as const, reason: `Tool ${toolName} not found` }
    console.log(`🚫 [Blocked] ${decision.reason}`)
    engine.logAudit({
      toolName,
      input: JSON.stringify(input),
      decision,
      time: new Date().toISOString(),
    })
    return
  }

  const validation = tool.validate(input)
  if (!validation.ok) {
    const decision = { behavior: "deny" as const, reason: validation.msg || "Invalid input" }
    console.log(`🚫 [Blocked] ${decision.reason}`)
    engine.logAudit({
      toolName,
      input: JSON.stringify(input),
      decision,
      time: new Date().toISOString(),
    })
    return
  }

  const safety = await tool.checkPhysicalSafety(input, ctx)
  if (safety?.behavior === "deny") {
    console.log(`❌ [Physical Deny] ${safety.reason}`)
    engine.logAudit({
      toolName,
      input: JSON.stringify(input),
      decision: safety,
      time: new Date().toISOString(),
    })
    return
  }

  let decision = await engine.decide(toolName, JSON.stringify(input), ctx)
  if (safety?.behavior === "ask" && decision.behavior !== "deny") {
    decision = {
      behavior: "ask",
      reason: safety.reason,
    }
  }

  if (decision.behavior === "ask") {
    decision = await handleAsk(toolName, input, decision as { behavior: "ask"; reason: string })
  }

  if (decision.behavior !== "allow") {
    console.log(`🚫 [Blocked] ${decision.reason}`)
    engine.logAudit({
      toolName,
      input: JSON.stringify(input),
      decision,
      time: new Date().toISOString(),
    })
    return
  }

  if (toolName === "FileWrite" || toolName === "FileEdit") {
    const writeSafety = engine.checkWriteSafety(input.path, ctx, {
      allowCreate: toolName === "FileWrite",
    })
    if (!writeSafety.ok) {
      const deny = {
        behavior: "deny" as const,
        reason: writeSafety.reason || "Unsafe write",
      }
      console.log(`❌ [Write Safety Deny] ${deny.reason}`)
      engine.logAudit({
        toolName,
        input: JSON.stringify(input),
        decision: deny,
        time: new Date().toISOString(),
      })
      return
    }
  }

  console.log(`🚀 [Allowed] Executing ${toolName}`)
  const result = await tool.run(input, ctx)

  if (toolName === "FileRead" && result !== "File not found" && !result.startsWith("Error")) {
    engine.recordFileRead(input.path, ctx)
  }

  if (
    (toolName === "FileWrite" || toolName === "FileEdit") &&
    !result.startsWith("Error")
  ) {
    engine.recordFileRead(input.path, ctx)
  }

  console.log(`✅ [Result]\n${result}`)
  engine.logAudit({
    toolName,
    input: JSON.stringify(input),
    decision,
    time: new Date().toISOString(),
    result,
  })
}

async function handleAsk(
  toolName: string,
  input: any,
  decision: { behavior: "ask"; reason: string },
) {
  if (!ctx.interactive) {
    console.log(`❓ [Ask Requested] -> Defaulting to Deny. Reason: ${decision.reason}`)
    return {
      behavior: "deny" as const,
      reason: "Auto-deny in non-interactive mode",
    }
  }

  console.log(`\nAgent wants to execute [${toolName}]`)
  console.log(`Input: ${JSON.stringify(input)}`)
  console.log(`Reason: ${decision.reason}`)
  process.stdout.write(
    "\nAllow?\n(y) allow once\n(n) deny\n(a) always allow tool\n(d) always deny this input\n> ",
  );

  return new Promise<any>((resolve) => {
      process.stdin.once('data', async (data) => {
          const answer = data.toString().trim().toLowerCase();
          if (answer === "y") {
            resolve({ behavior: "allow" as const, reason: "User approved once" });
          } else if (answer === "a") {
            await engine.saveRule({
              tool: toolName,
              behavior: "allow",
              source: "user",
            });
            resolve({ behavior: "allow" as const, reason: "User saved allow rule" });
          } else if (answer === "d") {
            const pattern = input.path || input.cmd || JSON.stringify(input);
            await engine.saveRule({
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

async function runDemo() {
    console.log("\x1b[1m--- XQ-GUARD 权限管理网关增强版 (最终验收测试) ---\x1b[0m\n");

    // 清理环境
    const testFiles = ["security_test.txt", "existing.txt", "audit.log"];
    for (const f of testFiles) {
        try { if (require("fs").existsSync(f)) require("fs").unlinkSync(f); } catch {}
    }

    // 初始化一些基础规则以便测试正常流程
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" });
    await engine.saveRule({ tool: "Bash", behavior: "allow", source: "user" });

    console.log("1️⃣ 测试: 路径逃逸拦截 (.git/config)");
    await executeAsAgent("FileRead", { path: ".git/config" });
    
    console.log("\n2️⃣ 测试: 危险命令识别 (rm -rf /)");
    await executeAsAgent("Bash", { cmd: "rm -rf /" });

    console.log("\n3️⃣ 测试: 写操作安全 - 新建文件 (允许不先读)");
    // 假设已有规则允许 FileWrite，或者默认行为是 ask (非交互下 deny)
    // 为了通过，我们需要一个 allow 规则
    await engine.saveRule({ tool: "FileWrite", behavior: "allow", source: "user" });
    await executeAsAgent("FileWrite", { path: "security_test.txt", content: "safe content" });

    console.log("\n4️⃣ 测试: 写操作安全 - 已存在文件没读过");
    // 手动创建一个文件模拟已存在
    await Bun.write("existing.txt", "old content");
    await executeAsAgent("FileWrite", { path: "existing.txt", content: "new content" });

    console.log("\n5️⃣ 测试: 正常流程 - 先读后改");
    await executeAsAgent("FileRead", { path: "existing.txt" });
    await engine.saveRule({ tool: "FileEdit", behavior: "allow", source: "user" });
    await executeAsAgent("FileEdit", { path: "existing.txt", oldString: "old content", newString: "updated content" });

    console.log("\n6️⃣ 测试: 并发冲突 - 读后被外部修改");
    await executeAsAgent("FileRead", { path: "existing.txt" });
    // 模拟外部修改，增加延迟确保 mtime 变化
    await new Promise(r => setTimeout(r, 100)); 
    await Bun.write("existing.txt", "externally modified content");
    await executeAsAgent("FileEdit", { path: "existing.txt", oldString: "externally modified content", newString: "hack" });

    console.log("\n7️⃣ 测试: MCP 权限优先级");
    await engine.saveRule({ tool: "mcp__google__*", behavior: "allow", source: "user" });
    await engine.saveRule({ tool: "mcp__google__delete", behavior: "deny", source: "user" });
    console.log("- 执行 mcp__google__search (应当允许)");
    await executeAsAgent("mcp__google__search", { query: "test" });
    console.log("- 执行 mcp__google__delete (应当拒绝)");
    await executeAsAgent("mcp__google__delete", { id: "123" });

    console.log("\n✅ 测试结束。");
    process.exit(0);
}

runDemo();
