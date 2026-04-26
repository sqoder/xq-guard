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
  mode: 'default',
  cwd: process.cwd(),
  allowedPaths: [process.cwd()] 
};

async function executeAsAgent(toolName: string, input: any) {
  const tool = tools[toolName] || { 
      name: toolName, 
      checkPhysicalSafety: async () => null, 
      run: async () => "Mock Result",
      validate: () => ({ ok: true })
  };

  // 1. 物理安全检查
  const safety = await (tool as Tool).checkPhysicalSafety?.(input, ctx);
  if (safety?.behavior === 'deny') {
    console.log(`❌ [Physical Deny] ${safety.reason}`);
    return;
  }

  // 2. 写安全
  if (toolName === 'FileWrite' || toolName === 'FileEdit') {
    const writeSafety = engine.checkWriteSafety(input.path);
    if (!writeSafety.ok) {
        console.log(`❌ [Write Safety Deny] ${writeSafety.reason}`);
        return;
    }
  }

  // 3. 策略决策
  let decision = await engine.decide(toolName, JSON.stringify(input), ctx);

  // 4. 合并物理安全建议 (如果物理安全建议 ask 且策略是 allow/ask，则取 ask)
  if (safety?.behavior === 'ask' && decision.behavior !== 'deny') {
      decision = { behavior: 'ask', reason: safety.reason };
  }

  // 5. 处理 Ask (非交互下自动拒绝)
  if (decision.behavior === 'ask') {
      console.log(`❓ [Ask Requested] -> Defaulting to Deny in test mode. Reason: ${decision.reason}`);
      decision = { behavior: 'deny', reason: 'Auto-deny in non-interactive test' };
  }

  // 5. 执行
  if (decision.behavior === 'allow') {
    console.log(`🚀 [Allowed] Executing ${toolName}`);
    if (toolName === 'FileRead') {
        engine.recordFileRead(input.path);
    }
  } else {
    console.log(`🚫 [Blocked] ${decision.reason}`);
  }

  // 6. 审计日志
  engine.logAudit({
    toolName,
    input: JSON.stringify(input),
    decision,
    time: new Date().toISOString()
  });
}

async function runDemo() {
    console.log("\x1b[1m--- XQ-GUARD 权限管理网关增强版 (非交互测试) ---\x1b[0m\n");

    const testCtx: ToolContext = {
        mode: 'default',
        cwd: process.cwd(),
        allowedPaths: [process.cwd()]
    };

    console.log("1️⃣ 测试: 路径逃逸拦截 (.git 目录)");
    await executeAsAgent("FileRead", { path: ".git/config" });
    
    console.log("\n2️⃣ 测试: 危险命令识别 (rm -rf)");
    await executeAsAgent("Bash", { cmd: "rm -rf /" });

    console.log("\n3️⃣ 测试: 写操作安全 (必须先读)");
    await executeAsAgent("FileWrite", { path: "security_test.txt", content: "safe" });

    console.log("\n4️⃣ 测试: 规则优先级 (Deny > Allow)");
    await engine.saveRule({ tool: "FileRead", pattern: "secret", behavior: "allow", source: "user" });
    await engine.saveRule({ tool: "FileRead", pattern: "secret", behavior: "deny", source: "user" });
    await executeAsAgent("FileRead", { path: "secret_data.txt" });

    console.log("\n5️⃣ 测试: MCP 权限 (mcp__google__*)");
    await engine.saveRule({ tool: "mcp__google__*", behavior: "deny", source: "user" });
    await executeAsAgent("mcp__google__search", { query: "hello" });

    console.log("\n6️⃣ 测试: 只读模式 (ReadOnly mode)");
    const readOnlyCtx = { ...testCtx, mode: 'readOnly' as const };
    
    console.log("- 读取 (应当允许，注入 allow 规则)");
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" });
    let decision = await engine.decide("FileRead", JSON.stringify({path: "README.md"}), readOnlyCtx);
    console.log(`Decision: ${decision.behavior} (${decision.reason})`);

    console.log("- 写入 (应当拦截，即使有 allow 规则)");
    await engine.saveRule({ tool: "FileWrite", behavior: "allow", source: "user" });
    decision = await engine.decide("FileWrite", JSON.stringify({path: "README.md", content: "hack"}), readOnlyCtx);
    console.log(`Decision: ${decision.behavior} (${decision.reason})`);

    console.log("\n✅ 测试结束。请检查输出日志。");
    process.exit(0);
}

runDemo();
