import { PermissionEngine } from "./engine";
import { FileReadTool, BashTool, Tool } from "./tools";
import { ToolContext } from "./types";
import { join } from "path";

const engine = new PermissionEngine(process.cwd());
const tools: Record<string, Tool> = {
  "FileRead": new FileReadTool(),
  "Bash": new BashTool()
};

const ctx: ToolContext = {
  mode: 'default',
  cwd: process.cwd(),
  allowedPaths: [process.cwd()] 
};

async function executeAsAgent(toolName: string, input: any) {
  const tool = tools[toolName];
  if (!tool) {
    console.log(`❌ Tool ${toolName} not found`);
    return;
  }

  // 1. 物理安全检查 (沙箱)
  const safety = await tool.checkPhysicalSafety(input, ctx);
  if (safety?.behavior === 'deny') {
    console.error(`\x1b[31m❌ [Safety Block] ${safety.reason}\x1b[0m`);
    return;
  }

  // 2. 权限策略决策
  let decision = await engine.decide(toolName, JSON.stringify(input), ctx);

  // 3. 交互式确认
  if (decision.behavior === 'ask') {
    console.log(`\n🤖 Agent 想要执行 [\x1b[36m${toolName}\x1b[0m]`);
    console.log(`📝 输入: ${JSON.stringify(input)}`);
    console.log(`❓ 原因: ${decision.reason}`);
    
    // Bun.stdin 交互
    process.stdout.write(`\n允许执行吗? \n(y)允许一次 \n(n)拒绝 \n(a)始终允许工具 \n(d)始终拒绝此内容: \n> `);
    
    for await (const line of console) {
      const answer = line.trim().toLowerCase();
      if (answer === 'y') {
        decision = { behavior: 'allow', reason: 'User approved' };
        break;
      } else if (answer === 'a') {
        await engine.saveRule({ tool: toolName, behavior: 'allow', source: 'user' });
        decision = { behavior: 'allow', reason: 'Rule saved' };
        break;
      } else if (answer === 'd') {
        const pattern = input.path || input.cmd;
        await engine.saveRule({ tool: '*', pattern: pattern, behavior: 'deny', source: 'user' });
        decision = { behavior: 'deny', reason: 'Permanent deny saved' };
        break;
      } else {
        decision = { behavior: 'deny', reason: 'User rejected' };
        break;
      }
    }
  }

  // 4. 执行
  if (decision.behavior === 'allow') {
    console.log(`🚀 执行中...`);
    const result = await tool.run(input);
    console.log(`\x1b[32m✅ 结果:\x1b[0m\n${result}`);
  } else {
    console.log(`\x1b[31m🚫 拦截: ${decision.reason}\x1b[0m`);
  }
}

async function runDemo() {
    console.log("\x1b[1m--- XQ-GUARD 权限管理网关模拟 ---\x1b[0m\n");

    console.log("👉 场景 1: 尝试读取沙箱外的系统文件 (触发物理安全拦截)");
    await executeAsAgent("FileRead", { path: "/etc/passwd" });
    console.log("\n------------------\n");

    console.log("👉 场景 2: 尝试读取本项目内的文件 (触发规则检查/询问)");
    await executeAsAgent("FileRead", { path: "src/types.ts" });
    console.log("\n------------------\n");

    console.log("👉 场景 3: 执行命令 (询问是否允许)");
    await executeAsAgent("Bash", { cmd: "ls -la" });
}

runDemo();
