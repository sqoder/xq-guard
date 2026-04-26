import { mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { PermissionEngine } from "./engine";
import { createGateway, PermissionGateway } from "./gateway";
import { PermissionDecision } from "./types";

function logResult(label: string, decision: PermissionDecision, result?: any) {
    const icon = decision.behavior === "allow" ? "✅" : (decision.behavior === "deny" ? "🚫" : "❓");
    console.log(`${icon} [${decision.behavior.toUpperCase()}] ${label}`);
    if (decision.reason) console.log(`   原因: ${decision.reason}`);
    if (result) {
        if (result.ok) {
            console.log(`   结果: ${result.output.substring(0, 50)}${result.output.length > 50 ? "..." : ""}`);
        } else {
            console.log(`   错误: ${result.error}`);
        }
    }
    console.log("");
}

async function runDemo() {
    console.log("\x1b[1m--- XQ-GUARD 权限管理网关增强版 (可视化 Demo) ---\x1b[0m\n");

    const tempDir = mkdtempSync(join(tmpdir(), "xq-guard-demo-"));
    console.log(`📂 工作目录: ${tempDir}\n`);

    const existingFilePath = join(tempDir, "existing.txt");
    writeFileSync(existingFilePath, "old content");

    const engine = new PermissionEngine(tempDir);
    const gateway = createGateway({
        engine,
        ctx: {
            mode: "default",
            cwd: tempDir,
            allowedPaths: [tempDir],
            interactive: false,
        },
    });

    // 1️⃣ 路径逃逸
    console.log("1️⃣ 测试: 路径逃逸拦截 (.git/config)");
    const r1 = await gateway.execute("FileRead", { path: join(tempDir, ".git/config") });
    logResult("读取 .git/config", r1.decision, r1.result);
    
    // 2️⃣ 危险命令
    console.log("2️⃣ 测试: 危险命令识别 (rm -rf /)");
    const r2 = await gateway.execute("Bash", { cmd: "rm -rf /" });
    logResult("执行 rm -rf /", r2.decision, r2.result);

    // 3️⃣ 写操作安全 - 新建文件
    console.log("3️⃣ 测试: 写操作安全 - 新建文件 (允许不先读)");
    await engine.saveRule({ tool: "FileWrite", behavior: "allow", source: "user" });
    const r3 = await gateway.execute("FileWrite", { path: "security_test.txt", content: "safe content" });
    logResult("新建 security_test.txt", r3.decision, r3.result);

    // 4️⃣ 写操作安全 - 未读先写
    console.log("4️⃣ 测试: 写操作安全 - 已存在文件没读过");
    const r4 = await gateway.execute("FileWrite", { path: "existing.txt", content: "new content" });
    logResult("直接覆盖 existing.txt", r4.decision, r4.result);

    // 5️⃣ 正常流程
    console.log("5️⃣ 测试: 正常流程 - 先读后改");
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" });
    const r5_read = await gateway.execute("FileRead", { path: "existing.txt" });
    logResult("读取 existing.txt", r5_read.decision, r5_read.result);
    
    await engine.saveRule({ tool: "FileEdit", behavior: "allow", source: "user" });
    const r5_edit = await gateway.execute("FileEdit", { path: "existing.txt", oldString: "old content", newString: "updated content" });
    logResult("修改 existing.txt", r5_edit.decision, r5_edit.result);

    // 6️⃣ 并发冲突
    console.log("6️⃣ 测试: 并发冲突 - 读后被外部修改");
    await gateway.execute("FileRead", { path: "existing.txt" });
    await new Promise(r => setTimeout(r, 100)); 
    writeFileSync(existingFilePath, "externally modified content");
    const r6 = await gateway.execute("FileEdit", { path: "existing.txt", oldString: "externally modified content", newString: "hack" });
    logResult("并发修改校验", r6.decision, r6.result);

    // 7️⃣ MCP 优先级
    console.log("7️⃣ 测试: MCP 权限优先级");
    await engine.saveRule({ tool: "mcp__google__*", behavior: "allow", source: "user" });
    await engine.saveRule({ tool: "mcp__google__delete", behavior: "deny", source: "user" });
    
    const r7_allow = await gateway.execute("mcp__google__search", { query: "test" });
    logResult("执行 mcp__google__search (通配符允许)", r7_allow.decision, r7_allow.result);
    
    const r7_deny = await gateway.execute("mcp__google__delete", { id: "123" });
    logResult("执行 mcp__google__delete (具体规则拦截)", r7_deny.decision, r7_deny.result);

    console.log("✅ Demo 运行结束。");
    process.exit(0);
}

runDemo();
