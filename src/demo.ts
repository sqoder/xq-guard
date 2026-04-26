import { mkdtempSync, writeFileSync, existsSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { PermissionEngine } from "./engine";
import { createGateway } from "./gateway";

async function runDemo() {
    console.log("\x1b[1m--- XQ-GUARD 权限管理网关增强版 (Demo) ---\x1b[0m\n");

    const tempDir = mkdtempSync(join(tmpdir(), "xq-guard-demo-"));
    console.log(`Using temporary directory: ${tempDir}`);

    // 初始化测试文件
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

    // 初始化一些基础规则
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" });
    await engine.saveRule({ tool: "Bash", behavior: "allow", source: "user" });

    console.log("1️⃣ 测试: 路径逃逸拦截 (.git/config)");
    // 虽然我们在临时目录跑，但物理检查会拦截包含 .git 的路径
    await gateway.execute("FileRead", { path: join(tempDir, ".git/config") });
    
    console.log("\n2️⃣ 测试: 危险命令识别 (rm -rf /)");
    await gateway.execute("Bash", { cmd: "rm -rf /" });

    console.log("\n3️⃣ 测试: 写操作安全 - 新建文件 (允许不先读)");
    await engine.saveRule({ tool: "FileWrite", behavior: "allow", source: "user" });
    await gateway.execute("FileWrite", { path: "security_test.txt", content: "safe content" });

    console.log("\n4️⃣ 测试: 写操作安全 - 已存在文件没读过");
    await gateway.execute("FileWrite", { path: "existing.txt", content: "new content" });

    console.log("5️⃣ 测试: 正常流程 - 先读后改");
    await gateway.execute("FileRead", { path: "existing.txt" });
    await engine.saveRule({ tool: "FileEdit", behavior: "allow", source: "user" });
    const editResult = await gateway.execute("FileEdit", { path: "existing.txt", oldString: "old content", newString: "updated content" });
    console.log(`Edit Result OK: ${editResult.result?.ok}`);

    console.log("\n6️⃣ 测试: 并发冲突 - 读后被外部修改");
    await gateway.execute("FileRead", { path: "existing.txt" });
    // 模拟外部修改，增加延迟确保 mtime 变化
    await new Promise(r => setTimeout(r, 100)); 
    writeFileSync(existingFilePath, "externally modified content");
    const conflictResult = await gateway.execute("FileEdit", { path: "existing.txt", oldString: "externally modified content", newString: "hack" });
    console.log(`Conflict Decision: ${conflictResult.decision.behavior}, Reason: ${conflictResult.decision.reason}`);

    console.log("\n7️⃣ 测试: MCP 权限优先级");
    await engine.saveRule({ tool: "mcp__google__*", behavior: "allow", source: "user" });
    await engine.saveRule({ tool: "mcp__google__delete", behavior: "deny", source: "user" });
    console.log("- 执行 mcp__google__search (应当允许)");
    await gateway.execute("mcp__google__search", { query: "test" });
    console.log("- 执行 mcp__google__delete (应当拒绝)");
    await gateway.execute("mcp__google__delete", { id: "123" });

    console.log("\n✅ Demo 运行结束。");
    process.exit(0);
}

runDemo();
