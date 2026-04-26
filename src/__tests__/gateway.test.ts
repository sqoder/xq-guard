import { describe, expect, test } from "bun:test"
import { mkdtempSync, writeFileSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import { PermissionEngine } from "../engine"
import { createGateway } from "../gateway"

function setup() {
  const cwd = mkdtempSync(join(tmpdir(), "xq-guard-test-"))
  const engine = new PermissionEngine(cwd)
  const gateway = createGateway({
    engine,
    ctx: {
      mode: "default",
      cwd,
      allowedPaths: [cwd],
      interactive: false,
    },
  })
  return { cwd, engine, gateway }
}

describe("xq-guard gateway", () => {
  test("blocks sensitive .git path", async () => {
    const { gateway, cwd } = setup()
    const result = await gateway.execute("FileRead", {
      path: join(cwd, ".git/config"),
    })
    expect(result.decision.behavior).toBe("deny")
  })

  test("allows creating new file when FileWrite is allowed", async () => {
    const { gateway, engine } = setup()
    await engine.saveRule({
      tool: "FileWrite",
      behavior: "allow",
      source: "user",
    })
    const result = await gateway.execute("FileWrite", {
      path: "new.txt",
      content: "hello",
    })
    expect(result.decision.behavior).toBe("allow")
    expect(result.result?.ok).toBe(true)
  })

  test("blocks editing existing file before read", async () => {
    const { cwd, gateway, engine } = setup()
    writeFileSync(join(cwd, "a.txt"), "old")
    await engine.saveRule({
      tool: "FileEdit",
      behavior: "allow",
      source: "user",
    })
    const result = await gateway.execute("FileEdit", {
      path: "a.txt",
      oldString: "old",
      newString: "new",
    })
    expect(result.decision.behavior).toBe("deny")
    expect(result.decision.reason).toContain("was not read before writing")
  })

  test("allows edit after read", async () => {
    const { cwd, gateway, engine } = setup()
    writeFileSync(join(cwd, "a.txt"), "old")
    await engine.saveRule({
      tool: "FileRead",
      behavior: "allow",
      source: "user",
    })
    await engine.saveRule({
      tool: "FileEdit",
      behavior: "allow",
      source: "user",
    })
    await gateway.execute("FileRead", {
      path: "a.txt",
    })
    const result = await gateway.execute("FileEdit", {
      path: "a.txt",
      oldString: "old",
      newString: "new",
    })
    expect(result.decision.behavior).toBe("allow")
    expect(result.result?.ok).toBe(true)
  })

  test("deny rule beats mcp server allow rule", async () => {
    const { gateway, engine } = setup()
    await engine.saveRule({
      tool: "mcp__google__*",
      behavior: "allow",
      source: "user",
    })
    await engine.saveRule({
      tool: "mcp__google__delete",
      behavior: "deny",
      source: "user",
    })
    const result = await gateway.execute("mcp__google__delete", {
      id: "123",
    })
    expect(result.decision.behavior).toBe("deny")
  })

  test("blocks write in readOnly mode even if allow rule exists", async () => {
    const { cwd, engine } = setup()
    const gateway = createGateway({
        engine,
        ctx: {
          mode: "readOnly",
          cwd,
          allowedPaths: [cwd],
          interactive: false,
        },
    })
    await engine.saveRule({
      tool: "FileWrite",
      behavior: "allow",
      source: "user",
    })
    const result = await gateway.execute("FileWrite", {
      path: "readonly_test.txt",
      content: "hack",
    })
    expect(result.decision.behavior).toBe("deny")
    expect(result.decision.reason).toContain("ReadOnly mode")
  })

  test("blocks edit when file changed after read", async () => {
    const { cwd, gateway, engine } = setup()
    writeFileSync(join(cwd, "a.txt"), "old")
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" })
    await engine.saveRule({ tool: "FileEdit", behavior: "allow", source: "user" })
    await gateway.execute("FileRead", { path: "a.txt" })
    
    // 模拟外部修改
    writeFileSync(join(cwd, "a.txt"), "changed by user")
    
    const result = await gateway.execute("FileEdit", {
      path: "a.txt",
      oldString: "old",
      newString: "hack",
    })
    expect(result.decision.behavior).toBe("deny")
    expect(result.decision.reason).toContain("modified since it was last read")
  })

  test("blocks path traversal outside allowed paths", async () => {
    const { gateway, engine } = setup()
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" })
    const result = await gateway.execute("FileRead", {
      path: "../outside.txt",
    })
    expect(result.decision.behavior).toBe("deny")
    expect(result.decision.reason).toContain("escapes allowed paths")
  })

  test("dangerous bash command is denied even with allow rule in non-interactive mode", async () => {
    const { gateway, engine } = setup()
    await engine.saveRule({ tool: "Bash", behavior: "allow", source: "user" })
    const result = await gateway.execute("Bash", {
      cmd: "rm -rf /",
    })
    expect(result.decision.behavior).toBe("deny")
    expect(result.decision.reason).toBe("Auto-deny in non-interactive mode")
  })
})
