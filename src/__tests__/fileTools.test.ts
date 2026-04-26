import { describe, expect, test } from "bun:test"
import { mkdtempSync, writeFileSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import { PermissionEngine } from "../engine"
import { createGateway } from "../gateway"

function setup() {
  const cwd = mkdtempSync(join(tmpdir(), "xq-guard-file-tools-"))
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

describe("file tools", () => {
  test("FileRead enforces size and binary limits", async () => {
    const { cwd, engine, gateway } = setup()
    writeFileSync(join(cwd, "big.txt"), "x".repeat(200))
    writeFileSync(join(cwd, "bin.dat"), Buffer.from([0, 1, 2, 255]))
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" })

    const big = await gateway.execute("FileRead", {
      path: "big.txt",
      maxSizeBytes: 32,
    })
    const binary = await gateway.execute("FileRead", { path: "bin.dat" })

    expect(big.decision.behavior).toBe("allow")
    expect(big.result?.ok).toBe(false)
    expect(big.result?.error).toContain("exceeds maxSizeBytes")
    expect(binary.decision.behavior).toBe("allow")
    expect(binary.result?.ok).toBe(false)
    expect(binary.result?.error).toContain("Binary file rejected")
  })

  test("FileRead supports offset/limit and line numbers", async () => {
    const { cwd, engine, gateway } = setup()
    writeFileSync(
      join(cwd, "lines.txt"),
      ["alpha", "beta", "gamma", "delta"].join("\n"),
    )
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" })

    const result = await gateway.execute("FileRead", {
      path: "lines.txt",
      offset: 1,
      limit: 2,
      includeLineNumbers: true,
    })

    expect(result.decision.behavior).toBe("allow")
    expect(result.result?.ok).toBe(true)
    expect(result.result?.output).toContain("2 | beta")
    expect(result.result?.output).toContain("3 | gamma")
    expect(result.result?.output).not.toContain("1 | alpha")
    expect((result.result?.data as any)?.startLine).toBe(2)
    expect((result.result?.data as any)?.totalLines).toBe(4)
  })

  test("FileRead can return file_unchanged cache hit", async () => {
    const { cwd, engine, gateway } = setup()
    writeFileSync(join(cwd, "cache.txt"), "same content")
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" })

    const first = await gateway.execute("FileRead", {
      path: "cache.txt",
      allowUnchangedResult: true,
    })
    const second = await gateway.execute("FileRead", {
      path: "cache.txt",
      allowUnchangedResult: true,
    })

    expect(first.result?.ok).toBe(true)
    expect((first.result?.data as any)?.type).toBe("text")
    expect(second.result?.ok).toBe(true)
    expect(second.result?.output).toBe("file_unchanged")
    expect((second.result?.data as any)?.type).toBe("file_unchanged")
  })

  test("FileWrite returns structured diff metadata", async () => {
    const { cwd, engine, gateway } = setup()
    writeFileSync(join(cwd, "edit-target.txt"), "before")
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" })
    await engine.saveRule({ tool: "FileWrite", behavior: "allow", source: "user" })
    await gateway.execute("FileRead", { path: "edit-target.txt" })

    const result = await gateway.execute("FileWrite", {
      path: "edit-target.txt",
      content: "after",
    })

    expect(result.decision.behavior).toBe("allow")
    expect(result.result?.ok).toBe(true)
    expect((result.result?.data as any)?.type).toBe("update")
    expect((result.result?.data as any)?.hashBefore).toBeDefined()
    expect((result.result?.data as any)?.hashAfter).toBeDefined()
    expect((result.result?.data as any)?.diff).toContain("-before")
    expect((result.result?.data as any)?.diff).toContain("+after")
  })

  test("FileEdit supports replaceAll and returns edit metadata", async () => {
    const { cwd, engine, gateway } = setup()
    writeFileSync(join(cwd, "replace.txt"), "foo\nfoo\n")
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" })
    await engine.saveRule({ tool: "FileEdit", behavior: "allow", source: "user" })
    await gateway.execute("FileRead", { path: "replace.txt" })

    const single = await gateway.execute("FileEdit", {
      path: "replace.txt",
      oldString: "foo",
      newString: "bar",
    })
    const replaceAll = await gateway.execute("FileEdit", {
      path: "replace.txt",
      oldString: "foo",
      newString: "bar",
      replaceAll: true,
    })

    expect(single.decision.behavior).toBe("allow")
    expect(single.result?.ok).toBe(false)
    expect(single.result?.error).toContain("replaceAll=true")
    expect(replaceAll.decision.behavior).toBe("allow")
    expect(replaceAll.result?.ok).toBe(true)
    expect((replaceAll.result?.data as any)?.replaceAll).toBe(true)
    expect((replaceAll.result?.data as any)?.replacedCount).toBe(2)
    expect((replaceAll.result?.data as any)?.diff).toContain("+bar")
  })

  test("FileEdit secret-like replacement requires approval", async () => {
    const { cwd, engine, gateway } = setup()
    writeFileSync(join(cwd, "secret.txt"), "token = old\n")
    await engine.saveRule({ tool: "FileRead", behavior: "allow", source: "user" })
    await engine.saveRule({ tool: "FileEdit", behavior: "allow", source: "user" })
    await gateway.execute("FileRead", { path: "secret.txt" })

    const result = await gateway.execute("FileEdit", {
      path: "secret.txt",
      oldString: "token = old",
      newString: "token = new-secret-value",
    })

    expect(result.decision.behavior).toBe("deny")
    expect(result.decision.reason).toBe("Auto-deny in non-interactive mode")
  })

  test("Bash-derived write paths require FileWrite permission and FileWrite safety", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "xq-guard-bash-write-link-"))
    const engine = new PermissionEngine(cwd)
    const gateway = createGateway({
      engine,
      ctx: {
        mode: "default",
        cwd,
        allowedPaths: [cwd],
        interactive: false,
      },
      tools: {
        Bash: {
          name: "Bash",
          validate: () => ({ ok: true }),
          checkPermissions: async () => null,
          run: async () => ({ ok: true, output: "mock bash ok" }),
        } as any,
      },
    })

    await engine.saveRule({ tool: "Bash", behavior: "allow", source: "user" })

    const missingWriteRule = await gateway.execute("Bash", {
      cmd: "echo hello > note.txt",
    })
    expect(missingWriteRule.decision.behavior).toBe("deny")
    expect(missingWriteRule.decision.reason).toBe("Auto-deny in non-interactive mode")

    await engine.saveRule({
      tool: "FileWrite(note.txt)",
      behavior: "allow",
      source: "user",
    })
    const withWriteRule = await gateway.execute("Bash", {
      cmd: "echo hello > note.txt",
    })
    expect(withWriteRule.decision.behavior).toBe("allow")
    expect(withWriteRule.result?.ok).toBe(true)

    await engine.saveRule({ tool: "FileWrite", behavior: "allow", source: "user" })
    const sensitivePath = await gateway.execute("Bash", {
      cmd: "echo secret > .env",
    })
    expect(sensitivePath.decision.behavior).toBe("deny")
    expect(sensitivePath.decision.reason).toContain("FileWrite safety denied")
  })
})
