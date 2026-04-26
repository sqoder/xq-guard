import { describe, expect, test } from "bun:test"
import { mkdirSync, mkdtempSync, writeFileSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import { PermissionEngine } from "../engine"
import { createGateway } from "../gateway"

function createTempWorkspace() {
  return mkdtempSync(join(tmpdir(), "xq-guard-permissions-"))
}

function createGatewayFor(cwd: string, engine: PermissionEngine) {
  return createGateway({
    engine,
    ctx: {
      mode: "default",
      cwd,
      allowedPaths: [cwd],
      interactive: false,
    },
  })
}

describe("permission core", () => {
  test("matches Read and Edit aliases for file tools", async () => {
    const cwd = createTempWorkspace()
    const engine = new PermissionEngine(cwd)
    const gateway = createGatewayFor(cwd, engine)

    mkdirSync(join(cwd, "src"), { recursive: true })
    writeFileSync(join(cwd, "src/app.ts"), "export const value = 1\n")
    writeFileSync(join(cwd, "package.json"), '{"name":"xq-guard"}\n')

    await engine.saveRule({
      tool: "Read(src/**)",
      behavior: "allow",
      source: "userSettings",
    })
    await engine.saveRule({
      tool: "Read(package.json)",
      behavior: "allow",
      source: "userSettings",
    })
    await engine.saveRule({
      tool: "Edit(package.json)",
      behavior: "allow",
      source: "userSettings",
    })

    const readResult = await gateway.execute("FileRead", {
      path: "src/app.ts",
    })
    const readPackageResult = await gateway.execute("FileRead", {
      path: "package.json",
    })
    const editResult = await gateway.execute("FileEdit", {
      path: "package.json",
      oldString: '"name":"xq-guard"',
      newString: '"name":"xq-guard-core"',
    })

    expect(readResult.decision.behavior).toBe("allow")
    expect(readPackageResult.decision.behavior).toBe("allow")
    expect(editResult.decision.behavior).toBe("allow")
  })

  test("persists rules into policySettings and reloads them", async () => {
    const cwd = createTempWorkspace()
    const policySettingsPath = join(cwd, "policy-settings.json")
    const engine = new PermissionEngine({
      baseDir: cwd,
      settings: {
        policySettingsPath,
      },
    })

    mkdirSync(join(cwd, "src"), { recursive: true })
    await expect(
      engine.saveRule({
        tool: "Read(src/**)",
        behavior: "allow",
        source: "policySettings",
      } as any),
    ).resolves.toBeDefined()

    const reloaded = new PermissionEngine({
      baseDir: cwd,
      settings: {
        policySettingsPath,
      },
    })
    const gateway = createGatewayFor(cwd, reloaded)

    writeFileSync(join(cwd, "src/app.ts"), "export const value = 1\n")
    const result = await gateway.execute("FileRead", {
      path: "src/app.ts",
    })

    expect(result.decision.behavior).toBe("allow")
  })
})
