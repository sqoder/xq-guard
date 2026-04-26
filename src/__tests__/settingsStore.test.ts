import { describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import { mkdtempSync } from "fs"
import { PermissionEngine } from "../engine"

function tempDir() {
  return mkdtempSync(join(tmpdir(), "xq-guard-settings-"))
}

function writeRules(path: string, rules: unknown[]) {
  mkdirSync(join(path, ".."), { recursive: true })
  writeFileSync(path, JSON.stringify(rules, null, 2))
}

function readRules(path: string) {
  return JSON.parse(readFileSync(path, "utf8"))
}

describe("settings store", () => {
  test("merges user, project, local, session, and cliArg rules", async () => {
    const cwd = tempDir()
    const userSettingsPath = join(cwd, "user-settings.json")
    const projectSettingsPath = join(cwd, "project-settings.json")
    const localSettingsPath = join(cwd, "local-settings.json")
    const sessionSettingsPath = join(cwd, "session-settings.json")

    writeRules(userSettingsPath, [
      { id: "user-1", tool: "FileRead(user.txt)", behavior: "allow", source: "user" },
    ])
    writeRules(projectSettingsPath, [
      { id: "project-1", tool: "FileRead(project.txt)", behavior: "allow", source: "project" },
    ])
    writeRules(localSettingsPath, [
      { id: "local-1", tool: "FileRead(local.txt)", behavior: "allow", source: "local" },
    ])
    writeRules(sessionSettingsPath, [
      { id: "session-1", tool: "FileRead(session.txt)", behavior: "allow", source: "session" },
    ])

    const engine = new PermissionEngine({
      baseDir: cwd,
      settings: {
        userSettingsPath,
        projectSettingsPath,
        localSettingsPath,
        sessionSettingsPath,
        cliArgRules: [
          { tool: "FileRead(cli.txt)", behavior: "allow", source: "cliArg" },
        ],
      },
    })

    for (const path of ["user.txt", "project.txt", "local.txt", "session.txt", "cli.txt"]) {
      const decision = await engine.decide(
        "FileRead",
        JSON.stringify({ path }),
        { mode: "default", cwd, allowedPaths: [cwd], interactive: false },
      )
      expect(decision.behavior).toBe("allow")
    }
  })

  test("keeps deny priority across settings layers", async () => {
    const cwd = tempDir()
    const userSettingsPath = join(cwd, "user-settings.json")
    const projectSettingsPath = join(cwd, "project-settings.json")

    writeRules(userSettingsPath, [
      { id: "user-1", tool: "Bash(git status*)", behavior: "allow", source: "user" },
    ])
    writeRules(projectSettingsPath, [
      { id: "project-1", tool: "Bash(git status --short)", behavior: "deny", source: "project" },
    ])

    const engine = new PermissionEngine({
      baseDir: cwd,
      settings: { userSettingsPath, projectSettingsPath },
    })

    const decision = await engine.decide(
      "Bash",
      JSON.stringify({ cmd: "git status --short" }),
      { mode: "default", cwd, allowedPaths: [cwd], interactive: false },
    )

    expect(decision.behavior).toBe("deny")
  })

  test("persists saved rules to the source-specific settings file", async () => {
    const cwd = tempDir()
    const userSettingsPath = join(cwd, "user-settings.json")
    const localSettingsPath = join(cwd, "local-settings.json")
    const engine = new PermissionEngine({
      baseDir: cwd,
      settings: { userSettingsPath, localSettingsPath },
    })

    await engine.saveRule({
      tool: "FileRead(user.txt)",
      behavior: "allow",
      source: "user",
    })
    await engine.saveRule({
      tool: "FileRead(local.txt)",
      behavior: "deny",
      source: "local",
    })

    expect(existsSync(userSettingsPath)).toBe(true)
    expect(existsSync(localSettingsPath)).toBe(true)
    expect(readRules(userSettingsPath)).toMatchObject([
      { tool: "FileRead(user.txt)", behavior: "allow", source: "user" },
    ])
    expect(readRules(localSettingsPath)).toMatchObject([
      { tool: "FileRead(local.txt)", behavior: "deny", source: "local" },
    ])
  })

  test("keeps legacy baseDir rules.json compatibility", async () => {
    const cwd = tempDir()
    const legacyPath = join(cwd, "rules.json")
    const engine = new PermissionEngine(cwd)

    await engine.saveRule({
      tool: "WebFetch(domain:example.com)",
      behavior: "allow",
      source: "user",
    })

    expect(existsSync(legacyPath)).toBe(true)
    expect(readRules(legacyPath)).toMatchObject([
      { tool: "WebFetch(domain:example.com)", behavior: "allow", source: "user" },
    ])
  })
})
