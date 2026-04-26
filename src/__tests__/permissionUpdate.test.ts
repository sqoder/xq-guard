import { describe, expect, test } from "bun:test"
import {
  isPermissionUpdate,
  normalizePermissionUpdate,
  normalizePermissionUpdates,
  permissionUpdateFromRule,
} from "../permissions/permissionUpdate"

describe("permission updates", () => {
  test("normalizes legacy rule updates into canonical batch updates", () => {
    const add = normalizePermissionUpdate({
      type: "addRule",
      rule: {
        tool: "Read(src/**)",
        behavior: "allow",
        source: "user",
      },
    } as any)

    const replace = normalizePermissionUpdate({
      type: "replaceRule",
      ruleId: "rule-1",
      rule: {
        tool: "Edit(package.json)",
        behavior: "deny",
        source: "project",
      },
      source: "project",
    } as any)

    const remove = normalizePermissionUpdate({
      type: "removeRule",
      ruleId: "rule-2",
      source: "local",
    } as any)

    expect(add).toMatchObject({
      type: "addRules",
      destination: "userSettings",
      rules: [
        {
          toolName: "Read",
          ruleContent: "src/**",
          behavior: "allow",
          source: "userSettings",
        },
      ],
    })
    expect(replace).toMatchObject({
      type: "replaceRules",
      destination: "projectSettings",
      rules: [
        {
          toolName: "Edit",
          ruleContent: "package.json",
          behavior: "deny",
          source: "projectSettings",
        },
      ],
    })
    expect(remove).toMatchObject({
      type: "removeRules",
      destination: "localSettings",
      ruleIds: ["rule-2"],
    })
  })

  test("creates addRules updates from normalized rules", () => {
    const update = permissionUpdateFromRule(
      {
        tool: "FileRead(src/app.ts)",
        behavior: "allow",
        source: "project",
      } as any,
      "projectSettings",
    )

    expect(update).toMatchObject({
      type: "addRules",
      destination: "projectSettings",
      rules: [
        {
          toolName: "FileRead",
          ruleContent: "src/app.ts",
          behavior: "allow",
          source: "projectSettings",
        },
      ],
    })
  })

  test("recognizes canonical and legacy update shapes", () => {
    expect(
      isPermissionUpdate({
        type: "addRules",
        destination: "session",
        rules: [],
      }),
    ).toBe(true)
    expect(
      isPermissionUpdate({
        type: "setMode",
        mode: "plan",
      }),
    ).toBe(true)
    expect(
      isPermissionUpdate({
        type: "removeDirectories",
        paths: ["./tmp"],
      }),
    ).toBe(true)
    expect(isPermissionUpdate({ type: "nope" })).toBe(false)
  })

  test("normalizes update batches consistently", () => {
    const updates = normalizePermissionUpdates([
      {
        type: "addRule",
        rule: {
          tool: "Write(notes.txt)",
          behavior: "allow",
          source: "session",
        },
      } as any,
      {
        type: "setMode",
        mode: "bypass",
      } as any,
    ])

    expect(updates).toHaveLength(2)
    expect(updates[0]).toMatchObject({
      type: "addRules",
      destination: "session",
    })
    expect(updates[1]).toMatchObject({
      type: "setMode",
      mode: "bypassPermissions",
    })
  })
})
