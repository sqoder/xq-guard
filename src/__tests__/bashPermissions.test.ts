import { describe, expect, test } from "bun:test"
import { assessBashCommand } from "../bashPermissions"

describe("bash permissions", () => {
  test("classifies read-only git commands", () => {
    expect(assessBashCommand("git status --short")).toMatchObject({
      isReadOnly: true,
      requiresAsk: false,
    })
  })

  test("asks for mutating git commands", () => {
    expect(assessBashCommand("git push origin main")).toMatchObject({
      isReadOnly: false,
      requiresAsk: true,
    })
  })

  test("does not treat quoted shell operators as command operators", () => {
    expect(assessBashCommand("echo 'a && b'")).toMatchObject({
      isReadOnly: true,
      requiresAsk: false,
    })
  })

  test("strips safe wrappers before classification", () => {
    expect(assessBashCommand("env FOO=bar command git status")).toMatchObject({
      isReadOnly: true,
      requiresAsk: false,
    })
  })

  test("asks for command substitution", () => {
    expect(assessBashCommand("echo $(cat .env)")).toMatchObject({
      isReadOnly: false,
      requiresAsk: true,
    })
  })

  test("allows read-only compound commands without blanket ask", () => {
    expect(assessBashCommand("git status --short && pwd")).toMatchObject({
      isReadOnly: true,
      requiresAsk: false,
    })
  })

  test("asks when any compound command segment mutates", () => {
    expect(assessBashCommand("git status --short && git push")).toMatchObject({
      isReadOnly: false,
      requiresAsk: true,
    })
  })
})
