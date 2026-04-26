import { describe, expect, test } from "bun:test"
import { ruleMatchesToolCall } from "../ruleMatcher"
import { ToolContext } from "../types"

const ctx: ToolContext = {
  mode: "default",
  cwd: "/repo",
  allowedPaths: ["/repo"],
  interactive: false,
}

describe("rule matcher", () => {
  test("matches file path glob rules", () => {
    expect(
      ruleMatchesToolCall(
        {
          id: "1",
          tool: "FileRead(src/**)",
          behavior: "allow",
          source: "user",
        },
        "FileRead",
        JSON.stringify({ path: "src/app/main.ts" }),
        ctx,
      ),
    ).toBe(true)

    expect(
      ruleMatchesToolCall(
        {
          id: "2",
          tool: "FileEdit(src/*.ts)",
          behavior: "allow",
          source: "user",
        },
        "FileEdit",
        JSON.stringify({ path: "src/app.ts" }),
        ctx,
      ),
    ).toBe(true)

    expect(
      ruleMatchesToolCall(
        {
          id: "3",
          tool: "FileEdit(src/*.ts)",
          behavior: "allow",
          source: "user",
        },
        "FileEdit",
        JSON.stringify({ path: "src/nested/app.ts" }),
        ctx,
      ),
    ).toBe(false)
  })

  test("matches bash command prefix rules", () => {
    expect(
      ruleMatchesToolCall(
        {
          id: "1",
          tool: "Bash(git status*)",
          behavior: "allow",
          source: "user",
        },
        "Bash",
        JSON.stringify({ cmd: "git status --short" }),
        ctx,
      ),
    ).toBe(true)

    expect(
      ruleMatchesToolCall(
        {
          id: "2",
          tool: "Bash(npm:*)",
          behavior: "allow",
          source: "user",
        },
        "Bash",
        JSON.stringify({ cmd: "npm install" }),
        ctx,
      ),
    ).toBe(true)
  })

  test("matches WebFetch domain rules without accepting lookalike hosts", () => {
    const rule = {
      id: "1",
      tool: "WebFetch(domain:github.com)",
      behavior: "allow" as const,
      source: "user" as const,
    }

    expect(
      ruleMatchesToolCall(
        rule,
        "WebFetch",
        JSON.stringify({ url: "https://api.github.com/repos" }),
        ctx,
      ),
    ).toBe(true)

    expect(
      ruleMatchesToolCall(
        rule,
        "WebFetch",
        JSON.stringify({ url: "https://github.com.evil.example/repos" }),
        ctx,
      ),
    ).toBe(false)
  })

  test("matches MCP server wildcard rules", () => {
    expect(
      ruleMatchesToolCall(
        {
          id: "1",
          tool: "mcp__github__*",
          behavior: "allow",
          source: "user",
        },
        "mcp__github__search",
        JSON.stringify({ query: "xq-guard" }),
        ctx,
      ),
    ).toBe(true)
  })
})
