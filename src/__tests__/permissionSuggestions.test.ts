import { describe, expect, test } from "bun:test"
import { buildPermissionSuggestions } from "../permissionSuggestions"

describe("permission suggestions", () => {
  test("suggests path-scoped rules for file tools", () => {
    const suggestions = buildPermissionSuggestions("FileEdit", {
      path: "src/app.ts",
      oldString: "old",
      newString: "new",
    })

    expect(suggestions.map(s => s.id)).toEqual([
      "allow_once",
      "deny_once",
      "allow_tool",
      "allow_path",
      "deny_path",
    ])
    expect(suggestions.find(s => s.id === "allow_path")?.rule).toMatchObject({
      tool: "FileEdit(src/app.ts)",
      behavior: "allow",
      source: "user",
    })
  })

  test("suggests command-prefix rules for bash tools", () => {
    const suggestions = buildPermissionSuggestions("Bash", {
      cmd: "npm run test:unit",
    })

    expect(suggestions.find(s => s.id === "allow_command_prefix")?.rule).toMatchObject({
      tool: "Bash(npm run test:unit*)",
      behavior: "allow",
      source: "user",
    })
  })

  test("suggests narrow npm command prefixes instead of npm:*", () => {
    const suggestions = buildPermissionSuggestions("Bash", {
      cmd: "npm install",
    })

    expect(suggestions.find(s => s.id === "allow_command_prefix")?.rule).toMatchObject({
      tool: "Bash(npm install*)",
      behavior: "allow",
      source: "user",
    })
  })

  test("suggests domain-scoped rules for WebFetch", () => {
    const suggestions = buildPermissionSuggestions("WebFetch", {
      url: "https://api.github.com/repos",
    })

    expect(suggestions.find(s => s.id === "allow_domain")?.rule).toMatchObject({
      tool: "WebFetch(domain:api.github.com)",
      behavior: "allow",
      source: "user",
    })
  })

  test("uses full hostname for multi-part TLDs", () => {
    const suggestions = buildPermissionSuggestions("WebFetch", {
      url: "https://docs.example.co.uk/path",
    })

    expect(suggestions.find(s => s.id === "allow_domain")?.rule).toMatchObject({
      tool: "WebFetch(domain:docs.example.co.uk)",
      behavior: "allow",
      source: "user",
    })
  })

  test("suggests MCP server-scoped rules", () => {
    const suggestions = buildPermissionSuggestions("mcp__github__search", {
      query: "xq-guard",
    })

    expect(suggestions.find(s => s.id === "allow_mcp_server")?.rule).toMatchObject({
      tool: "mcp__github__*",
      behavior: "allow",
      source: "user",
    })
  })
})
