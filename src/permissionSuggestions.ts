import {
  PermissionSuggestion,
  permissionRuleValueToString,
} from "./types"

function canonicalSuggestionToolName(toolName: string): string {
  if (toolName === "FileRead") return "Read"
  if (toolName === "FileEdit") return "Edit"
  if (toolName === "FileWrite") return "Write"
  return toolName
}

function escapeRulePattern(value: string): string {
  return value.replace(/[()]/g, "\\$&")
}

function pathValue(input: unknown): string | undefined {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return undefined
  }
  const value = (input as Record<string, unknown>).path
  return typeof value === "string" && value.length > 0 ? value : undefined
}

function cmdValue(input: unknown): string | undefined {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return undefined
  }
  const value = (input as Record<string, unknown>).cmd
  return typeof value === "string" && value.length > 0 ? value : undefined
}

function urlValue(input: unknown): string | undefined {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return undefined
  }
  const value = (input as Record<string, unknown>).url
  return typeof value === "string" && value.length > 0 ? value : undefined
}

function domainFromUrl(url: string): string | undefined {
  try {
    return new URL(url).hostname.toLowerCase()
  } catch {
    return undefined
  }
}

function shellWords(cmd: string): string[] {
  return cmd.trim().split(/\s+/).filter(Boolean)
}

function bashPrefixPattern(cmd: string): string | undefined {
  const words = shellWords(cmd)
  if (words.length === 0) return undefined
  const executable = words[0]
  const subcommand = words[1]

  if (["npm", "pnpm", "yarn", "bun"].includes(executable)) {
    if (subcommand === "run") {
      const scriptName = words[2]
      if (scriptName) return `${executable} run ${scriptName}*`
      return `${executable} run*`
    }
    if (subcommand) return `${executable} ${subcommand}*`
    return `${executable}*`
  }

  if (executable === "git" && subcommand) {
    return `git ${subcommand}*`
  }

  return words.length > 1
    ? `${words.slice(0, 2).join(" ")}*`
    : `${executable}*`
}

function mcpServerRule(toolName: string): string | undefined {
  const match = /^mcp__([^_]+)__/.exec(toolName)
  if (!match) return undefined
  return `mcp__${match[1]}__*`
}

export function buildPermissionSuggestions(
  toolName: string,
  input: unknown,
): PermissionSuggestion[] {
  const suggestions: PermissionSuggestion[] = [
    {
      id: "allow_once",
      key: "y",
      label: "allow once",
      behavior: "allow",
    },
    {
      id: "deny_once",
      key: "n",
      label: "deny once",
      behavior: "deny",
    },
    {
      id: "allow_tool",
      key: "a",
      label: `always allow ${canonicalSuggestionToolName(toolName)}`,
      behavior: "allow",
      rule: {
        toolName: canonicalSuggestionToolName(toolName),
        tool: permissionRuleValueToString({
          toolName: canonicalSuggestionToolName(toolName),
        }),
        behavior: "allow",
        source: "userSettings",
      },
    },
  ]

  const path = pathValue(input)
  if (path && ["FileRead", "FileWrite", "FileEdit"].includes(toolName)) {
    const escapedPath = escapeRulePattern(path)
    const canonicalToolName = canonicalSuggestionToolName(toolName)
    suggestions.push(
      {
        id: "allow_path",
        key: "p",
        label: `always allow ${canonicalToolName} for ${path}`,
        behavior: "allow",
        rule: {
          toolName: canonicalToolName,
          ruleContent: escapedPath,
          tool: permissionRuleValueToString({
            toolName: canonicalToolName,
            ruleContent: escapedPath,
          }),
          behavior: "allow",
          source: "userSettings",
        },
      },
      {
        id: "deny_path",
        key: "d",
        label: `always deny ${canonicalToolName} for ${path}`,
        behavior: "deny",
        rule: {
          toolName: canonicalToolName,
          ruleContent: escapedPath,
          tool: permissionRuleValueToString({
            toolName: canonicalToolName,
            ruleContent: escapedPath,
          }),
          behavior: "deny",
          source: "userSettings",
        },
      },
    )
    return suggestions
  }

  const cmd = cmdValue(input)
  const bashPattern = cmd ? bashPrefixPattern(cmd) : undefined
  if (toolName === "Bash" && bashPattern) {
    suggestions.push(
      {
        id: "allow_command_prefix",
        key: "c",
        label: `always allow ${bashPattern}`,
        behavior: "allow",
        rule: {
          toolName: "Bash",
          ruleContent: escapeRulePattern(bashPattern),
          tool: permissionRuleValueToString({
            toolName: "Bash",
            ruleContent: escapeRulePattern(bashPattern),
          }),
          behavior: "allow",
          source: "userSettings",
        },
      },
      {
        id: "deny_command_prefix",
        key: "d",
        label: `always deny ${bashPattern}`,
        behavior: "deny",
        rule: {
          toolName: "Bash",
          ruleContent: escapeRulePattern(bashPattern),
          tool: permissionRuleValueToString({
            toolName: "Bash",
            ruleContent: escapeRulePattern(bashPattern),
          }),
          behavior: "deny",
          source: "userSettings",
        },
      },
    )
    return suggestions
  }

  const url = urlValue(input)
  const domain = url ? domainFromUrl(url) : undefined
  if (toolName === "WebFetch" && domain) {
    suggestions.push(
      {
        id: "allow_domain",
        key: "w",
        label: `always allow domain ${domain}`,
        behavior: "allow",
        rule: {
          toolName: "WebFetch",
          ruleContent: `domain:${domain}`,
          tool: permissionRuleValueToString({
            toolName: "WebFetch",
            ruleContent: `domain:${domain}`,
          }),
          behavior: "allow",
          source: "userSettings",
        },
      },
      {
        id: "deny_domain",
        key: "d",
        label: `always deny domain ${domain}`,
        behavior: "deny",
        rule: {
          toolName: "WebFetch",
          ruleContent: `domain:${domain}`,
          tool: permissionRuleValueToString({
            toolName: "WebFetch",
            ruleContent: `domain:${domain}`,
          }),
          behavior: "deny",
          source: "userSettings",
        },
      },
    )
    return suggestions
  }

  const serverRule = mcpServerRule(toolName)
  if (serverRule) {
    suggestions.push(
      {
        id: "allow_mcp_server",
        key: "s",
        label: `always allow MCP server ${serverRule}`,
        behavior: "allow",
        rule: {
          toolName: serverRule,
          tool: serverRule,
          behavior: "allow",
          source: "userSettings",
        },
      },
      {
        id: "deny_mcp_tool",
        key: "d",
        label: `always deny ${toolName}`,
        behavior: "deny",
        rule: {
          toolName,
          tool: toolName,
          behavior: "deny",
          source: "userSettings",
        },
      },
    )
    return suggestions
  }

  suggestions.push({
    id: "deny_tool",
    key: "d",
    label: `always deny ${toolName}`,
    behavior: "deny",
    rule: {
      toolName,
      tool: toolName,
      behavior: "deny",
      source: "userSettings",
    },
  })

  return suggestions
}
