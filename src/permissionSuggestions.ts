import { PermissionSuggestion } from "./types"

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

function registrableDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split(".").filter(Boolean)
  if (parts.length <= 2) return parts.join(".")
  return parts.slice(-2).join(".")
}

function domainFromUrl(url: string): string | undefined {
  try {
    return registrableDomain(new URL(url).hostname)
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
    if (subcommand === "run") return `${executable} run:*`
    if (subcommand) return `${executable}:*`
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
      label: `always allow ${toolName}`,
      behavior: "allow",
      rule: {
        tool: toolName,
        behavior: "allow",
        source: "user",
      },
    },
  ]

  const path = pathValue(input)
  if (path && ["FileRead", "FileWrite", "FileEdit"].includes(toolName)) {
    const escapedPath = escapeRulePattern(path)
    suggestions.push(
      {
        id: "allow_path",
        key: "p",
        label: `always allow ${toolName} for ${path}`,
        behavior: "allow",
        rule: {
          tool: `${toolName}(${escapedPath})`,
          behavior: "allow",
          source: "user",
        },
      },
      {
        id: "deny_path",
        key: "d",
        label: `always deny ${toolName} for ${path}`,
        behavior: "deny",
        rule: {
          tool: `${toolName}(${escapedPath})`,
          behavior: "deny",
          source: "user",
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
          tool: `Bash(${escapeRulePattern(bashPattern)})`,
          behavior: "allow",
          source: "user",
        },
      },
      {
        id: "deny_command_prefix",
        key: "d",
        label: `always deny ${bashPattern}`,
        behavior: "deny",
        rule: {
          tool: `Bash(${escapeRulePattern(bashPattern)})`,
          behavior: "deny",
          source: "user",
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
          tool: `WebFetch(domain:${domain})`,
          behavior: "allow",
          source: "user",
        },
      },
      {
        id: "deny_domain",
        key: "d",
        label: `always deny domain ${domain}`,
        behavior: "deny",
        rule: {
          tool: `WebFetch(domain:${domain})`,
          behavior: "deny",
          source: "user",
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
          tool: serverRule,
          behavior: "allow",
          source: "user",
        },
      },
      {
        id: "deny_mcp_tool",
        key: "d",
        label: `always deny ${toolName}`,
        behavior: "deny",
        rule: {
          tool: toolName,
          behavior: "deny",
          source: "user",
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
      tool: toolName,
      behavior: "deny",
      source: "user",
    },
  })

  return suggestions
}
