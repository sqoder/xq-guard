import { PermissionRule, ToolContext } from "./types"
import { isAbsolute, relative } from "path"

interface ParsedRuleTool {
  tool: string
  inlinePattern?: string
}

function parseRuleTool(ruleTool: string): ParsedRuleTool {
  const open = ruleTool.indexOf("(")
  if (open <= 0 || !ruleTool.endsWith(")")) {
    return { tool: ruleTool }
  }
  return {
    tool: ruleTool.slice(0, open),
    inlinePattern: ruleTool.slice(open + 1, -1),
  }
}

function toolMatchesRule(ruleTool: string, toolName: string): boolean {
  if (ruleTool === "*") return true
  if (ruleTool === toolName) return true
  if (ruleTool.endsWith("__*")) {
    const prefix = ruleTool.slice(0, -1)
    return toolName.startsWith(prefix)
  }
  return false
}

function legacyPatternMatches(pattern: string, input: string): boolean {
  try {
    return new RegExp(pattern).test(input)
  } catch {
    return false
  }
}

function escapeRegex(text: string): string {
  return text.replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
}

function globToRegExp(glob: string): RegExp {
  let source = "^"
  for (let i = 0; i < glob.length; i += 1) {
    const char = glob[i]
    const next = glob[i + 1]
    if (char === "*" && next === "*") {
      source += ".*"
      i += 1
    } else if (char === "*") {
      source += "[^/]*"
    } else if (char === "?") {
      source += "[^/]"
    } else {
      source += escapeRegex(char)
    }
  }
  source += "$"
  return new RegExp(source)
}

function normalizeSlashes(text: string): string {
  return text.replace(/\\/g, "/")
}

function pathCandidates(path: string, ctx: ToolContext): string[] {
  const normalized = normalizeSlashes(path)
  const candidates = new Set([normalized])
  if (isAbsolute(path)) {
    const rel = normalizeSlashes(relative(ctx.cwd, path))
    if (rel && !rel.startsWith("..")) candidates.add(rel)
  }
  return [...candidates]
}

function globMatches(pattern: string, value: string): boolean {
  if (pattern.includes("*") || pattern.includes("?")) {
    return globToRegExp(normalizeSlashes(pattern)).test(normalizeSlashes(value))
  }
  return normalizeSlashes(pattern) === normalizeSlashes(value)
}

function bashPatternMatches(pattern: string, cmd: string): boolean {
  const normalizedPattern = pattern.trim()
  const normalizedCommand = cmd.trim()
  const variants = new Set([
    normalizedPattern,
    normalizedPattern.replace(/:\*$/u, " *"),
  ])
  return [...variants].some(variant => {
    if (variant.includes("*") || variant.includes("?")) {
      return globToRegExp(variant).test(normalizedCommand)
    }
    return (
      normalizedCommand === variant ||
      normalizedCommand.startsWith(`${variant} `)
    )
  })
}

function domainMatches(ruleDomain: string, urlValue: string): boolean {
  try {
    const host = new URL(urlValue).hostname.toLowerCase()
    const domain = ruleDomain.toLowerCase()
    return host === domain || host.endsWith(`.${domain}`)
  } catch {
    return false
  }
}

function inlinePatternMatches(
  pattern: string,
  toolName: string,
  input: string,
  ctx: ToolContext,
): boolean {
  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(input)
  } catch {
    return false
  }

  if (toolName === "Bash") {
    return typeof parsed.cmd === "string" && bashPatternMatches(pattern, parsed.cmd)
  }

  if (toolName === "WebFetch") {
    if (typeof parsed.url !== "string") return false
    if (pattern.startsWith("domain:")) {
      return domainMatches(pattern.slice("domain:".length), parsed.url)
    }
    return globMatches(pattern, parsed.url)
  }

  if (["FileRead", "FileWrite", "FileEdit"].includes(toolName)) {
    if (typeof parsed.path !== "string") return false
    return pathCandidates(parsed.path, ctx).some(candidate =>
      globMatches(pattern, candidate),
    )
  }

  return legacyPatternMatches(pattern, input)
}

export function ruleMatchesToolCall(
  rule: PermissionRule,
  toolName: string,
  input: string,
  ctx: ToolContext,
): boolean {
  const parsedRule = parseRuleTool(rule.tool)
  if (!toolMatchesRule(parsedRule.tool, toolName)) return false
  if (
    parsedRule.inlinePattern &&
    !inlinePatternMatches(parsedRule.inlinePattern, toolName, input, ctx)
  ) {
    return false
  }
  if (rule.pattern && !legacyPatternMatches(rule.pattern, input)) return false
  return true
}
