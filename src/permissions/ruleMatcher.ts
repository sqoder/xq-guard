import { isAbsolute, relative } from "path"
import { bashPatternMatches } from "../bash/ruleMatcher"
import { PermissionRule, ToolContext } from "./types"
import { normalizePermissionRule } from "./permissionRuleParser"
import { isBashWriteOperation } from "../bashPermissions"

const TOOL_ALIASES: Record<string, string> = {
  Read: "FileRead",
  Edit: "FileEdit",
  Write: "FileWrite",
}

function canonicalToolName(name: string): string {
  return TOOL_ALIASES[name] || name
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

function legacyPatternMatches(pattern: string, input: string): boolean {
  try {
    return new RegExp(pattern).test(input)
  } catch {
    return false
  }
}

function globMatches(pattern: string, value: string): boolean {
  if (pattern.includes("*") || pattern.includes("?")) {
    return globToRegExp(normalizeSlashes(pattern)).test(normalizeSlashes(value))
  }
  return normalizeSlashes(pattern) === normalizeSlashes(value)
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

function pathCandidates(path: string, ctx: ToolContext): string[] {
  const normalized = normalizeSlashes(path)
  const candidates = new Set([normalized])
  if (isAbsolute(path)) {
    const rel = normalizeSlashes(relative(ctx.cwd, path))
    if (rel && !rel.startsWith("..")) candidates.add(rel)
  }
  return [...candidates]
}

function toolMatchesRule(ruleTool: string, toolName: string): boolean {
  const canonicalRuleTool = canonicalToolName(ruleTool)
  const canonicalTool = canonicalToolName(toolName)

  if (canonicalRuleTool === "*") return true
  if (canonicalRuleTool === canonicalTool) return true
  if (canonicalRuleTool.endsWith("__*")) {
    const prefix = canonicalRuleTool.slice(0, -1)
    return canonicalTool.startsWith(prefix)
  }
  if (
    canonicalRuleTool.startsWith("mcp__") &&
    canonicalTool.startsWith(`${canonicalRuleTool}__`)
  ) {
    return true
  }
  return false
}

function parseInputObject(input: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(input)
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>
    }
    return undefined
  } catch {
    return undefined
  }
}

function ruleContentMatches(
  toolName: string,
  ruleContent: string,
  input: string,
  ctx: ToolContext,
): boolean {
  const parsed = parseInputObject(input)

  const canonicalTool = canonicalToolName(toolName)
  if (canonicalTool === "Bash") {
    if (!parsed || typeof parsed.cmd !== "string") return false
    return bashPatternMatches(ruleContent, parsed.cmd)
  }

  if (canonicalTool === "WebFetch") {
    if (!parsed || typeof parsed.url !== "string") return false
    if (ruleContent.startsWith("domain:")) {
      return domainMatches(ruleContent.slice("domain:".length), parsed.url)
    }
    return globMatches(ruleContent, parsed.url)
  }

  if (["FileRead", "FileWrite", "FileEdit"].includes(canonicalTool)) {
    if (!parsed || typeof parsed.path !== "string") return false
    return pathCandidates(parsed.path, ctx).some(candidate =>
      globMatches(ruleContent, candidate),
    )
  }

  if (canonicalTool.startsWith("mcp__")) {
    return globMatches(ruleContent, input)
  }

  return legacyPatternMatches(ruleContent, input)
}

function legacyPatternFieldMatches(pattern: string, input: string): boolean {
  return legacyPatternMatches(pattern, input)
}

export function isWriteOperation(toolName: string, input: string): boolean {
  const canonicalTool = canonicalToolName(toolName)
  if (["FileWrite", "FileEdit"].includes(canonicalTool)) return true
  if (canonicalTool === "Bash") {
    const parsed = parseInputObject(input)
    if (!parsed || typeof parsed.cmd !== "string") {
      return true
    }
    return isBashWriteOperation(parsed.cmd)
  }
  return false
}

export function ruleMatchesToolCall(
  rule: PermissionRule,
  toolName: string,
  input: string,
  ctx: ToolContext,
): boolean {
  const normalizedRule = normalizePermissionRule(rule)
  if (!toolMatchesRule(normalizedRule.toolName, toolName)) return false

  if (
    typeof normalizedRule.ruleContent === "string" &&
    !ruleContentMatches(
      toolName,
      normalizedRule.ruleContent,
      input,
      ctx,
    )
  ) {
    return false
  }

  if (
    typeof normalizedRule.pattern === "string" &&
    !legacyPatternFieldMatches(normalizedRule.pattern, input)
  ) {
    return false
  }

  return true
}
