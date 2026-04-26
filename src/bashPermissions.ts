import { assessBashCommandRisk } from "./bash/riskClassifier"
import { splitCommand } from "./bash/splitCommand"
import { tokenizeShellWords } from "./bash/tokenize"
import { PermissionDecision } from "./types"

export interface BashPermissionAssessment {
  isReadOnly: boolean
  requiresAsk: boolean
  reason?: string
  decision: "allow" | "ask" | "deny"
}

function isOptionToken(token: string): boolean {
  return token.startsWith("-")
}

function isShellOperatorToken(token: string): boolean {
  return token === "|" || token === "||" || token === "&&" || token === ";" || token === "&"
}

function sanitizePathToken(token: string): string | null {
  const trimmed = token.trim()
  if (!trimmed) return null
  if (trimmed === "-" || trimmed === "--") return null
  if (trimmed.startsWith("$")) return null

  const unquoted = trimmed.replace(/^['"]|['"]$/g, "")
  if (!unquoted) return null
  if (unquoted === "-" || unquoted === "--") return null
  if (unquoted.startsWith("$")) return null
  return unquoted
}

function uniquePaths(paths: string[]): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const path of paths) {
    if (!path || seen.has(path)) continue
    seen.add(path)
    result.push(path)
  }
  return result
}

function extractRedirectionTargets(command: string): string[] {
  const targets: string[] = []
  let quote: "'" | '"' | null = null
  let escaped = false

  for (let i = 0; i < command.length; i += 1) {
    const char = command[i]
    if (escaped) {
      escaped = false
      continue
    }
    if (char === "\\") {
      escaped = true
      continue
    }
    if (quote) {
      if (char === quote) {
        quote = null
      }
      continue
    }
    if (char === "'" || char === '"') {
      quote = char
      continue
    }
    if (char !== ">") {
      continue
    }

    let cursor = i + 1
    while (cursor < command.length && command[cursor] === ">") {
      cursor += 1
    }
    while (cursor < command.length && /\s/.test(command[cursor])) {
      cursor += 1
    }

    let token = ""
    let tokenQuote: "'" | '"' | null = null
    while (cursor < command.length) {
      const current = command[cursor]
      if (tokenQuote) {
        if (current === tokenQuote) {
          tokenQuote = null
          cursor += 1
          continue
        }
        token += current
        cursor += 1
        continue
      }

      if (current === "'" || current === '"') {
        tokenQuote = current
        cursor += 1
        continue
      }
      if (/\s/.test(current) || current === "|" || current === ";" || current === "&") {
        break
      }
      token += current
      cursor += 1
    }

    const sanitized = sanitizePathToken(token)
    if (sanitized) {
      targets.push(sanitized)
    }
    i = cursor - 1
  }

  return targets
}

function extractTeeTargets(words: string[]): string[] {
  const targets: string[] = []
  for (let i = 0; i < words.length; i += 1) {
    if (words[i] !== "tee") continue
    let cursor = i + 1
    while (cursor < words.length) {
      const token = words[cursor]
      if (isShellOperatorToken(token)) break
      if (!isOptionToken(token)) {
        const sanitized = sanitizePathToken(token)
        if (sanitized) {
          targets.push(sanitized)
        }
      }
      cursor += 1
    }
  }
  return targets
}

function extractPathOperands(words: string[]): string[] {
  if (words.length === 0) return []
  const executable = words[0]
  const positional = words
    .slice(1)
    .filter(token => !isOptionToken(token))
    .map(token => sanitizePathToken(token))
    .filter((token): token is string => Boolean(token))

  if (executable === "cp" || executable === "mv") {
    if (positional.length >= 2) {
      return [positional[positional.length - 1]]
    }
    return []
  }

  if (executable === "rm" || executable === "rmdir") {
    return positional
  }

  if (
    executable === "touch" ||
    executable === "mkdir" ||
    executable === "install" ||
    executable === "truncate"
  ) {
    return positional
  }

  if (executable === "sed" && words.some(token => token === "-i" || token.startsWith("-i"))) {
    if (positional.length >= 2) {
      return positional.slice(1)
    }
  }

  if (executable === "perl" && words.some(token => token === "-i" || token.startsWith("-i"))) {
    if (positional.length >= 1) {
      return [positional[positional.length - 1]]
    }
  }

  return []
}

function extractPythonOpenTargets(command: string): string[] {
  const targets: string[] = []
  const openPattern =
    /open\(\s*["']([^"']+)["']\s*,\s*["'](?:w|a|x|r\+|w\+|a\+)["']/g
  let match = openPattern.exec(command)
  while (match) {
    const sanitized = sanitizePathToken(match[1])
    if (sanitized) {
      targets.push(sanitized)
    }
    match = openPattern.exec(command)
  }
  return targets
}

function extractSegmentWritePaths(segment: string): string[] {
  const words = tokenizeShellWords(segment).words
  return uniquePaths([
    ...extractRedirectionTargets(segment),
    ...extractTeeTargets(words),
    ...extractPathOperands(words),
    ...extractPythonOpenTargets(segment),
  ])
}

export function extractBashWritePaths(command: string): string[] {
  const trimmed = command.trim()
  if (!trimmed) {
    return []
  }

  const split = splitCommand(trimmed)
  if (split.unsafeReason || split.segments.length === 0) {
    return extractSegmentWritePaths(trimmed)
  }

  const paths = split.segments.flatMap(segment => extractSegmentWritePaths(segment))
  return uniquePaths(paths)
}

export function assessBashCommand(cmd: string): BashPermissionAssessment {
  const assessment = assessBashCommandRisk(cmd)
  return {
    isReadOnly: assessment.isReadOnly,
    requiresAsk: assessment.decision !== "allow",
    reason: assessment.reason,
    decision: assessment.decision,
  }
}

export function bashPhysicalSafetyDecision(cmd: string): PermissionDecision | null {
  const assessment = assessBashCommand(cmd)
  if (assessment.decision === "allow") {
    return null
  }

  return {
    behavior: assessment.decision === "deny" ? "deny" : "ask",
    reason: assessment.reason || `Command requires confirmation: ${cmd}`,
  }
}

export function isBashWriteOperation(cmd: string): boolean {
  if (extractBashWritePaths(cmd).length > 0) {
    return true
  }
  const assessment = assessBashCommand(cmd)
  return assessment.decision !== "allow" || !assessment.isReadOnly
}
