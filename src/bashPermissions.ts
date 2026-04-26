import { PermissionDecision } from "./types"

export interface BashPermissionAssessment {
  isReadOnly: boolean
  requiresAsk: boolean
  reason?: string
}

const READ_ONLY_COMMANDS = new Set([
  "cat",
  "find",
  "grep",
  "head",
  "less",
  "ls",
  "pwd",
  "rg",
  "tail",
  "wc",
  "which",
])

const DANGEROUS_COMMANDS = new Set([
  "chmod",
  "chown",
  "cp",
  "curl",
  "dd",
  "ln",
  "mkdir",
  "mv",
  "rm",
  "rmdir",
  "rsync",
  "scp",
  "ssh",
  "tee",
  "touch",
  "wget",
])

const MUTATING_GIT_SUBCOMMANDS = new Set([
  "am",
  "apply",
  "bisect",
  "checkout",
  "cherry-pick",
  "clean",
  "clone",
  "commit",
  "fetch",
  "merge",
  "pull",
  "push",
  "rebase",
  "reset",
  "restore",
  "revert",
  "switch",
])

const READ_ONLY_GIT_SUBCOMMANDS = new Set([
  "branch",
  "diff",
  "log",
  "ls-files",
  "show",
  "status",
])

const MUTATING_PACKAGE_SUBCOMMANDS = new Set([
  "add",
  "audit",
  "dedupe",
  "install",
  "link",
  "publish",
  "remove",
  "uninstall",
  "update",
  "upgrade",
])

const PACKAGE_MANAGERS = new Set(["bun", "npm", "pnpm", "yarn"])

function hasUnquotedShellOperator(cmd: string): boolean {
  let quote: "'" | '"' | null = null
  let escaped = false
  for (let i = 0; i < cmd.length; i += 1) {
    const char = cmd[i]
    const next = cmd[i + 1]
    if (escaped) {
      escaped = false
      continue
    }
    if (char === "\\") {
      escaped = true
      continue
    }
    if (quote) {
      if (char === quote) quote = null
      continue
    }
    if (char === "'" || char === '"') {
      quote = char
      continue
    }
    if (char === "`") return true
    if (char === "$" && next === "(") return true
    if (char === ";" || char === "|" || char === "<" || char === ">") {
      return true
    }
    if (char === "&" && next === "&") return true
  }
  return false
}

function tokenizeShellWords(cmd: string): string[] {
  const words: string[] = []
  let quote: "'" | '"' | null = null
  let escaped = false
  let current = ""

  for (let i = 0; i < cmd.length; i += 1) {
    const char = cmd[i]
    if (escaped) {
      current += char
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
      } else {
        current += char
      }
      continue
    }
    if (char === "'" || char === '"') {
      quote = char
      continue
    }
    if (/\s/.test(char)) {
      if (current.length > 0) {
        words.push(current)
        current = ""
      }
      continue
    }
    current += char
  }

  if (current.length > 0) words.push(current)
  return words
}

function stripSafeWrappers(words: string[]): string[] {
  let index = 0
  while (index < words.length) {
    const word = words[index]
    if (["command", "builtin", "noglob", "time"].includes(word)) {
      index += 1
      continue
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) {
      index += 1
      continue
    }
    if (word === "env") {
      index += 1
      while (index < words.length) {
        const envWord = words[index]
        if (envWord === "-i" || envWord.startsWith("-")) {
          index += 1
          continue
        }
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(envWord)) {
          index += 1
          continue
        }
        break
      }
      continue
    }
    break
  }
  return words.slice(index)
}

function packageSubcommand(words: string[]): string | undefined {
  if (words.length < 2) return undefined
  if (words[0] === "bun" && words[1] === "x") return undefined
  return words[1]
}

export function assessBashCommand(cmd: string): BashPermissionAssessment {
  const trimmed = cmd.trim()
  if (trimmed.length === 0) {
    return {
      isReadOnly: false,
      requiresAsk: true,
      reason: "Empty shell command",
    }
  }

  if (hasUnquotedShellOperator(trimmed)) {
    return {
      isReadOnly: false,
      requiresAsk: true,
      reason: `Command contains shell operators or substitutions: ${cmd}`,
    }
  }

  const words = stripSafeWrappers(tokenizeShellWords(trimmed))
  const executable = words[0]
  if (!executable) {
    return {
      isReadOnly: false,
      requiresAsk: true,
      reason: "Unable to identify shell command",
    }
  }

  if (DANGEROUS_COMMANDS.has(executable)) {
    return {
      isReadOnly: false,
      requiresAsk: true,
      reason: `Command may modify files, network, or system state: ${executable}`,
    }
  }

  if (executable === "git") {
    const subcommand = words[1]
    if (!subcommand) {
      return { isReadOnly: true, requiresAsk: false }
    }
    if (MUTATING_GIT_SUBCOMMANDS.has(subcommand)) {
      return {
        isReadOnly: false,
        requiresAsk: true,
        reason: `Git subcommand may modify repository or remote state: ${subcommand}`,
      }
    }
    return {
      isReadOnly: READ_ONLY_GIT_SUBCOMMANDS.has(subcommand),
      requiresAsk: false,
    }
  }

  if (PACKAGE_MANAGERS.has(executable)) {
    const subcommand = packageSubcommand(words)
    if (subcommand && MUTATING_PACKAGE_SUBCOMMANDS.has(subcommand)) {
      return {
        isReadOnly: false,
        requiresAsk: true,
        reason: `Package manager subcommand may modify dependencies or publish state: ${subcommand}`,
      }
    }
  }

  if (READ_ONLY_COMMANDS.has(executable)) {
    return { isReadOnly: true, requiresAsk: false }
  }

  return { isReadOnly: false, requiresAsk: false }
}

export function bashPhysicalSafetyDecision(cmd: string): PermissionDecision | null {
  const assessment = assessBashCommand(cmd)
  if (!assessment.requiresAsk) return null
  return {
    behavior: "ask",
    reason: assessment.reason || `Command requires confirmation: ${cmd}`,
  }
}

export function isBashWriteOperation(cmd: string): boolean {
  const assessment = assessBashCommand(cmd)
  return assessment.requiresAsk || !assessment.isReadOnly
}
