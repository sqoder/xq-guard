import {
  analyzeShellOperators,
  isSensitiveRedirectionTarget,
} from "./redirection"
import { splitCommand } from "./splitCommand"
import { stripSafeWrappers, tokenizeShellWords } from "./tokenize"

export interface BashRiskAssessment {
  decision: "allow" | "ask" | "deny"
  isReadOnly: boolean
  reason?: string
}

const READ_ONLY_COMMANDS = new Set([
  "cat",
  "echo",
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

const ASK_COMMANDS = new Set([
  "chmod",
  "chown",
  "cp",
  "dd",
  "ln",
  "mkdir",
  "mv",
  "rm",
  "rmdir",
  "rsync",
  "scp",
  "ssh",
  "touch",
])

const DENY_COMMANDS = new Set(["eval"])
const SHELL_INTERPRETERS = new Set(["bash", "dash", "ksh", "sh", "zsh"])
const SOURCE_COMMANDS = new Set(["source", "."])

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

const PACKAGE_MANAGERS = new Set(["bun", "npm", "pnpm", "yarn"])
const ASK_PACKAGE_SUBCOMMANDS = new Set([
  "add",
  "audit",
  "dedupe",
  "install",
  "link",
  "remove",
  "uninstall",
  "update",
  "upgrade",
])
const DENY_PACKAGE_SUBCOMMANDS = new Set(["publish"])

function combineAssessments(assessments: BashRiskAssessment[]): BashRiskAssessment {
  const denied = assessments.find(item => item.decision === "deny")
  if (denied) return denied

  const ask = assessments.find(item => item.decision === "ask")
  if (ask) return ask

  return {
    decision: "allow",
    isReadOnly: assessments.every(item => item.isReadOnly),
  }
}

function packageSubcommand(words: string[]): string | undefined {
  if (words.length < 2) return undefined
  if (words[0] === "bun" && words[1] === "x") return undefined
  return words[1]
}

function hasRemoteScriptPipeline(command: string): boolean {
  return /\b(curl|wget)\b[^|]*\|\s*(bash|sh|zsh|dash)\b/i.test(command)
}

function hasSensitiveTeeTarget(command: string): boolean {
  const teePattern = /\btee\b(?:\s+-[a-zA-Z]+)*\s+([^\s|;&]+)/g
  let match = teePattern.exec(command)
  while (match) {
    if (isSensitiveRedirectionTarget(match[1])) {
      return true
    }
    match = teePattern.exec(command)
  }
  return false
}

function assessSimpleCommand(command: string): BashRiskAssessment {
  const tokenized = tokenizeShellWords(command)
  if (tokenized.hasUnterminatedQuote) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: `Command has unterminated quote: ${command}`,
    }
  }

  const words = stripSafeWrappers(tokenized.words)
  const executable = words[0]
  if (!executable) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: "Unable to identify shell command",
    }
  }

  if (DENY_COMMANDS.has(executable)) {
    return {
      decision: "deny",
      isReadOnly: false,
      reason: `Command is blocked by policy: ${executable}`,
    }
  }

  if (SOURCE_COMMANDS.has(executable)) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: `Command loads shell state dynamically: ${executable}`,
    }
  }

  if (SHELL_INTERPRETERS.has(executable) && words.includes("-c")) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: `Command executes shell code dynamically: ${executable} -c`,
    }
  }

  if (ASK_COMMANDS.has(executable)) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: `Command may modify filesystem or system state: ${executable}`,
    }
  }

  if (executable === "tee") {
    if (words.slice(1).some(target => isSensitiveRedirectionTarget(target))) {
      return {
        decision: "deny",
        isReadOnly: false,
        reason: "Command writes to sensitive file via tee",
      }
    }
    return {
      decision: "ask",
      isReadOnly: false,
      reason: "tee can overwrite files",
    }
  }

  if (executable === "git") {
    const subcommand = words[1]
    if (!subcommand) {
      return { decision: "allow", isReadOnly: true }
    }

    if (
      subcommand === "reset" &&
      words.some(word => ["--hard", "-H"].includes(word))
    ) {
      return {
        decision: "ask",
        isReadOnly: false,
        reason: "git reset --hard can destroy local changes",
      }
    }

    if (
      subcommand === "clean" &&
      words.some(word => word.includes("-f") || word.includes("--force"))
    ) {
      return {
        decision: "ask",
        isReadOnly: false,
        reason: "git clean with force can remove untracked files",
      }
    }

    if (MUTATING_GIT_SUBCOMMANDS.has(subcommand)) {
      return {
        decision: "ask",
        isReadOnly: false,
        reason: `Git subcommand may modify repository or remote state: ${subcommand}`,
      }
    }

    return {
      decision: "allow",
      isReadOnly: READ_ONLY_GIT_SUBCOMMANDS.has(subcommand),
    }
  }

  if (PACKAGE_MANAGERS.has(executable)) {
    const subcommand = packageSubcommand(words)
    if (subcommand && DENY_PACKAGE_SUBCOMMANDS.has(subcommand)) {
      return {
        decision: "deny",
        isReadOnly: false,
        reason: `Package manager subcommand is blocked: ${subcommand}`,
      }
    }
    if (subcommand && ASK_PACKAGE_SUBCOMMANDS.has(subcommand)) {
      return {
        decision: "ask",
        isReadOnly: false,
        reason: `Package manager subcommand may modify dependencies: ${subcommand}`,
      }
    }
  }

  if (READ_ONLY_COMMANDS.has(executable)) {
    return { decision: "allow", isReadOnly: true }
  }

  return { decision: "allow", isReadOnly: false }
}

export function assessBashCommandRisk(command: string): BashRiskAssessment {
  const trimmed = command.trim()
  if (trimmed.length === 0) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: "Empty shell command",
    }
  }

  const split = splitCommand(trimmed)
  if (split.unsafeReason) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: split.unsafeReason,
    }
  }

  const segmentAssessments = split.segments.map(segment =>
    assessSimpleCommand(segment),
  )
  const combined = combineAssessments(segmentAssessments)
  if (combined.decision === "deny") {
    return combined
  }

  const operatorAnalysis = analyzeShellOperators(trimmed)
  if (operatorAnalysis.hasCommandSubstitution) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: `Command contains shell substitution: ${trimmed}`,
    }
  }

  if (operatorAnalysis.hasBackground) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: `Command contains background execution: ${trimmed}`,
    }
  }

  if (operatorAnalysis.hasPipe && hasRemoteScriptPipeline(trimmed)) {
    return {
      decision: "deny",
      isReadOnly: false,
      reason: "Piping network output directly into a shell is blocked",
    }
  }

  if (hasSensitiveTeeTarget(trimmed)) {
    return {
      decision: "deny",
      isReadOnly: false,
      reason: "Command writes to sensitive file via tee",
    }
  }

  if (operatorAnalysis.redirectionTargets.some(isSensitiveRedirectionTarget)) {
    return {
      decision: "deny",
      isReadOnly: false,
      reason: "Command redirects output into sensitive files",
    }
  }

  if (operatorAnalysis.hasPipe || operatorAnalysis.hasRedirection) {
    return {
      decision: "ask",
      isReadOnly: false,
      reason: `Command contains shell operators: ${trimmed}`,
    }
  }

  return combined
}
