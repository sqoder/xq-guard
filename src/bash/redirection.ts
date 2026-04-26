function isWordBoundary(char: string | undefined): boolean {
  return (
    char === undefined ||
    /\s/.test(char) ||
    ["|", "<", ">", ";", "&"].includes(char)
  )
}

function normalizeTarget(token: string): string {
  return token.replace(/^['"]|['"]$/g, "")
}

export interface ShellOperatorAnalysis {
  hasPipe: boolean
  hasRedirection: boolean
  hasBackground: boolean
  hasCommandSubstitution: boolean
  redirectionTargets: string[]
}

export function analyzeShellOperators(command: string): ShellOperatorAnalysis {
  const redirectionTargets: string[] = []
  let hasPipe = false
  let hasRedirection = false
  let hasBackground = false
  let hasCommandSubstitution = false
  let quote: "'" | '"' | null = null
  let escaped = false

  for (let i = 0; i < command.length; i += 1) {
    const char = command[i]
    const next = command[i + 1]
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

    if (char === "`" || (char === "$" && next === "(")) {
      hasCommandSubstitution = true
      continue
    }

    if (char === "&" && next === "&") {
      i += 1
      continue
    }
    if (char === "&") {
      hasBackground = true
      continue
    }

    if (char === "|") {
      if (next !== "|") {
        hasPipe = true
      }
      continue
    }

    if (char !== ">" && char !== "<") {
      continue
    }

    hasRedirection = true
    let cursor = i + 1
    while (cursor < command.length && [">", "<"].includes(command[cursor])) {
      cursor += 1
    }
    while (cursor < command.length && /\s/.test(command[cursor])) {
      cursor += 1
    }

    let token = ""
    while (cursor < command.length && !isWordBoundary(command[cursor])) {
      token += command[cursor]
      cursor += 1
    }
    if (token.length > 0) {
      redirectionTargets.push(normalizeTarget(token))
    }
    i = cursor - 1
  }

  return {
    hasPipe,
    hasRedirection,
    hasBackground,
    hasCommandSubstitution,
    redirectionTargets,
  }
}

const SENSITIVE_REDIRECTION_TARGETS = [
  ".env",
  ".npmrc",
  ".pypirc",
  ".netrc",
  ".ssh/config",
]

export function isSensitiveRedirectionTarget(target: string): boolean {
  const normalized = target.toLowerCase()
  if (normalized === ".env" || normalized.startsWith(".env.")) {
    return true
  }

  return SENSITIVE_REDIRECTION_TARGETS.some(candidate =>
    normalized.endsWith(candidate),
  )
}
