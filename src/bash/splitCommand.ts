export interface SplitCommandResult {
  segments: string[]
  unsafeReason?: string
}

export function splitCommand(command: string): SplitCommandResult {
  const segments: string[] = []
  let quote: "'" | '"' | null = null
  let escaped = false
  let current = ""

  for (let i = 0; i < command.length; i += 1) {
    const char = command[i]
    const next = command[i + 1]
    if (escaped) {
      current += char
      escaped = false
      continue
    }
    if (char === "\\") {
      current += char
      escaped = true
      continue
    }
    if (quote) {
      current += char
      if (char === quote) {
        quote = null
      }
      continue
    }
    if (char === "'" || char === '"') {
      current += char
      quote = char
      continue
    }
    if (char === "`" || (char === "$" && next === "(")) {
      return {
        segments: [],
        unsafeReason: `Command contains shell substitution: ${command}`,
      }
    }
    if (char === "&" && next === "&") {
      if (current.trim().length === 0) {
        return {
          segments: [],
          unsafeReason: `Empty command segment: ${command}`,
        }
      }
      segments.push(current.trim())
      current = ""
      i += 1
      continue
    }
    if (char === "&") {
      return {
        segments: [],
        unsafeReason: `Command contains background operator: ${command}`,
      }
    }
    if (char === ";") {
      if (current.trim().length === 0) {
        return {
          segments: [],
          unsafeReason: `Empty command segment: ${command}`,
        }
      }
      segments.push(current.trim())
      current = ""
      continue
    }
    current += char
  }

  if (quote) {
    return {
      segments: [],
      unsafeReason: `Command has unterminated quote: ${command}`,
    }
  }

  if (current.trim().length > 0) {
    segments.push(current.trim())
  }

  return { segments }
}
