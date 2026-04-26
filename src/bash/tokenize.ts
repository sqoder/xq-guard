export interface ShellTokenizeResult {
  words: string[]
  hasUnterminatedQuote: boolean
}

export function tokenizeShellWords(command: string): ShellTokenizeResult {
  const words: string[] = []
  let quote: "'" | '"' | null = null
  let escaped = false
  let current = ""

  for (let i = 0; i < command.length; i += 1) {
    const char = command[i]
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

  if (current.length > 0) {
    words.push(current)
  }

  return {
    words,
    hasUnterminatedQuote: quote !== null,
  }
}

export function stripSafeWrappers(words: string[]): string[] {
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
