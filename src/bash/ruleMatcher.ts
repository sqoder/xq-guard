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
      source += ".*"
    } else if (char === "?") {
      source += "."
    } else {
      source += escapeRegex(char)
    }
  }
  source += "$"
  return new RegExp(source)
}

export function bashPatternMatches(pattern: string, command: string): boolean {
  const normalizedPattern = pattern.trim()
  const normalizedCommand = command.trim()
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
