import {
  PermissionRequestHandler,
  PermissionRequestedEvent,
  PermissionResponse,
} from "./types"

function promptLines(event: PermissionRequestedEvent): string {
  const suggestions = event.suggestions
    .map(suggestion => `(${suggestion.key}) ${suggestion.label}`)
    .join("\n")
  return [
    `\nAgent wants to execute [${event.toolName}]`,
    `Input: ${JSON.stringify(event.input)}`,
    `Reason: ${event.reason}`,
    "",
    "Allow?",
    suggestions,
    "> ",
  ].join("\n")
}

export function createCliPermissionRequestHandler(): PermissionRequestHandler {
  return async (event: PermissionRequestedEvent): Promise<PermissionResponse> => {
    process.stdout.write(promptLines(event))

    return await new Promise<PermissionResponse>(resolve => {
      process.stdin.once("data", data => {
        const suggestionKey = data.toString().trim().toLowerCase()
        const suggestion = event.suggestions.find(
          candidate => candidate.key === suggestionKey,
        )
        if (!suggestion) {
          resolve({
            decision: "deny",
            reason: "User rejected",
          })
          return
        }

        resolve({
          decision: suggestion.behavior,
          suggestionKey,
          reason:
            suggestion.behavior === "allow"
              ? "User approved"
              : "User rejected",
          rule: suggestion.rule,
        })
      })
    })
  }
}
