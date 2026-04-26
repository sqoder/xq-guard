import { assessBashCommand } from "../bashPermissions"
import { isWriteOperation, ruleMatchesToolCall } from "./ruleMatcher"
import {
  PermissionDecision,
  PermissionMode,
  PermissionRule,
  ToolContext,
  normalizePermissionMode,
} from "./types"

function isPlanningReadOperation(toolName: string, input: string): boolean {
  if (toolName === "FileRead") {
    return true
  }

  if (toolName === "Bash") {
    try {
      const parsed = JSON.parse(input)
      if (typeof parsed?.cmd !== "string") {
        return false
      }
      const assessment = assessBashCommand(parsed.cmd)
      return assessment.isReadOnly && !assessment.requiresAsk
    } catch {
      return false
    }
  }

  return false
}

function denyForMode(mode: PermissionMode, toolName: string, input: string) {
  if ((mode === "readOnly" || mode === "plan") && isWriteOperation(toolName, input)) {
    return {
      behavior: "deny" as const,
      reason:
        mode === "plan"
          ? "Write operation forbidden in Plan mode"
          : "Write operation forbidden in ReadOnly mode",
    }
  }

  return null
}

export function hasPermissionsToUseTool(
  toolName: string,
  input: string,
  ctx: ToolContext,
  rules: PermissionRule[],
): PermissionDecision {
  const mode = normalizePermissionMode(ctx.mode)
  const matchingRules = rules.filter(rule =>
    ruleMatchesToolCall(rule, toolName, input, ctx),
  )

  if (matchingRules.some(rule => rule.behavior === "deny")) {
    return { behavior: "deny", reason: "Matched a deny rule" }
  }

  if (mode === "bypassPermissions") {
    return { behavior: "allow", reason: "Bypass mode" }
  }

  if (matchingRules.length > 0) {
    const writeDecision = denyForMode(mode, toolName, input)
    if (writeDecision) {
      return writeDecision
    }

    if (matchingRules.some(rule => rule.behavior === "ask")) {
      if (mode === "dontAsk" || mode === "plan") {
        return {
          behavior: "deny",
          reason:
            mode === "plan"
              ? "Plan mode does not prompt for ask rules"
              : "dontAsk mode does not prompt for ask rules",
        }
      }
      return { behavior: "ask", reason: "Matched an ask rule" }
    }

    return { behavior: "allow", reason: "Matched allow rule(s)" }
  }

  if (mode === "readOnly") {
    if (isWriteOperation(toolName, input)) {
      return {
        behavior: "deny",
        reason: "Write operation forbidden in ReadOnly mode",
      }
    }
    return { behavior: "allow", reason: "ReadOnly mode" }
  }

  if (mode === "plan") {
    if (isWriteOperation(toolName, input)) {
      return {
        behavior: "deny",
        reason: "Write operation forbidden in Plan mode",
      }
    }
    if (isPlanningReadOperation(toolName, input)) {
      return { behavior: "allow", reason: "Plan mode read operation" }
    }
    return {
      behavior: "deny",
      reason: "Plan mode requires an explicit rule for this tool",
    }
  }

  if (mode === "dontAsk") {
    return {
      behavior: "deny",
      reason: "dontAsk mode does not prompt for new permissions",
    }
  }

  if (mode === "acceptEdits") {
    if (toolName === "FileWrite" || toolName === "FileEdit") {
      return { behavior: "allow", reason: "AcceptEdits mode allows file edits" }
    }
  }

  return { behavior: "ask", reason: "No matching rule found" }
}
