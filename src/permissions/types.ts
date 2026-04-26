export type PermissionBehavior = "allow" | "ask" | "deny" | "passthrough"

export type PermissionMode =
  | "default"
  | "acceptEdits"
  | "bypassPermissions"
  | "dontAsk"
  | "plan"
  | "auto"
  | "bubble"
  | "readOnly"
  | "bypass"

export type PermissionRuleSource =
  | "userSettings"
  | "projectSettings"
  | "localSettings"
  | "policySettings"
  | "flagSettings"
  | "cliArg"
  | "command"
  | "session"
  | "user"
  | "project"
  | "local"

export interface PermissionRuleValue {
  toolName: string
  ruleContent?: string
}

export interface PermissionRuleInput {
  toolName?: string
  ruleContent?: string
  tool?: string
  pattern?: string
  behavior: PermissionBehavior
  source: PermissionRuleSource
}

export interface PermissionRule extends PermissionRuleInput {
  id: string
  toolName: string
  source: PermissionRuleSource
  value: PermissionRuleValue
  tool: string
}

export interface PermissionSuggestion {
  id: string
  key: string
  label: string
  behavior: "allow" | "deny"
  rule?: PermissionRuleInput
}

export interface PermissionDecision {
  behavior: "allow" | "deny" | "ask"
  reason: string
  suggestions?: PermissionSuggestion[]
}

export interface ToolRunResult {
  ok: boolean
  output: string
  error?: string
}

export interface GatewayExecuteResult {
  decision: PermissionDecision
  result?: ToolRunResult
}

export interface ToolContext {
  mode: PermissionMode
  cwd: string
  allowedPaths: string[]
  interactive?: boolean
}

export const CANONICAL_PERMISSION_MODES: Exclude<PermissionMode, "bypass">[] = [
  "default",
  "acceptEdits",
  "bypassPermissions",
  "dontAsk",
  "plan",
  "auto",
  "bubble",
  "readOnly",
]

export const CANONICAL_PERMISSION_SOURCES: PermissionRuleSource[] = [
  "userSettings",
  "projectSettings",
  "localSettings",
  "policySettings",
  "flagSettings",
  "cliArg",
  "command",
  "session",
]

export function normalizePermissionMode(mode: PermissionMode | string): PermissionMode {
  if (mode === "bypass") return "bypassPermissions"
  if ((CANONICAL_PERMISSION_MODES as readonly string[]).includes(mode)) {
    return mode as PermissionMode
  }
  return "default"
}

export function normalizePermissionRuleSource(
  source: PermissionRuleSource | string,
): PermissionRuleSource {
  switch (source) {
    case "user":
      return "userSettings"
    case "project":
      return "projectSettings"
    case "local":
      return "localSettings"
    default:
      if ((CANONICAL_PERMISSION_SOURCES as readonly string[]).includes(source)) {
        return source as PermissionRuleSource
      }
      return "session"
  }
}

export function permissionRuleValueToString(value: PermissionRuleValue): string {
  return value.ruleContent
    ? `${value.toolName}(${value.ruleContent})`
    : value.toolName
}
