import { PermissionMode, PermissionRuleInput } from "./types"

export type PermissionUpdate =
  | {
      type: "addRule"
      rule: PermissionRuleInput
    }
  | {
      type: "replaceRule"
      ruleId: string
      rule: PermissionRuleInput
    }
  | {
      type: "removeRule"
      ruleId: string
    }
  | {
      type: "setMode"
      mode: PermissionMode
    }
  | {
      type: "addDirectories"
      paths: string[]
    }
  | {
      type: "removeDirectories"
      paths: string[]
    }

export function isPermissionUpdate(value: unknown): value is PermissionUpdate {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false
  }
  const record = value as Record<string, unknown>
  return typeof record.type === "string"
}
