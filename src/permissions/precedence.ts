import {
  PermissionBehavior,
  PermissionRule,
  PermissionRuleConflict,
  PermissionRuleSource,
  normalizePermissionRuleSource,
} from "./types"

const SOURCE_PRECEDENCE_TABLE: Record<PermissionRuleSource, number> = {
  policySettings: 1000,
  flagSettings: 950,
  localSettings: 900,
  projectSettings: 800,
  userSettings: 700,
  session: 600,
  command: 500,
  cliArg: 400,
  user: 700,
  project: 800,
  local: 900,
}

const BEHAVIOR_PRECEDENCE: Record<PermissionBehavior, number> = {
  deny: 300,
  ask: 200,
  allow: 100,
  passthrough: 0,
}

export function permissionSourcePrecedence(source: PermissionRuleSource): number {
  const normalized = normalizePermissionRuleSource(source)
  return SOURCE_PRECEDENCE_TABLE[normalized] || 0
}

export function sortRulesByPrecedence(rules: PermissionRule[]): PermissionRule[] {
  return [...rules].sort((left, right) => {
    const behaviorDelta =
      BEHAVIOR_PRECEDENCE[right.behavior] - BEHAVIOR_PRECEDENCE[left.behavior]
    if (behaviorDelta !== 0) return behaviorDelta

    const sourceDelta =
      permissionSourcePrecedence(right.source) -
      permissionSourcePrecedence(left.source)
    if (sourceDelta !== 0) return sourceDelta

    return left.id.localeCompare(right.id)
  })
}

export function conflictsForRule(
  winner: PermissionRule,
  matchingRules: PermissionRule[],
): PermissionRuleConflict[] {
  return matchingRules
    .filter(rule => rule.id !== winner.id)
    .map(rule => ({
      id: rule.id,
      source: normalizePermissionRuleSource(rule.source),
      behavior: rule.behavior,
      tool: rule.tool,
    }))
}
