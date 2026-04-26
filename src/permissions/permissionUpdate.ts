import { normalizePermissionRule } from "./permissionRuleParser"
import {
  PermissionMode,
  PermissionRule,
  PermissionRuleInput,
  PermissionRuleSource,
  normalizePermissionMode,
  normalizePermissionRuleSource,
} from "./types"

export type PermissionRuleDestination = PermissionRuleSource

export type PermissionRuleBatchUpdate =
  | {
      type: "addRules"
      rules: PermissionRule[]
      destination: PermissionRuleDestination
    }
  | {
      type: "replaceRules"
      rules: PermissionRule[]
      destination: PermissionRuleDestination
    }
  | {
      type: "removeRules"
      ruleIds: string[]
      destination: PermissionRuleDestination
    }

export type PermissionModeUpdate = {
  type: "setMode"
  mode: PermissionMode
}

export type PermissionDirectoryUpdate =
  | {
      type: "addDirectories"
      directories: string[]
    }
  | {
      type: "removeDirectories"
      directories: string[]
    }

export type PermissionUpdate =
  | PermissionRuleBatchUpdate
  | PermissionModeUpdate
  | PermissionDirectoryUpdate

export type LegacyPermissionUpdate =
  | {
      type: "addRule"
      rule: PermissionRuleInput | PermissionRule
      destination?: PermissionRuleDestination
      source?: PermissionRuleSource
    }
  | {
      type: "replaceRule"
      ruleId: string
      rule: PermissionRuleInput | PermissionRule
      destination?: PermissionRuleDestination
      source?: PermissionRuleSource
    }
  | {
      type: "removeRule"
      ruleId: string
      destination?: PermissionRuleDestination
      source?: PermissionRuleSource
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

export type PermissionUpdateInput = PermissionUpdate | LegacyPermissionUpdate

const PERMISSION_UPDATE_TYPES = new Set([
  "addRules",
  "replaceRules",
  "removeRules",
  "setMode",
  "addDirectories",
  "removeDirectories",
  "addRule",
  "replaceRule",
  "removeRule",
])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(value => typeof value === "string" && value.length > 0))]
}

function normalizeRuleList(rules: Array<PermissionRuleInput | PermissionRule>): PermissionRule[] {
  return rules.map(rule => normalizePermissionRule(rule))
}

function resolveDestination(
  update: {
    destination?: PermissionRuleDestination
    source?: PermissionRuleSource
    rule?: PermissionRuleInput | PermissionRule
  },
  fallback: PermissionRuleDestination = "session",
): PermissionRuleDestination {
  if (typeof update.destination === "string") {
    return normalizePermissionRuleSource(update.destination)
  }

  if (typeof update.source === "string") {
    return normalizePermissionRuleSource(update.source)
  }

  if (update.rule && isRecord(update.rule) && typeof update.rule.source === "string") {
    return normalizePermissionRuleSource(update.rule.source)
  }

  return normalizePermissionRuleSource(fallback)
}

function normalizeDirectoryUpdate(
  update: { type: "addDirectories" | "removeDirectories"; directories?: string[]; paths?: string[] },
): PermissionDirectoryUpdate {
  return {
    type: update.type,
    directories: uniqueStrings(update.directories || update.paths || []),
  }
}

export function permissionUpdateFromRule(
  rule: PermissionRuleInput | PermissionRule,
  destination?: PermissionRuleDestination,
): PermissionRuleBatchUpdate {
  const normalizedRule = normalizePermissionRule(rule)
  return {
    type: "addRules",
    destination: normalizePermissionRuleSource(
      destination || normalizedRule.source || "session",
    ),
    rules: [normalizedRule],
  }
}

export function normalizePermissionUpdate(
  update: PermissionUpdateInput,
): PermissionUpdate {
  switch (update.type) {
    case "addRules":
      return {
        type: "addRules",
        destination: resolveDestination(update),
        rules: normalizeRuleList(update.rules),
      }
    case "replaceRules":
      return {
        type: "replaceRules",
        destination: resolveDestination(update),
        rules: normalizeRuleList(update.rules),
      }
    case "removeRules":
      return {
        type: "removeRules",
        destination: resolveDestination(update),
        ruleIds: uniqueStrings(update.ruleIds),
      }
    case "setMode":
      return {
        type: "setMode",
        mode: normalizePermissionMode(update.mode),
      }
    case "addDirectories":
    case "removeDirectories":
      return normalizeDirectoryUpdate(update)
    case "addRule":
      return permissionUpdateFromRule(update.rule, resolveDestination(update))
    case "replaceRule":
      return {
        type: "replaceRules",
        destination: resolveDestination(update),
        rules: normalizeRuleList([update.rule]),
      }
    case "removeRule":
      return {
        type: "removeRules",
        destination: resolveDestination(update),
        ruleIds: uniqueStrings([update.ruleId]),
      }
  }
}

export function normalizePermissionUpdates(
  updates: PermissionUpdateInput[],
): PermissionUpdate[] {
  return updates.map(update => normalizePermissionUpdate(update))
}

export function isPermissionUpdate(value: unknown): value is PermissionUpdateInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false
  }

  const record = value as Record<string, unknown>
  return typeof record.type === "string" && PERMISSION_UPDATE_TYPES.has(record.type)
}
