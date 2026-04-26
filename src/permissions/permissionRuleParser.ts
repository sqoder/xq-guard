import { randomUUID } from "crypto"
import {
  PermissionBehavior,
  PermissionRule,
  PermissionRuleInput,
  PermissionRuleSource,
  PermissionRuleValue,
  normalizePermissionRuleSource,
  permissionRuleValueToString,
} from "./types"

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

export function parsePermissionRuleValue(spec: string): PermissionRuleValue {
  const open = spec.indexOf("(")
  if (open > 0 && spec.endsWith(")")) {
    return {
      toolName: spec.slice(0, open),
      ruleContent: spec.slice(open + 1, -1),
    }
  }
  return { toolName: spec }
}

function ruleValueFromInput(
  input: PermissionRuleInput | PermissionRule,
): PermissionRuleValue {
  if (isRecord((input as PermissionRule).value)) {
    const value = (input as PermissionRule).value
    if (typeof value.toolName === "string" && value.toolName.length > 0) {
      return {
        toolName: value.toolName,
        ruleContent:
          typeof value.ruleContent === "string" && value.ruleContent.length > 0
            ? value.ruleContent
            : undefined,
      }
    }
  }

  if (typeof input.toolName === "string" && input.toolName.length > 0) {
    return {
      toolName: input.toolName,
      ruleContent:
        typeof input.ruleContent === "string" && input.ruleContent.length > 0
          ? input.ruleContent
          : undefined,
    }
  }

  if (typeof input.tool === "string" && input.tool.length > 0) {
    const parsed = parsePermissionRuleValue(input.tool)
    return {
      toolName: parsed.toolName,
      ruleContent:
        typeof input.pattern === "string" && input.pattern.length > 0
          ? input.pattern
          : parsed.ruleContent,
    }
  }

  return { toolName: "*" }
}

export function normalizePermissionRule(
  input: PermissionRuleInput | PermissionRule,
): PermissionRule {
  const value = ruleValueFromInput(input)
  const source = normalizePermissionRuleSource(input.source)
  const tool = permissionRuleValueToString(value)

  return {
    ...(isRecord(input) ? input : {}),
    id: "id" in input && typeof input.id === "string" ? input.id : randomUUID(),
    behavior: input.behavior as PermissionBehavior,
    source,
    toolName: value.toolName,
    ruleContent: value.ruleContent,
    value,
    tool,
    pattern:
      typeof (input as PermissionRule).pattern === "string"
        ? (input as PermissionRule).pattern
        : undefined,
  }
}

export function serializePermissionRule(rule: PermissionRule): PermissionRule {
  return normalizePermissionRule(rule)
}

export function parsePermissionRuleSource(source: PermissionRuleSource | string) {
  return normalizePermissionRuleSource(source)
}
