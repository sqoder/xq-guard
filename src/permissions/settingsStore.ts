import { existsSync, mkdirSync, readFileSync } from "fs"
import { dirname, join } from "path"
import {
  PermissionRule,
  PermissionRuleInput,
  PermissionRuleSource,
  PermissionRuleValue,
  normalizePermissionRuleSource,
} from "./types"
import {
  normalizePermissionRule,
  serializePermissionRule,
} from "./permissionRuleParser"

type PersistedRuleSource = Exclude<PermissionRuleSource, "cliArg" | "command">

export interface PermissionSettingsOptions {
  userSettingsPath?: string
  projectSettingsPath?: string
  localSettingsPath?: string
  policySettingsPath?: string
  flagSettingsPath?: string
  sessionSettingsPath?: string
  cliArgRules?: Array<PermissionRuleInput | PermissionRule>
  commandRules?: Array<PermissionRuleInput | PermissionRule>
}

interface SettingsLayer {
  source: PermissionRuleSource
  path?: string
  rules: PermissionRule[]
}

const PERSISTED_SOURCES: PersistedRuleSource[] = [
  "policySettings",
  "flagSettings",
  "localSettings",
  "projectSettings",
  "userSettings",
  "session",
]

function pathForSource(
  source: PersistedRuleSource,
  options: PermissionSettingsOptions,
): string | undefined {
  switch (source) {
    case "policySettings":
      return options.policySettingsPath
    case "flagSettings":
      return options.flagSettingsPath
    case "localSettings":
      return options.localSettingsPath
    case "projectSettings":
      return options.projectSettingsPath
    case "userSettings":
      return options.userSettingsPath
    case "session":
      return options.sessionSettingsPath
  }
}

function readRulesFile(
  path: string,
  source: PermissionRuleSource,
): PermissionRule[] {
  if (!existsSync(path)) return []

  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"))
    const rules: Array<PermissionRuleInput | PermissionRule> = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed?.rules)
        ? parsed.rules
        : []
    return rules.map(rule =>
      normalizePermissionRule({
        ...rule,
        source: normalizePermissionRuleSource(
          (rule as PermissionRule).source || source,
        ),
      } as PermissionRuleInput | PermissionRule),
    )
  } catch {
    return []
  }
}

function toPersistedRules(rules: PermissionRule[]): PermissionRule[] {
  return rules.map(rule => serializePermissionRule(normalizePermissionRule(rule)))
}

export class PermissionSettingsStore {
  private layers: SettingsLayer[]
  readonly auditPath: string

  constructor(baseDir: string, options: PermissionSettingsOptions = {}) {
    this.auditPath = join(baseDir, "audit.log")
    const legacyPath = join(baseDir, "rules.json")
    const hasExplicitSettings = PERSISTED_SOURCES.some(source =>
      Boolean(pathForSource(source, options)),
    )
    const settings = hasExplicitSettings
      ? options
      : { ...options, userSettingsPath: legacyPath }

    this.layers = [
      ...PERSISTED_SOURCES.map(source => {
        const path = pathForSource(source, settings)
        return {
          source,
          path,
          rules: path ? readRulesFile(path, source) : [],
        }
      }),
      {
        source: "command",
        rules: (settings.commandRules || []).map(rule =>
          normalizePermissionRule(rule),
        ),
      },
      {
        source: "cliArg",
        rules: (settings.cliArgRules || []).map(rule =>
          normalizePermissionRule(rule),
        ),
      },
    ]
  }

  getRules(): PermissionRule[] {
    return this.layers.flatMap(layer => layer.rules)
  }

  async saveRule(rule: PermissionRuleInput | PermissionRule): Promise<PermissionRule> {
    const normalized = normalizePermissionRule(rule)
    const layer = this.layers.find(candidate => candidate.source === normalized.source)

    if (!layer) {
      throw new Error(`Unknown permission rule source: ${normalized.source}`)
    }

    const storedRule = serializePermissionRule(normalized)
    layer.rules.push(storedRule)

    if (layer.path) {
      mkdirSync(dirname(layer.path), { recursive: true })
      await Bun.write(layer.path, JSON.stringify(toPersistedRules(layer.rules), null, 2))
    }

    return storedRule
  }
}
