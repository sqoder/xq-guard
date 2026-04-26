import { existsSync, mkdirSync, readFileSync } from "fs"
import { dirname, join } from "path"
import { PermissionRule, PermissionRuleSource } from "./types"

type PersistedPermissionRuleSource = Exclude<PermissionRuleSource, "cliArg">

export interface PermissionSettingsOptions {
  userSettingsPath?: string
  projectSettingsPath?: string
  localSettingsPath?: string
  sessionSettingsPath?: string
  cliArgRules?: Array<Omit<PermissionRule, "id"> | PermissionRule>
}

interface SettingsLayer {
  source: PermissionRuleSource
  path?: string
  rules: PermissionRule[]
}

const PERSISTED_SOURCES: PersistedPermissionRuleSource[] = [
  "user",
  "project",
  "local",
  "session",
]

function ruleWithId(
  rule: Omit<PermissionRule, "id"> | PermissionRule,
  source: PermissionRuleSource,
): PermissionRule {
  return {
    ...rule,
    id: "id" in rule ? rule.id : crypto.randomUUID(),
    source: rule.source || source,
  }
}

function readRulesFile(path: string, source: PermissionRuleSource): PermissionRule[] {
  if (!existsSync(path)) return []
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"))
    const rules: Array<Omit<PermissionRule, "id"> | PermissionRule> = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed?.rules)
        ? parsed.rules
        : []
    return rules.map((rule: Omit<PermissionRule, "id"> | PermissionRule) =>
      ruleWithId(rule, source),
    )
  } catch {
    return []
  }
}

function pathForSource(
  source: PersistedPermissionRuleSource,
  options: PermissionSettingsOptions,
): string | undefined {
  if (source === "user") return options.userSettingsPath
  if (source === "project") return options.projectSettingsPath
  if (source === "local") return options.localSettingsPath
  return options.sessionSettingsPath
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
        source: "cliArg" as const,
        rules: (settings.cliArgRules || []).map(rule => ruleWithId(rule, "cliArg")),
      },
    ]
  }

  getRules(): PermissionRule[] {
    return this.layers.flatMap(layer => layer.rules)
  }

  async saveRule(rule: Omit<PermissionRule, "id">): Promise<PermissionRule> {
    const source = rule.source
    const layer = this.layers.find(candidate => candidate.source === source)
    if (!layer) {
      throw new Error(`Unknown permission rule source: ${source}`)
    }

    const newRule = ruleWithId(rule, source)
    layer.rules.push(newRule)

    if (layer.path) {
      mkdirSync(dirname(layer.path), { recursive: true })
      await Bun.write(layer.path, JSON.stringify(layer.rules, null, 2))
    }

    return newRule
  }
}
