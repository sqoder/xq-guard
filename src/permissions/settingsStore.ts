import { existsSync, mkdirSync, readFileSync } from "fs"
import { dirname, join } from "path"
import {
  PermissionUpdate,
  PermissionUpdateInput,
  normalizePermissionUpdate,
} from "./permissionUpdate"
import {
  PermissionMode,
  PermissionRule,
  PermissionRuleInput,
  PermissionRuleSource,
  permissionRuleValueToString,
  normalizePermissionMode,
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
  statePath?: string
  initialMode?: PermissionMode
  initialDirectories?: string[]
}

interface SettingsLayer {
  source: PermissionRuleSource
  path?: string
  rules: PermissionRule[]
}

interface PermissionPersistedState {
  mode: PermissionMode
  directories: string[]
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

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))]
}

const DEFAULT_PERSISTED_STATE: PermissionPersistedState = {
  mode: "default",
  directories: [],
}

function readStateFile(path: string): PermissionPersistedState {
  if (!existsSync(path)) {
    return { ...DEFAULT_PERSISTED_STATE }
  }

  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"))
    const mode = normalizePermissionMode(parsed?.mode || "default")
    const directories = Array.isArray(parsed?.directories)
      ? uniqueStrings(
          parsed.directories.filter((entry: unknown) => typeof entry === "string"),
        )
      : []
    return {
      mode,
      directories,
    }
  } catch {
    return { ...DEFAULT_PERSISTED_STATE }
  }
}

export class PermissionSettingsStore {
  private layers: SettingsLayer[]
  private statePath?: string
  private state: PermissionPersistedState
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
    this.statePath = settings.statePath || join(baseDir, "permission-state.json")

    const loadedState = this.statePath
      ? readStateFile(this.statePath)
      : { ...DEFAULT_PERSISTED_STATE }
    this.state = {
      mode: normalizePermissionMode(settings.initialMode || loadedState.mode),
      directories: uniqueStrings([
        ...loadedState.directories,
        ...(settings.initialDirectories || []),
      ]),
    }

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

  getRulesBySource(): Record<PermissionRuleSource, PermissionRule[]> {
    const buckets: Record<PermissionRuleSource, PermissionRule[]> = {
      policySettings: [],
      flagSettings: [],
      localSettings: [],
      projectSettings: [],
      userSettings: [],
      session: [],
      command: [],
      cliArg: [],
      user: [],
      project: [],
      local: [],
    }

    for (const layer of this.layers) {
      for (const rule of layer.rules) {
        const source = normalizePermissionRuleSource(rule.source)
        if (!buckets[source]) {
          buckets[source] = []
        }
        buckets[source].push(rule)
      }
    }

    return buckets
  }

  getRuleStringBucketsByBehavior(): {
    alwaysAllowRules: Record<PermissionRuleSource, string[]>
    alwaysDenyRules: Record<PermissionRuleSource, string[]>
    alwaysAskRules: Record<PermissionRuleSource, string[]>
  } {
    const initBucket = (): Record<PermissionRuleSource, string[]> => ({
      policySettings: [],
      flagSettings: [],
      localSettings: [],
      projectSettings: [],
      userSettings: [],
      session: [],
      command: [],
      cliArg: [],
      user: [],
      project: [],
      local: [],
    })

    const alwaysAllowRules = initBucket()
    const alwaysDenyRules = initBucket()
    const alwaysAskRules = initBucket()

    for (const rule of this.getRules()) {
      const source = normalizePermissionRuleSource(rule.source)
      const serialized = permissionRuleValueToString(rule.value)
      if (rule.behavior === "allow") {
        alwaysAllowRules[source].push(serialized)
        continue
      }
      if (rule.behavior === "deny") {
        alwaysDenyRules[source].push(serialized)
        continue
      }
      if (rule.behavior === "ask") {
        alwaysAskRules[source].push(serialized)
      }
    }

    return {
      alwaysAllowRules,
      alwaysDenyRules,
      alwaysAskRules,
    }
  }

  getMode(): PermissionMode {
    return this.state.mode
  }

  getDirectories(): string[] {
    return [...this.state.directories]
  }

  private layerForSource(source: PermissionRuleSource): SettingsLayer {
    const layer = this.layers.find(candidate => candidate.source === source)
    if (!layer) {
      throw new Error(`Unknown permission rule source: ${source}`)
    }
    return layer
  }

  private async persistLayer(layer: SettingsLayer) {
    if (!layer.path) return
    mkdirSync(dirname(layer.path), { recursive: true })
    await Bun.write(layer.path, JSON.stringify(toPersistedRules(layer.rules), null, 2))
  }

  private async persistState() {
    if (!this.statePath) return
    mkdirSync(dirname(this.statePath), { recursive: true })
    await Bun.write(this.statePath, JSON.stringify(this.state, null, 2))
  }

  private async applyNormalizedUpdate(update: PermissionUpdate) {
    switch (update.type) {
      case "addRules": {
        const layer = this.layerForSource(update.destination)
        layer.rules.push(...update.rules.map(rule => serializePermissionRule(rule)))
        await this.persistLayer(layer)
        return
      }
      case "replaceRules": {
        const layer = this.layerForSource(update.destination)
        const byId = new Map(layer.rules.map(rule => [rule.id, rule]))
        for (const incoming of update.rules) {
          byId.set(incoming.id, serializePermissionRule(incoming))
        }
        layer.rules = [...byId.values()]
        await this.persistLayer(layer)
        return
      }
      case "removeRules": {
        const layer = this.layerForSource(update.destination)
        const removeIds = new Set(update.ruleIds)
        layer.rules = layer.rules.filter(rule => !removeIds.has(rule.id))
        await this.persistLayer(layer)
        return
      }
      case "setMode": {
        this.state.mode = normalizePermissionMode(update.mode)
        await this.persistState()
        return
      }
      case "addDirectories": {
        this.state.directories = uniqueStrings([
          ...this.state.directories,
          ...update.directories,
        ])
        await this.persistState()
        return
      }
      case "removeDirectories": {
        const toRemove = new Set(update.directories)
        this.state.directories = this.state.directories.filter(
          dir => !toRemove.has(dir),
        )
        await this.persistState()
      }
    }
  }

  async applyPermissionUpdate(
    update: PermissionUpdateInput,
  ): Promise<PermissionUpdate> {
    const normalized = normalizePermissionUpdate(update)
    await this.applyNormalizedUpdate(normalized)
    return normalized
  }

  async applyPermissionUpdates(
    updates: PermissionUpdateInput[],
  ): Promise<PermissionUpdate[]> {
    const normalizedUpdates: PermissionUpdate[] = []
    for (const update of updates) {
      const normalized = await this.applyPermissionUpdate(update)
      normalizedUpdates.push(normalized)
    }
    return normalizedUpdates
  }

  async saveRule(rule: PermissionRuleInput | PermissionRule): Promise<PermissionRule> {
    const normalized = normalizePermissionRule(rule)
    const storedRule = serializePermissionRule(normalized)
    await this.applyNormalizedUpdate({
      type: "addRules",
      destination: storedRule.source,
      rules: [storedRule],
    })
    return storedRule
  }
}
