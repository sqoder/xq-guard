import {
  PermissionUpdate,
  PermissionUpdateInput,
  PermissionRuleSource,
  ToolPermissionContext,
  ToolRunContext,
  normalizePermissionMode,
  PermissionRule,
  PermissionRuleInput,
  PermissionDecision,
  ToolContext,
} from "./types"
import { resolve, isAbsolute, normalize } from "path"
import { statSync, existsSync, realpathSync, readFileSync } from "fs"
import { createHash } from "crypto"
import { hasPermissionsToUseTool } from "./permissions/hasPermissionsToUseTool"
import {
  PermissionSettingsOptions,
  PermissionSettingsStore,
} from "./settingsStore"

export interface AuditLog {
  toolName: string
  input: string
  decision: PermissionDecision
  time: string
  result?: string
}

type FileState = {
  mtimeMs: number
  size: number
  hash: string
}

export interface PermissionEngineOptions {
  baseDir: string
  settings?: PermissionSettingsOptions
}

export class PermissionEngine {
  private settingsStore: PermissionSettingsStore
  private fileStates: Map<string, FileState> = new Map()
  private auditLogs: AuditLog[] = []

  constructor(options: string | PermissionEngineOptions) {
    const baseDir = typeof options === "string" ? options : options.baseDir
    const settings = typeof options === "string" ? undefined : options.settings
    this.settingsStore = new PermissionSettingsStore(baseDir, settings)
  }

  async saveRule(rule: PermissionRuleInput | PermissionRule) {
    return this.settingsStore.saveRule(rule)
  }

  async applyPermissionUpdate(update: PermissionUpdateInput): Promise<PermissionUpdate> {
    return this.settingsStore.applyPermissionUpdate(update)
  }

  async applyPermissionUpdates(
    updates: PermissionUpdateInput[],
  ): Promise<PermissionUpdate[]> {
    return this.settingsStore.applyPermissionUpdates(updates)
  }

  resolveContext(ctx: ToolContext): ToolContext {
    const layeredMode = this.settingsStore.getMode()
    const mergedAllowedPaths = [
      ...(ctx.allowedPaths || []),
      ...this.settingsStore.getDirectories(),
    ]
    const ruleBuckets = this.settingsStore.getRuleStringBucketsByBehavior()
    const additionalWorkingDirectories = new Map<
      string,
      { path: string; source: PermissionRuleSource }
    >()
    for (const dir of this.settingsStore.getDirectories()) {
      additionalWorkingDirectories.set(dir, {
        path: dir,
        source: "session",
      })
    }
    if (ctx.additionalWorkingDirectories) {
      for (const [key, value] of ctx.additionalWorkingDirectories.entries()) {
        additionalWorkingDirectories.set(key, value)
      }
    }

    const normalizedMode =
      ctx.mode === "default"
        ? normalizePermissionMode(layeredMode)
        : normalizePermissionMode(ctx.mode)

    return {
      ...ctx,
      mode: normalizedMode,
      allowedPaths: [...new Set(mergedAllowedPaths.filter(Boolean))],
      additionalWorkingDirectories,
      alwaysAllowRules: ctx.alwaysAllowRules || ruleBuckets.alwaysAllowRules,
      alwaysDenyRules: ctx.alwaysDenyRules || ruleBuckets.alwaysDenyRules,
      alwaysAskRules: ctx.alwaysAskRules || ruleBuckets.alwaysAskRules,
      shouldAvoidPermissionPrompts:
        typeof ctx.shouldAvoidPermissionPrompts === "boolean"
          ? ctx.shouldAvoidPermissionPrompts
          : normalizedMode === "dontAsk" || ctx.interactive === false,
      isBypassPermissionsModeAvailable:
        typeof ctx.isBypassPermissionsModeAvailable === "boolean"
          ? ctx.isBypassPermissionsModeAvailable
          : true,
    }
  }

  resolvePermissionContext(ctx: ToolContext): ToolPermissionContext {
    return this.resolveContext(ctx)
  }

  resolveRunContext(ctx: ToolContext): ToolRunContext {
    return {
      cwd: ctx.cwd,
      env: ctx.env,
    }
  }

  private canonicalPath(path: string, ctx: ToolContext): string {
    const absolutePath = isAbsolute(path) ? path : resolve(ctx.cwd, path)
    try {
      if (existsSync(absolutePath)) {
        return realpathSync(absolutePath)
      }
    } catch {
      // ignore and fallback
    }
    return normalize(absolutePath)
  }

  private fileHash(path: string): string {
    const buf = readFileSync(path)
    return createHash("sha256").update(buf).digest("hex")
  }

  recordFileRead(path: string, ctx: ToolContext) {
    const canonical = this.canonicalPath(path, ctx)
    if (existsSync(canonical)) {
      const stats = statSync(canonical)
      this.fileStates.set(canonical, {
        mtimeMs: stats.mtimeMs,
        size: stats.size,
        hash: this.fileHash(canonical),
      })
    }
  }

  checkWriteSafety(
    path: string,
    ctx: ToolContext,
    options: { allowCreate?: boolean } = {},
  ): { ok: boolean; reason?: string } {
    const canonical = this.canonicalPath(path, ctx)
    if (!existsSync(canonical)) {
      if (options.allowCreate) {
        return { ok: true }
      }
      return {
        ok: false,
        reason: `File ${canonical} does not exist`,
      }
    }
    if (!this.fileStates.has(canonical)) {
      return {
        ok: false,
        reason: `File ${canonical} was not read before writing`,
      }
    }
    const stats = statSync(canonical)
    const current = {
      mtimeMs: stats.mtimeMs,
      size: stats.size,
      hash: this.fileHash(canonical),
    }
    const last = this.fileStates.get(canonical)!
    
    // 比较 mtimeMs, size 和 hash
    if (
      current.mtimeMs !== last.mtimeMs ||
      current.size !== last.size ||
      current.hash !== last.hash
    ) {
      return {
        ok: false,
        reason: `File ${canonical} has been modified since it was last read`,
      }
    }
    return { ok: true }
  }

  logAudit(log: AuditLog) {
    this.auditLogs.push(log)
    Bun.write(
      this.settingsStore.auditPath,
      JSON.stringify(this.auditLogs, null, 2),
    ).catch(console.error)
  }

  async decide(
    toolName: string,
    input: string,
    ctx: ToolContext,
  ): Promise<PermissionDecision> {
    const effectiveCtx = this.resolveContext(ctx)
    return hasPermissionsToUseTool(
      toolName,
      input,
      effectiveCtx,
      this.settingsStore.getRules(),
    )
  }
}
