import { PermissionRule, PermissionDecision, ToolContext } from "./types"
import { resolve, isAbsolute, normalize } from "path"
import { statSync, existsSync, realpathSync, readFileSync } from "fs"
import { createHash } from "crypto"
import { ruleMatchesToolCall, isWriteOperation } from "./ruleMatcher"
import { assessBashCommand } from "./bashPermissions"
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

  async saveRule(rule: Omit<PermissionRule, "id">) {
    await this.settingsStore.saveRule(rule)
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

  private isPlanningReadOperation(toolName: string, input: string): boolean {
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

  async decide(
    toolName: string,
    input: string,
    ctx: ToolContext,
  ): Promise<PermissionDecision> {
    if (ctx.mode === "bypass") {
      return { behavior: "allow", reason: "Bypass mode" }
    }

    const matchingRules = this.settingsStore.getRules().filter(rule =>
      ruleMatchesToolCall(rule, toolName, input, ctx),
    )

    if (matchingRules.length > 0) {
      if (matchingRules.some(r => r.behavior === "deny")) {
        return { behavior: "deny", reason: "Matched a deny rule" }
      }
      if (
        (ctx.mode === "readOnly" || ctx.mode === "plan") &&
        isWriteOperation(toolName, input)
      ) {
        return {
          behavior: "deny",
          reason:
            ctx.mode === "plan"
              ? "Write operation forbidden in Plan mode"
              : "Write operation forbidden in ReadOnly mode",
        }
      }
      if (matchingRules.some(r => r.behavior === "ask")) {
        if (ctx.mode === "dontAsk" || ctx.mode === "plan") {
          return {
            behavior: "deny",
            reason:
              ctx.mode === "plan"
                ? "Plan mode does not prompt for ask rules"
                : "dontAsk mode does not prompt for ask rules",
          }
        }
        return { behavior: "ask", reason: "Matched an ask rule" }
      }
      return { behavior: "allow", reason: "Matched allow rule(s)" }
    }

    if (ctx.mode === "readOnly") {
      if (isWriteOperation(toolName, input)) {
        return {
          behavior: "deny",
          reason: "Write operation forbidden in ReadOnly mode",
        }
      }
      return { behavior: "allow", reason: "ReadOnly mode" }
    }

    if (ctx.mode === "plan") {
      if (isWriteOperation(toolName, input)) {
        return {
          behavior: "deny",
          reason: "Write operation forbidden in Plan mode",
        }
      }
      if (this.isPlanningReadOperation(toolName, input)) {
        return { behavior: "allow", reason: "Plan mode read operation" }
      }
      return {
        behavior: "deny",
        reason: "Plan mode requires an explicit rule for this tool",
      }
    }

    if (ctx.mode === "dontAsk") {
      return {
        behavior: "deny",
        reason: "dontAsk mode does not prompt for new permissions",
      }
    }

    if (ctx.mode === "acceptEdits") {
      if (toolName === "FileWrite" || toolName === "FileEdit") {
        return { behavior: "allow", reason: "AcceptEdits mode allows file edits" }
      }
    }

    return { behavior: "ask", reason: "No matching rule found" }
  }
}
