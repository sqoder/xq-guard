import { PermissionRule, PermissionDecision, ToolContext } from "./types"
import { join, resolve, isAbsolute, normalize } from "path"
import { statSync, existsSync, realpathSync } from "fs"

export interface AuditLog {
  toolName: string
  input: string
  decision: PermissionDecision
  time: string
  result?: string
}

export class PermissionEngine {
  private rules: PermissionRule[] = []
  private rulesPath: string
  private fileStates: Map<string, number> = new Map()
  private auditLogs: AuditLog[] = []

  constructor(baseDir: string) {
    this.rulesPath = join(baseDir, "rules.json")
    this.loadRulesSync()
  }

  private loadRulesSync() {
    try {
      // Use dynamic import or require depending on environment, Bun supports both
      const file = require(this.rulesPath)
      this.rules = file
    } catch {
      this.rules = []
    }
  }

  async saveRule(rule: Omit<PermissionRule, "id">) {
    const newRule = { ...rule, id: crypto.randomUUID() }
    this.rules.push(newRule)
    await Bun.write(this.rulesPath, JSON.stringify(this.rules, null, 2))
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

  recordFileRead(path: string, ctx: ToolContext) {
    const canonical = this.canonicalPath(path, ctx)
    if (existsSync(canonical)) {
      const stats = statSync(canonical)
      this.fileStates.set(canonical, stats.mtimeMs)
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
    const lastReadMtime = this.fileStates.get(canonical)!
    if (Math.floor(stats.mtimeMs) > Math.floor(lastReadMtime)) {
      return {
        ok: false,
        reason: `File ${canonical} has been modified since it was last read`,
      }
    }
    return { ok: true }
  }

  logAudit(log: AuditLog) {
    this.auditLogs.push(log)
    const logPath = join(this.rulesPath, "../audit.log")
    Bun.write(logPath, JSON.stringify(this.auditLogs, null, 2)).catch(console.error)
  }

  async decide(
    toolName: string,
    input: string,
    ctx: ToolContext,
  ): Promise<PermissionDecision> {
    if (ctx.mode === "bypass") {
      return { behavior: "allow", reason: "Bypass mode" }
    }

    const matchingRules = this.rules.filter(rule => {
      if (!this.toolMatchesRule(rule.tool, toolName)) return false
      if (rule.pattern && !new RegExp(rule.pattern).test(input)) return false
      return true
    })

    if (matchingRules.length > 0) {
      if (matchingRules.some(r => r.behavior === "deny")) {
        return { behavior: "deny", reason: "Matched a deny rule" }
      }
      if (ctx.mode === "readOnly" && this.isWriteOperation(toolName, input)) {
        return {
          behavior: "deny",
          reason: "Write operation forbidden in ReadOnly mode",
        }
      }
      if (matchingRules.some(r => r.behavior === "ask")) {
        return { behavior: "ask", reason: "Matched an ask rule" }
      }
      return { behavior: "allow", reason: "Matched allow rule(s)" }
    }

    if (ctx.mode === "readOnly") {
      if (this.isWriteOperation(toolName, input)) {
        return {
          behavior: "deny",
          reason: "Write operation forbidden in ReadOnly mode",
        }
      }
      return { behavior: "allow", reason: "ReadOnly mode" }
    }

    if (ctx.mode === "acceptEdits") {
      if (toolName === "FileWrite" || toolName === "FileEdit") {
        return { behavior: "allow", reason: "AcceptEdits mode allows file edits" }
      }
    }

    return { behavior: "ask", reason: "No matching rule found" }
  }

  private toolMatchesRule(ruleTool: string, toolName: string): boolean {
    if (ruleTool === "*") return true
    if (ruleTool === toolName) return true
    // MCP server-level rule:
    // mcp__github__* matches mcp__github__search
    if (ruleTool.endsWith("__*")) {
      const prefix = ruleTool.slice(0, -1)
      return toolName.startsWith(prefix)
    }
    return false
  }

  private isWriteOperation(tool: string, input: string): boolean {
    if (["FileWrite", "FileEdit"].includes(tool)) return true
    if (tool === "Bash") {
      try {
        const parsed = JSON.parse(input)
        const cmd = parsed.cmd || ""
        const readOnlyPatterns = [
          /^\s*ls\b/,
          /^\s*pwd\b/,
          /^\s*cat\b/,
          /^\s*head\b/,
          /^\s*tail\b/,
          /^\s*grep\b/,
          /^\s*rg\b/,
          /^\s*find\b/,
          /^\s*git\s+(status|diff|log|show|branch)\b/,
        ]
        if (readOnlyPatterns.some(p => p.test(cmd))) {
          return false
        }
        return /\b(rm|mv|cp|chmod|chown|touch|mkdir|rmdir|tee)\b|>>|>|\bgit\s+(push|commit|reset|clean|rebase|merge|checkout)\b|\b(npm|yarn|bun|pnpm)\s+(install|add|remove|publish)\b/.test(cmd)
      } catch {
        return true
      }
    }
    return false
  }
}
