import { PermissionRule, PermissionDecision, ToolContext } from "./types";
import { join } from "path";
import { statSync, existsSync } from "fs";

export interface AuditLog {
  toolName: string;
  input: string;
  decision: PermissionDecision;
  time: string;
  result?: string;
}

export class PermissionEngine {
  private rules: PermissionRule[] = [];
  private rulesPath: string;
  private fileStates: Map<string, number> = new Map(); // path -> mtime
  private auditLogs: AuditLog[] = [];

  constructor(baseDir: string) {
    this.rulesPath = join(baseDir, "rules.json");
    this.loadRulesSync();
  }

  private loadRulesSync() {
    try {
      const file = require(this.rulesPath);
      this.rules = file;
    } catch (e) {
      this.rules = [];
    }
  }

  async saveRule(rule: Omit<PermissionRule, "id">) {
    const newRule = { ...rule, id: crypto.randomUUID() };
    this.rules.push(newRule);
    await Bun.write(this.rulesPath, JSON.stringify(this.rules, null, 2));
  }

  // 记录文件读取状态
  recordFileRead(path: string) {
    if (existsSync(path)) {
      const stats = statSync(path);
      this.fileStates.set(path, stats.mtimeMs);
    }
  }

  // 检查写操作是否安全 (必须先读，且内容未变)
  checkWriteSafety(path: string): { ok: boolean; reason?: string } {
    if (!this.fileStates.has(path)) {
      return { ok: false, reason: `File ${path} was not read before writing` };
    }
    
    if (existsSync(path)) {
      const stats = statSync(path);
      if (stats.mtimeMs !== this.fileStates.get(path)) {
        return { ok: false, reason: `File ${path} has been modified since it was last read` };
      }
    }
    return { ok: true };
  }

  logAudit(log: AuditLog) {
    this.auditLogs.push(log);
    // 异步保存审计日志
    const logPath = join(this.rulesPath, '../audit.log');
    Bun.write(logPath, JSON.stringify(this.auditLogs, null, 2)).catch(console.error);
  }

  async decide(toolName: string, input: string, ctx: ToolContext): Promise<PermissionDecision> {
    if (ctx.mode === 'bypass') return { behavior: 'allow', reason: 'Bypass mode' };

    // 1. 物理安全检查已经在外部执行

    // 2. MCP Tool 权限处理
    if (toolName.startsWith('mcp__')) {
      const mcpDecision = this.checkMCPPermission(toolName, input);
      if (mcpDecision) return mcpDecision;
    }

    // 3. 查找匹配的规则
    const matchingRules = this.rules.filter(rule => {
      if (rule.tool !== '*' && rule.tool !== toolName) return false;
      if (rule.pattern && !new RegExp(rule.pattern).test(input)) return false;
      return true;
    });

    if (matchingRules.length > 0) {
      if (matchingRules.some(r => r.behavior === 'deny')) {
        return { behavior: 'deny', reason: 'Matched a deny rule' };
      }
      
      // 在 ReadOnly 模式下，即使有 allow 规则，如果是写操作也要拦截
      if (ctx.mode === 'readOnly' && this.isWriteOperation(toolName, input)) {
        return { behavior: 'deny', reason: 'Write operation forbidden in ReadOnly mode' };
      }

      if (matchingRules.some(r => r.behavior === 'ask')) {
        return { behavior: 'ask', reason: 'Matched an ask rule' };
      }
      return { behavior: 'allow', reason: 'Matched allow rule(s)' };
    }

    // 4. 模式限制逻辑 (无规则时的默认处理)
    if (ctx.mode === 'readOnly' && !this.isWriteOperation(toolName, input)) {
      return { behavior: 'allow', reason: 'ReadOnly mode' };
    }
    if (ctx.mode === 'readOnly' && this.isWriteOperation(toolName, input)) {
      return { behavior: 'deny', reason: 'Write operation forbidden in ReadOnly mode' };
    }

    return { behavior: 'ask', reason: 'No matching rule found' };
  }

  private checkMCPPermission(toolName: string, input: string): PermissionDecision | null {
    // 简单实现：检查是否有针对该 MCP server 的规则
    const parts = toolName.split('__');
    const serverName = parts[1];
    
    const serverRule = this.rules.find(r => r.tool === `mcp__${serverName}__*`);
    if (serverRule) {
      return { behavior: serverRule.behavior, reason: `Matched MCP server rule for ${serverName}` };
    }
    return null;
  }

  private isWriteOperation(tool: string, input: string) {
    if (['FileWrite', 'FileEdit'].includes(tool)) return true;
    if (tool === 'Bash') {
        try {
            const parsed = JSON.parse(input);
            const cmd = parsed.cmd || "";
            // 简单识别写命令
            return /\b(rm|mv|cp|chmod|chown|touch|mkdir|git|npm|yarn|bun|pnpm|tee|>>|>)\b/.test(cmd);
        } catch (e) {
            return true; // 解析失败默认视为危险
        }
    }
    return false;
  }
}
