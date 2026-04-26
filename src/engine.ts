import { PermissionRule, PermissionDecision, ToolContext } from "./types";
import { join } from "path";

export class PermissionEngine {
  private rules: PermissionRule[] = [];
  private rulesPath: string;

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

  async decide(toolName: string, input: string, ctx: ToolContext): Promise<PermissionDecision> {
    if (ctx.mode === 'bypass') return { behavior: 'allow', reason: 'Bypass mode' };

    // 1. 查找匹配的规则 (后定义的规则优先覆盖)
    const sortedRules = [...this.rules].reverse(); 
    
    for (const rule of sortedRules) {
      if (rule.tool !== '*' && rule.tool !== toolName) continue;
      if (rule.pattern && !new RegExp(rule.pattern).test(input)) continue;

      return { behavior: rule.behavior, reason: `Matched ${rule.source} rule: ${rule.behavior}` };
    }

    // 2. 默认行为逻辑
    if (ctx.mode === 'readOnly' && !this.isWriteOperation(toolName)) {
      return { behavior: 'allow', reason: 'ReadOnly mode' };
    }

    return { behavior: 'ask', reason: 'No matching rule found' };
  }

  private isWriteOperation(tool: string) {
    return ['FileWrite', 'FileEdit', 'Bash'].includes(tool);
  }
}
