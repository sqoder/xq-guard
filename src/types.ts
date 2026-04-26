export type PermissionBehavior = 'allow' | 'ask' | 'deny' | 'passthrough';
export type PermissionMode = 'default' | 'acceptEdits' | 'bypass' | 'readOnly';

export interface PermissionRule {
  id: string;
  tool: string;       // 工具名或 '*'
  pattern?: string;   // 正则匹配输入内容
  behavior: 'allow' | 'deny' | 'ask';
  source: 'user' | 'project' | 'session';
}

export interface PermissionDecision {
  behavior: 'allow' | 'deny' | 'ask';
  reason: string;
}

export interface ToolContext {
  mode: PermissionMode;
  cwd: string;
  allowedPaths: string[];
}
