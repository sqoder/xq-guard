export type PermissionBehavior = 'allow' | 'ask' | 'deny' | 'passthrough';
export type PermissionMode = 'default' | 'acceptEdits' | 'bypass' | 'readOnly';

export interface PermissionRule {
  id: string;
  tool: string;       // 工具名或 '*' 或 'mcp__server__*'
  pattern?: string;   // 正则匹配输入内容
  behavior: 'allow' | 'deny' | 'ask';
  source: 'user' | 'project' | 'session';
}

export interface PermissionSuggestion {
  id: string;
  key: string;
  label: string;
  behavior: 'allow' | 'deny';
  rule?: Omit<PermissionRule, 'id'>;
}

export interface PermissionDecision {
  behavior: 'allow' | 'deny' | 'ask';
  reason: string;
  suggestions?: PermissionSuggestion[];
}

export interface ToolRunResult {
  ok: boolean;
  output: string;
  error?: string;
}

export interface GatewayExecuteResult {
  decision: PermissionDecision;
  result?: ToolRunResult;
}

export interface ToolContext {
  mode: PermissionMode;
  cwd: string;
  allowedPaths: string[];
  interactive?: boolean;
}
