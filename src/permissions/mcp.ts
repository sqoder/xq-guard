const MCP_TOOL_PATTERN = /^mcp__([^_]+)__(.+)$/

export interface McpToolName {
  serverName: string
  toolName?: string
  isServerWildcard: boolean
}

export function parseMcpToolName(toolName: string): McpToolName | undefined {
  const match = MCP_TOOL_PATTERN.exec(toolName)
  if (!match) return undefined

  return {
    serverName: match[1],
    toolName: match[2] === "*" ? undefined : match[2],
    isServerWildcard: match[2] === "*",
  }
}

export function buildMcpServerRule(serverName: string): string {
  return `mcp__${serverName}__*`
}
