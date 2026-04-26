# xq-guard

**A permission gateway for AI agents, built with [Bun](https://bun.sh) and TypeScript.**

---

## 🌟 Overview

`xq-guard` is a strategic security layer designed to sit between an AI Agent and the host system. It implements a three-tier defense mechanism to ensure that agentic tool usage is safe, observable, and controllable.

### The Three Layers of Defense:
1. **Physical Sandbox Check**: Tool-level filesystem and shell safety checks run before policy decisions.
2. **Policy Engine**: Structured permission rules match tool names plus optional scoped content such as file globs, Bash prefixes, WebFetch domains, and MCP tool names.
3. **Human-in-the-Loop (HITL)**: An interactive CLI prompt can approve once, deny once, or persist durable rules when no existing policy matches.

---

## 🚀 Quick Start

### Prerequisites
- [Bun](https://bun.sh) installed on your system.

### Installation
```bash
git clone https://github.com/sqoder/xq-guard.git
cd xq-guard
bun install
```

### Run the Demo
```bash
bun start
```

---

## 🛠 Architecture

- **`src/gateway.ts`**: End-to-end execution flow for validation, tool-level permission checks, policy decisions, permission request events, read-before-write safety, execution, and audit logging.
- **`src/engine.ts`**: Permission-state coordination for rule persistence, audit logging, and read-before-write tracking.
- **`src/tools.ts`**: Built-in tool implementations with `checkPermissions()` and runtime safety checks for files, Bash, and network access.
- **`src/permissions/`**: Structured permission modules for types, modes, rule parsing, rule matching, settings layers, updates, filesystem helpers, MCP client integration, and the shared `hasPermissionsToUseTool()` policy core.
- **`src/bash/` + `src/bashPermissions.ts`**: Bash tokenizer/splitter/redirection/risk-classifier/rule-matcher modules with compatibility exports.
- **`src/toolRegistry.ts`**: Tool registry and metadata for built-ins, custom tools, and MCP tools.
- **`src/permissionSuggestions.ts`**: Generates reusable permission choices for tool, path, command-prefix, domain, and MCP server scopes.
- **`src/permissionEvents.ts`**: Event-oriented permission request handler helpers (CLI responder included for compatibility).
- **`src/index.ts`**: Package exports for the public API surface.

---

## 🔒 Security Features

- **ReadOnly Mode**: Switch the global context to `readOnly` to automatically allow safe operations (like `ls` or `cat`) while still blocking destructive ones.
- **Plan Mode**: Switch the global context to `plan` to allow read-only planning operations while denying writes and unresolved asks.
- **dontAsk Mode**: Switch the global context to `dontAsk` to auto-deny unresolved operations instead of prompting.
- **Bypass Mode**: Skips only unresolved default prompts. Explicit `deny` and `ask` rules still win, and tool-level safety checks still run before policy allow.
- **Tool Pattern Rules**: Allow or deny stable permission targets with `Tool(pattern)` rules while preserving legacy Regex patterns.
- **WebFetch Domain Rules**: Grant network access by domain with rules like `WebFetch(domain:docs.example.com)`.
- **Permission Events**: `permission.requested` / `permission.responded` events support CLI, TUI, HTTP, and headless agent integrations without coupling to stdin.
- **Sensitive Path Protection**: Blocks common agent, shell, Git, SSH, editor, and package-manager configuration paths before policy rules are evaluated.
- **Permission Suggestions**: Ask prompts can suggest one-time choices plus durable rules for exact file paths, Bash prefixes, WebFetch domains, and MCP servers.
- **Bash Compound Handling**: Simple read-only compound commands such as `git status && pwd` can pass read-only classification, while mutating segments, dynamic shell execution, and sensitive redirections require confirmation or are denied.
- **Bash Runtime Guardrails**: `Bash` execution supports `timeoutMs`, uses a minimal allowlisted environment, truncates oversized command output, and kills the full detached process group on timeout.
- **Layered Settings**: Rules can be loaded from user, project, local, session, and CLI-argument sources while preserving legacy `rules.json` compatibility.
- **MCP Client Manager**: Dynamically loads MCP tool schemas by server and dispatches real `callTool` invocations through a pluggable manager.

---

## 📝 License

MIT © [sqoder](https://github.com/sqoder)
