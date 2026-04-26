# xq-guard

`xq-guard` is a permission gateway between an AI agent and host tools/filesystem.

It focuses on five core boundaries:
1. Permission management
2. File read
3. File write/edit
4. Permission confirmation
5. Security boundary enforcement

## Quick Start

Prerequisite: [Bun](https://bun.sh).

```bash
git clone https://github.com/sqoder/xq-guard.git
cd xq-guard
bun install
bun test
```

## Permission Model

Decision flow in `src/gateway.ts`:
1. Resolve tool (built-in/custom/MCP)
2. Validate input
3. Run tool-level `checkPermissions()`
4. Run policy engine decision (`src/permissions/hasPermissionsToUseTool.ts`)
5. Handle `ask` through pluggable permission handler (`permission.requested` / `permission.responded`)
6. Enforce write safety (`read-before-write`)
7. Execute tool
8. Update file-read state and audit log

Priority model:
- Explicit `deny` rule wins first.
- Tool safety deny/ask still applies even in bypass mode.
- `ask` rules are honored unless mode semantics deny prompts (`dontAsk`, `plan`).
- Allow rules only allow matching scope; unresolved actions still ask/deny by mode.

## Permission Modes

Supported modes:
- `default`
- `acceptEdits`
- `bypassPermissions` (legacy `bypass` normalized here)
- `dontAsk`
- `plan`
- `auto`
- `bubble`
- `readOnly`

`readOnly`/`plan` deny write operations. `dontAsk` denies unresolved asks. `bypassPermissions` does not bypass explicit deny or tool safety.

## Rule Syntax

Rules can use plain tool names or scoped `Tool(content)` syntax:
- `Bash(git status*)`
- `Bash(npm run:*)`
- `WebFetch(domain:example.com)`
- `FileRead(src/**)` / `Read(src/**)`
- `FileEdit(package.json)` / `Edit(package.json)`
- `mcp__github__*`
- `mcp__github__delete`

Rule sources/layers include:
- `policySettings`
- `flagSettings`
- `localSettings`
- `projectSettings`
- `userSettings`
- `session`
- `command`
- `cliArg`

## Permission Updates and Settings

`PermissionUpdate` is fully applied and persisted by `src/permissions/settingsStore.ts`:
- `addRules`
- `replaceRules`
- `removeRules`
- `setMode`
- `addDirectories`
- `removeDirectories`

Runtime context overlays mode/directories/rule buckets into `ToolPermissionContext`.

## File Read Permissions

`FileRead` supports:
- Path safety checks and allowed-root enforcement
- `offset` / `limit` line-range reads
- `includeLineNumbers`
- `maxSizeBytes` and output truncation (`maxOutputChars`)
- Binary-file rejection
- `file_unchanged` cache result mode
- Similar-path suggestions for missing files

## File Write/Edit Permissions

`FileWrite` and `FileEdit` enforce:
- Read-before-write safety (engine state + hash/mtime/size checks)
- Path/sensitive-file safety checks in `checkPermissions()`
- Secret-like content ask gate
- Structured output metadata (`create`/`update`, `diff`, `hashBefore`, `hashAfter`)
- Post-write verification and rollback-on-failure best effort
- `FileEdit.replaceAll` support with multi-match guard

## Permission Events

Permission confirmation is event-based:
- `permission.requested`
- `permission.responded`

Gateway accepts a pluggable `PermissionRequestHandler` (CLI/TUI/HTTP/headless).

## Security Boundaries

Filesystem/path protections include:
- CWD/allowed-roots escape prevention (realpath-aware)
- Sensitive directory/file denylist (`.git`, `.claude`, `.env`, shell/git configs, etc.)
- Network/protocol/UNC path block
- `/dev/*` block
- Cross-platform bypass checks:
  - NTFS ADS (`file.txt:stream`)
  - 8.3 short names (`GIT~1`)
  - Windows long-path/device prefixes (`\\?\`, `\\.\`)
  - DOS device names (`CON`, `NUL`, ...)
  - trailing dot/space segments
  - suspicious multi-dot segments

Bash protections include:
- Command risk classifier (`allow`/`ask`/`deny`)
- Remote script pipeline block (`curl|bash` style)
- Sensitive redirection target block
- Unknown-command default ask
- Runtime isolation: sanitized env/PATH, timeout, output cap, process-group kill
- Bash-derived write-path linkage to `FileWrite` permission + safety checks

## Test Matrix

`bun test` covers:
- Mode semantics (`plan`, `dontAsk`, `readOnly`, `bypassPermissions`)
- Deny precedence and rule-source layering
- Permission updates persistence/runtime effect
- Read-before-write and external-modification detection
- Path traversal/symlink/bypass pattern defense
- Bash risk classification + runtime guards
- MCP wildcard/specific/destructive behavior
- File tool size/binary/range/read-cache/diff/replaceAll behavior

## Architecture Map

- `src/gateway.ts`: execution and permission orchestration
- `src/engine.ts`: context overlay, decision entry, file-state safety, audit
- `src/tools.ts`: built-in tool implementations and tool-level checks
- `src/permissions/*`: rule parsing/matching/precedence/settings/MCP/filesystem
- `src/bash/*`: bash tokenize/split/redirection/classification/rule matching
- `src/permissionEvents.ts`: pluggable permission request handlers
- `src/toolRegistry.ts`: built-in/custom/MCP tool registration and metadata

## License

MIT © [sqoder](https://github.com/sqoder)
