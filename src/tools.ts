import { ToolContext, PermissionDecision, ToolRunResult } from "./types"
import {
  resolve,
  relative,
  isAbsolute,
  dirname,
  basename,
  join,
  normalize,
} from "path"
import { realpathSync, existsSync } from "fs"
import { bashPhysicalSafetyDecision } from "./bashPermissions"

function isObjectInput(input: unknown): input is Record<string, unknown> {
  return typeof input === "object" && input !== null && !Array.isArray(input)
}

const BASH_DEFAULT_TIMEOUT_MS = 30_000
const BASH_MAX_TIMEOUT_MS = 120_000
const BASH_MAX_OUTPUT_CHARS = 1_000_000
const BASH_ALLOWED_ENV_KEYS = [
  "HOME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "LOGNAME",
  "PATH",
  "SHELL",
  "TERM",
  "TMPDIR",
  "TZ",
  "USER",
]
const BASH_BLOCKED_ENV_PATTERN = /(token|secret|pass|password|key|credential|cookie|auth)/i
const BASH_SAFE_PATH_CANDIDATES = [
  "/usr/bin",
  "/bin",
  "/usr/sbin",
  "/sbin",
  "/opt/homebrew/bin",
  "/opt/homebrew/sbin",
  "/usr/local/bin",
  "/usr/local/sbin",
  process.env.HOME ? join(process.env.HOME, ".bun/bin") : "",
].filter(Boolean)

function uniquePaths(paths: string[]): string[] {
  return [...new Set(paths.filter(Boolean))]
}

function buildSafePath(): string {
  const current = (process.env.PATH || "").split(":").filter(Boolean)
  const safe = uniquePaths([
    ...current.filter(entry => BASH_SAFE_PATH_CANDIDATES.includes(entry)),
    ...BASH_SAFE_PATH_CANDIDATES,
  ])
  return safe.join(":")
}

export abstract class Tool {
  abstract name: string
  abstract validate(input: any): { ok: boolean; msg?: string }

  // 新的主权限入口。默认不附加工具级约束。
  async checkPermissions(
    input: any,
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return null
  }

  // 旧的物理安全钩子，保留给老实现和直接调用方做兼容。
  async checkPhysicalSafety(
    input: any,
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return this.checkPermissions(input, ctx)
  }

  protected resolveThroughExistingParent(targetPath: string): string {
    let current = targetPath
    const missingParts: string[] = []
    while (!existsSync(current)) {
      const parent = dirname(current)
      if (parent === current) {
        break
      }
      missingParts.unshift(basename(current))
      current = parent
    }
    const base = existsSync(current) ? realpathSync(current) : current
    return normalize(join(base, ...missingParts))
  }

  protected isInsidePath(child: string, parent: string): boolean {
    const rel = relative(parent, child)
    return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))
  }

  protected isPathEscaped(
    path: string,
    ctx: ToolContext,
  ): PermissionDecision | null {
    try {
      if (path.startsWith("\\\\") || path.includes("://")) {
        return {
          behavior: "deny",
          reason: `Network or protocol paths are forbidden: ${path}`,
        }
      }
      if (path.startsWith("/dev/")) {
        return {
          behavior: "deny",
          reason: `Access to device files is forbidden: ${path}`,
        }
      }
      const absolutePath = isAbsolute(path) ? path : resolve(ctx.cwd, path)
      const resolvedPath = this.resolveThroughExistingParent(absolutePath)
      const allowedRoots =
        ctx.allowedPaths.length > 0 ? ctx.allowedPaths : [ctx.cwd]
      const resolvedAllowedRoots = allowedRoots.map(root => {
        const absoluteRoot = isAbsolute(root) ? root : resolve(ctx.cwd, root)
        return existsSync(absoluteRoot)
          ? realpathSync(absoluteRoot)
          : normalize(absoluteRoot)
      })
      const insideAllowedRoot = resolvedAllowedRoots.some(root =>
        this.isInsidePath(resolvedPath, root),
      )
      if (!insideAllowedRoot) {
        return {
          behavior: "deny",
          reason: `Path ${resolvedPath} escapes allowed paths`,
        }
      }
      const lower = resolvedPath.toLowerCase()
      const segments = lower.split(/[\\/]+/)
      const fileName = segments.at(-1) || ""
      const forbiddenDirs = [
        ".claude",
        ".git",
        ".idea",
        ".ssh",
        ".vscode",
        "node_modules",
      ]
      const forbiddenFiles = [
        ".env",
        ".bash_profile",
        ".bashrc",
        ".claude.json",
        ".gitconfig",
        ".gitmodules",
        ".mcp.json",
        ".npmrc",
        ".profile",
        ".ripgreprc",
        ".zprofile",
        ".zshrc",
      ]
      if (segments.some(seg => forbiddenDirs.includes(seg))) {
        return {
          behavior: "deny",
          reason: `Access to sensitive directory is forbidden: ${resolvedPath}`,
        }
      }
      if (forbiddenFiles.includes(fileName) || fileName.startsWith(".env.")) {
        return {
          behavior: "deny",
          reason: `Access to sensitive file is forbidden: ${resolvedPath}`,
        }
      }
      return null
    } catch (e: any) {
      return {
        behavior: "deny",
        reason: `Security check error: ${e.message}`,
      }
    }
  }

  abstract run(input: any, ctx: ToolContext): Promise<ToolRunResult>
}

export class FileReadTool extends Tool {
  name = "FileRead"
  validate(input: any) {
    if (!isObjectInput(input)) {
      return { ok: false, msg: "Input must be an object" }
    }
    if (typeof input.path !== "string" || input.path.length === 0) {
      return { ok: false, msg: "path must be a non-empty string" }
    }
    return { ok: true }
  }

  async checkPermissions(
    input: { path: string },
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx)
  }

  async run(input: { path: string }, ctx: ToolContext): Promise<ToolRunResult> {
    try {
      const fullPath = isAbsolute(input.path)
        ? input.path
        : resolve(ctx.cwd, input.path)
      const file = Bun.file(fullPath)
      if (await file.exists()) {
        return { ok: true, output: await file.text() }
      }
      return { ok: false, output: "", error: "File not found" };
    } catch (e: any) {
      return { ok: false, output: "", error: `Error reading file: ${e.message}` };
    }
  }
}

export class BashTool extends Tool {
  name = "Bash"
  validate(input: any) {
    if (!isObjectInput(input)) {
      return { ok: false, msg: "Input must be an object" }
    }
    if (typeof input.cmd !== "string" || input.cmd.length === 0) {
      return { ok: false, msg: "cmd must be a non-empty string" }
    }
    if (
      input.timeoutMs !== undefined &&
      (typeof input.timeoutMs !== "number" ||
        !Number.isFinite(input.timeoutMs) ||
        input.timeoutMs <= 0)
    ) {
      return { ok: false, msg: "timeoutMs must be a positive number" }
    }
    return { ok: true }
  }

  async checkPermissions(
    input: { cmd: string },
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return bashPhysicalSafetyDecision(input.cmd)
  }

  private buildSafeEnv(cwd: string): Record<string, string> {
    const env: Record<string, string> = {}
    for (const key of BASH_ALLOWED_ENV_KEYS) {
      const value = process.env[key]
      if (!value) continue
      if (BASH_BLOCKED_ENV_PATTERN.test(key)) continue
      env[key] = value
    }
    env.PATH = buildSafePath()
    env.PWD = cwd
    return env
  }

  private normalizeTimeout(timeoutMs?: number): number {
    if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs)) {
      return BASH_DEFAULT_TIMEOUT_MS
    }
    return Math.min(Math.max(Math.floor(timeoutMs), 1), BASH_MAX_TIMEOUT_MS)
  }

  private normalizeOutput(stdout: string, stderr: string): string {
    return [stdout, stderr].filter(Boolean).join("\n").trim()
  }

  private buildBashInvocation(cmd: string): string[] {
    const wrapper = [
      "eval \"$1\"",
      "status=$?",
      "wait || true",
      "exit \"$status\"",
    ].join("; ")
    return ["bash", "-lc", wrapper, "xq-guard", cmd]
  }

  private killProcessGroup(proc: Bun.Subprocess) {
    if (proc.pid > 0) {
      try {
        process.kill(-proc.pid, "SIGTERM")
        return
      } catch {
        // fall back to killing the direct shell process below
      }
    }
    try {
      proc.kill("SIGTERM")
    } catch {
      try {
        proc.kill()
      } catch {
        // ignore kill races once the process is gone
      }
    }
  }

  private async readStreamWithLimit(
    stream: ReadableStream<Uint8Array>,
    append: (chunk: string) => boolean,
    stop: () => void,
  ): Promise<void> {
    const reader = stream.getReader()
    const decoder = new TextDecoder()
    try {
      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        if (!value || value.length === 0) continue
        const chunk = decoder.decode(value, { stream: true })
        if (chunk && !append(chunk)) {
          stop()
          try {
            await reader.cancel()
          } catch {
            // ignore cancellation races after kill
          }
          break
        }
      }
      const flush = decoder.decode()
      if (flush) {
        append(flush)
      }
    } catch {
      // Ignore stream errors after process termination or cancellation.
    } finally {
      try {
        reader.releaseLock()
      } catch {
        // no-op
      }
    }
  }

  private truncateOutput(text: string): string {
    if (text.length <= BASH_MAX_OUTPUT_CHARS) {
      return text
    }
    return text.slice(0, BASH_MAX_OUTPUT_CHARS)
  }

  async run(
    input: { cmd: string; timeoutMs?: number },
    ctx: ToolContext,
  ): Promise<ToolRunResult> {
    try {
      const timeoutMs = this.normalizeTimeout(input.timeoutMs)
      const proc = Bun.spawn(this.buildBashInvocation(input.cmd), {
        cwd: ctx.cwd,
        env: this.buildSafeEnv(ctx.cwd),
        stdout: "pipe",
        stderr: "pipe",
        detached: true,
      })
      let terminalReason: "timeout" | "output" | null = null
      let outputLength = 0
      const stdoutParts: string[] = []
      const stderrParts: string[] = []
      const appendChunk = (parts: string[], chunk: string) => {
        if (terminalReason) return false
        const remaining = BASH_MAX_OUTPUT_CHARS - outputLength
        if (remaining <= 0) {
          terminalReason = "output"
          return false
        }
        const next = chunk.length <= remaining ? chunk : chunk.slice(0, remaining)
        parts.push(next)
        outputLength += next.length
        if (next.length < chunk.length || outputLength >= BASH_MAX_OUTPUT_CHARS) {
          terminalReason = "output"
          return false
        }
        return true
      }
      const stop = () => {
        if (terminalReason === null) {
          terminalReason = "timeout"
        }
        this.killProcessGroup(proc)
      }
      const timer = setTimeout(() => {
        stop()
      }, timeoutMs)

      let exitCode = 0
      try {
        await Promise.all([
          this.readStreamWithLimit(
            proc.stdout as ReadableStream<Uint8Array>,
            chunk => appendChunk(stdoutParts, chunk),
            stop,
          ),
          this.readStreamWithLimit(
            proc.stderr as ReadableStream<Uint8Array>,
            chunk => appendChunk(stderrParts, chunk),
            stop,
          ),
          proc.exited.then(code => {
            exitCode = code
          }),
        ])
      } finally {
        clearTimeout(timer)
      }

      const stdout = this.truncateOutput(stdoutParts.join(""))
      const stderr = this.truncateOutput(stderrParts.join(""))
      const output = this.normalizeOutput(stdout, stderr)
      if (terminalReason === "output") {
        return {
          ok: false,
          output: output || "(No output)",
          error: `Command output exceeded ${BASH_MAX_OUTPUT_CHARS} chars`,
        }
      }
      if (terminalReason === "timeout") {
        return {
          ok: false,
          output: output || "(No output)",
          error: `Command timed out after ${timeoutMs}ms`,
        }
      }
      if (exitCode !== 0) {
        return { 
            ok: false, 
            output: output, 
            error: output ? `Exit code ${exitCode}` : `Command failed with exit code ${exitCode}` 
        };
      }
      return { ok: true, output: output || "(No output)" };
    } catch (e: any) {
      return { ok: false, output: "", error: `Error running bash: ${e.message}` };
    }
  }
}

export class WebFetchTool extends Tool {
  name = "WebFetch"
  validate(input: any) {
    if (!isObjectInput(input)) {
      return { ok: false, msg: "Input must be an object" }
    }
    if (typeof input.url !== "string" || input.url.length === 0) {
      return { ok: false, msg: "url must be a non-empty string" }
    }
    try {
      const url = new URL(input.url)
      if (url.protocol !== "http:" && url.protocol !== "https:") {
        return { ok: false, msg: "url must be a valid http(s) URL" }
      }
    } catch {
      return { ok: false, msg: "url must be a valid http(s) URL" }
    }
    return { ok: true }
  }

  async checkPermissions(
    _input: { url: string },
    _ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return null
  }

  async run(input: { url: string }): Promise<ToolRunResult> {
    try {
      const response = await fetch(input.url)
      const text = await response.text()
      const output = text.length > 1_000_000
        ? `${text.slice(0, 1_000_000)}\n[truncated at 1000000 bytes]`
        : text
      if (!response.ok) {
        return {
          ok: false,
          output,
          error: `HTTP ${response.status} ${response.statusText}`,
        }
      }
      return { ok: true, output }
    } catch (e: any) {
      return { ok: false, output: "", error: `Error fetching URL: ${e.message}` }
    }
  }
}

export class FileWriteTool extends Tool {
  name = "FileWrite"
  validate(input: any) {
    if (!isObjectInput(input)) {
      return { ok: false, msg: "Input must be an object" }
    }
    if (typeof input.path !== "string" || input.path.length === 0) {
      return { ok: false, msg: "path must be a non-empty string" }
    }
    if (typeof input.content !== "string") {
      return { ok: false, msg: "content must be a string" }
    }
    return { ok: true }
  }

  async checkPermissions(
    input: { path: string },
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx)
  }

  async run(input: { path: string; content: string }, ctx: ToolContext): Promise<ToolRunResult> {
    try {
      const fullPath = isAbsolute(input.path)
        ? input.path
        : resolve(ctx.cwd, input.path)
      await Bun.write(fullPath, input.content)
      return { ok: true, output: "File written successfully" };
    } catch (e: any) {
      return { ok: false, output: "", error: `Error writing file: ${e.message}` };
    }
  }
}

export class FileEditTool extends Tool {
  name = "FileEdit"
  validate(input: any) {
    if (!isObjectInput(input)) {
      return { ok: false, msg: "Input must be an object" }
    }
    if (typeof input.path !== "string" || input.path.length === 0) {
      return { ok: false, msg: "path must be a non-empty string" }
    }
    if (typeof input.oldString !== "string" || input.oldString.length === 0)
      return { ok: false, msg: "oldString must be a non-empty string" }
    if (typeof input.newString !== "string")
      return { ok: false, msg: "newString must be a string" }
    if (input.oldString === input.newString)
      return { ok: false, msg: "oldString and newString are the same" }
    return { ok: true }
  }

  async checkPermissions(
    input: { path: string },
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx)
  }

  async run(
    input: { path: string; oldString: string; newString: string },
    ctx: ToolContext,
  ): Promise<ToolRunResult> {
    try {
      const fullPath = isAbsolute(input.path)
        ? input.path
        : resolve(ctx.cwd, input.path)
      const file = Bun.file(fullPath)
      const content = await file.text()
      const matches = content.split(input.oldString).length - 1
      if (matches === 0) {
        return { ok: false, output: "", error: "Error: oldString not found in file" };
      }
      if (matches > 1) {
        return { ok: false, output: "", error: "Error: oldString matched multiple times; provide more context" };
      }
      const newContent = content.replace(input.oldString, input.newString)
      await Bun.write(fullPath, newContent)
      return { ok: true, output: "File edited successfully" };
    } catch (e: any) {
      return { ok: false, output: "", error: `Error editing file: ${e.message}` };
    }
  }
}
