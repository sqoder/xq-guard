import {
  ToolPermissionContext,
  PermissionDecision,
  ToolRunContext,
  ToolRunResult,
} from "./types"
import {
  resolve,
  relative,
  isAbsolute,
  dirname,
  basename,
  join,
  normalize,
} from "path"
import {
  realpathSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
} from "fs"
import { createHash } from "crypto"
import { bashPhysicalSafetyDecision } from "./bashPermissions"
import { detectPathSecurityRisk } from "./permissions/filesystem"

function isObjectInput(input: unknown): input is Record<string, unknown> {
  return typeof input === "object" && input !== null && !Array.isArray(input)
}

const BASH_DEFAULT_TIMEOUT_MS = 30_000
const BASH_MAX_TIMEOUT_MS = 120_000
const BASH_MAX_OUTPUT_CHARS = 1_000_000
const DEFAULT_READ_MAX_SIZE_BYTES = 10 * 1024 * 1024
const ABSOLUTE_READ_MAX_SIZE_BYTES = 32 * 1024 * 1024
const DEFAULT_READ_MAX_OUTPUT_CHARS = 200_000
const DEFAULT_WRITE_MAX_SIZE_BYTES = 2 * 1024 * 1024
const DEFAULT_EDIT_MAX_SIZE_BYTES = 2 * 1024 * 1024
const BINARY_SAMPLE_BYTES = 8192
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

const SECRET_WRITE_PATTERN =
  /(token|secret|password|api[_-]?key|private[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]/i

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

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex")
}

function normalizeTextLineEndings(text: string): string {
  return text.replace(/\r\n/g, "\n")
}

function splitLines(text: string): string[] {
  return normalizeTextLineEndings(text).split("\n")
}

function withLineNumbers(lines: string[], startLine: number): string {
  return lines
    .map((line, index) => `${startLine + index} | ${line}`)
    .join("\n")
}

function sampleLooksBinary(buffer: Buffer): boolean {
  if (buffer.length === 0) return false
  let suspicious = 0
  for (const value of buffer.values()) {
    if (value === 0) return true
    const isControl = value < 9 || (value > 13 && value < 32)
    if (isControl) suspicious += 1
  }
  return suspicious / buffer.length > 0.3
}

function levenshteinDistance(a: string, b: string): number {
  const rows = a.length + 1
  const cols = b.length + 1
  const matrix: number[][] = Array.from({ length: rows }, () =>
    Array.from({ length: cols }, () => 0),
  )

  for (let i = 0; i < rows; i += 1) matrix[i][0] = i
  for (let j = 0; j < cols; j += 1) matrix[0][j] = j

  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost,
      )
    }
  }

  return matrix[rows - 1][cols - 1]
}

function suggestSiblingPaths(path: string, cwd: string): string[] {
  const absolutePath = isAbsolute(path) ? path : resolve(cwd, path)
  const parent = dirname(absolutePath)
  if (!existsSync(parent)) return []

  const targetName = basename(path)
  const entries = readdirSync(parent)
  return entries
    .map(entry => ({
      entry,
      score: levenshteinDistance(targetName.toLowerCase(), entry.toLowerCase()),
    }))
    .sort((left, right) => left.score - right.score)
    .slice(0, 3)
    .map(item => join(parent, item.entry))
}

function truncateText(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value
  return `${value.slice(0, maxChars)}\n[truncated at ${maxChars} chars]`
}

function unifiedDiff(path: string, before: string, after: string): string {
  if (before === after) {
    return `--- ${path}\n+++ ${path}\n@@ unchanged @@`
  }
  const beforeLines = splitLines(before)
  const afterLines = splitLines(after)
  const maxLines = Math.max(beforeLines.length, afterLines.length)
  const body: string[] = [`--- ${path}`, `+++ ${path}`]
  for (let i = 0; i < maxLines; i += 1) {
    const left = beforeLines[i]
    const right = afterLines[i]
    if (left === right) {
      body.push(` ${left ?? ""}`)
      continue
    }
    if (left !== undefined) {
      body.push(`-${left}`)
    }
    if (right !== undefined) {
      body.push(`+${right}`)
    }
  }
  return body.join("\n")
}

export abstract class Tool {
  abstract name: string
  abstract validate(input: any): { ok: boolean; msg?: string }

  // 新的主权限入口。默认不附加工具级约束。
  async checkPermissions(
    input: any,
    ctx: ToolPermissionContext,
  ): Promise<PermissionDecision | null> {
    return null
  }

  // 旧的物理安全钩子，保留给老实现和直接调用方做兼容。
  async checkPhysicalSafety(
    input: any,
    ctx: ToolPermissionContext,
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
    ctx: ToolPermissionContext,
  ): PermissionDecision | null {
    try {
      const rawRisk = detectPathSecurityRisk(path)
      if (rawRisk) {
        return {
          behavior: "deny",
          reason: `${rawRisk}: ${path}`,
        }
      }
      const absolutePath = isAbsolute(path) ? path : resolve(ctx.cwd, path)
      const absoluteRisk = detectPathSecurityRisk(absolutePath)
      if (absoluteRisk) {
        return {
          behavior: "deny",
          reason: `${absoluteRisk}: ${absolutePath}`,
        }
      }
      const resolvedPath = this.resolveThroughExistingParent(absolutePath)
      const resolvedRisk = detectPathSecurityRisk(resolvedPath)
      if (resolvedRisk) {
        return {
          behavior: "deny",
          reason: `${resolvedRisk}: ${resolvedPath}`,
        }
      }
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

  abstract run(input: any, ctx: ToolRunContext): Promise<ToolRunResult>
}

export class FileReadTool extends Tool {
  name = "FileRead"
  private readHashCache = new Map<string, string>()

  validate(input: any) {
    if (!isObjectInput(input)) {
      return { ok: false, msg: "Input must be an object" }
    }
    if (typeof input.path !== "string" || input.path.length === 0) {
      return { ok: false, msg: "path must be a non-empty string" }
    }
    if (
      input.offset !== undefined &&
      (!Number.isInteger(input.offset) || input.offset < 0)
    ) {
      return { ok: false, msg: "offset must be a non-negative integer" }
    }
    if (
      input.limit !== undefined &&
      (!Number.isInteger(input.limit) || input.limit <= 0)
    ) {
      return { ok: false, msg: "limit must be a positive integer" }
    }
    if (
      input.maxSizeBytes !== undefined &&
      (!Number.isInteger(input.maxSizeBytes) || input.maxSizeBytes <= 0)
    ) {
      return { ok: false, msg: "maxSizeBytes must be a positive integer" }
    }
    if (
      input.maxOutputChars !== undefined &&
      (!Number.isInteger(input.maxOutputChars) || input.maxOutputChars <= 0)
    ) {
      return { ok: false, msg: "maxOutputChars must be a positive integer" }
    }
    return { ok: true }
  }

  async checkPermissions(
    input: { path: string },
    ctx: ToolPermissionContext,
  ): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx)
  }

  async run(
    input: {
      path: string
      offset?: number
      limit?: number
      maxSizeBytes?: number
      maxOutputChars?: number
      includeLineNumbers?: boolean
      allowUnchangedResult?: boolean
    },
    ctx: ToolRunContext,
  ): Promise<ToolRunResult> {
    try {
      const fullPath = isAbsolute(input.path)
        ? input.path
        : resolve(ctx.cwd, input.path)
      if (!existsSync(fullPath)) {
        const suggestions = suggestSiblingPaths(input.path, ctx.cwd)
        return {
          ok: false,
          output: "",
          error:
            suggestions.length > 0
              ? `File not found. Did you mean: ${suggestions.join(", ")}`
              : "File not found",
        }
      }

      const stats = statSync(fullPath)
      const maxSizeBytes = Math.min(
        input.maxSizeBytes || DEFAULT_READ_MAX_SIZE_BYTES,
        ABSOLUTE_READ_MAX_SIZE_BYTES,
      )
      if (stats.size > maxSizeBytes) {
        return {
          ok: false,
          output: "",
          error: `File size ${stats.size} exceeds maxSizeBytes ${maxSizeBytes}`,
        }
      }

      const buffer = readFileSync(fullPath)
      if (sampleLooksBinary(buffer.subarray(0, BINARY_SAMPLE_BYTES))) {
        return {
          ok: false,
          output: "",
          error: `Binary file rejected: ${input.path}`,
          data: { type: "binary_rejected", path: input.path },
        }
      }

      const text = buffer.toString("utf8")
      const hash = sha256Text(text)
      if (input.allowUnchangedResult && this.readHashCache.get(fullPath) === hash) {
        return {
          ok: true,
          output: "file_unchanged",
          data: {
            type: "file_unchanged",
            path: input.path,
          },
        }
      }

      this.readHashCache.set(fullPath, hash)
      const allLines = splitLines(text)
      const startLine = input.offset || 0
      const endLine =
        input.limit !== undefined
          ? Math.min(startLine + input.limit, allLines.length)
          : allLines.length
      const sliced = allLines.slice(startLine, endLine)
      const includeLineNumbers = input.includeLineNumbers !== false
      const formatted = includeLineNumbers
        ? withLineNumbers(sliced, startLine + 1)
        : sliced.join("\n")
      const maxOutputChars = input.maxOutputChars || DEFAULT_READ_MAX_OUTPUT_CHARS
      const content = truncateText(formatted, maxOutputChars)
      return {
        ok: true,
        output: content,
        data: {
          type: "text",
          path: input.path,
          startLine: startLine + 1,
          totalLines: allLines.length,
          content,
        },
      }
    } catch (e: any) {
      return { ok: false, output: "", error: `Error reading file: ${e.message}` }
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
    ctx: ToolPermissionContext,
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
    ctx: ToolRunContext,
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
    _ctx: ToolPermissionContext,
  ): Promise<PermissionDecision | null> {
    return null
  }

  async run(input: { url: string }, _ctx: ToolRunContext): Promise<ToolRunResult> {
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
    if (
      input.createParents !== undefined &&
      typeof input.createParents !== "boolean"
    ) {
      return { ok: false, msg: "createParents must be a boolean" }
    }
    if (input.content.length > DEFAULT_WRITE_MAX_SIZE_BYTES) {
      return {
        ok: false,
        msg: `content too large; max ${DEFAULT_WRITE_MAX_SIZE_BYTES} chars`,
      }
    }
    return { ok: true }
  }

  async checkPermissions(
    input: { path: string; content: string },
    ctx: ToolPermissionContext,
  ): Promise<PermissionDecision | null> {
    const escaped = this.isPathEscaped(input.path, ctx)
    if (escaped) return escaped
    if (SECRET_WRITE_PATTERN.test(input.content)) {
      return {
        behavior: "ask",
        reason: "Content appears to contain secrets and requires confirmation",
        reasonDetail: {
          type: "safetyCheck",
          reason: "Potential secret detected in write content",
          classifierApprovable: true,
        },
      }
    }
    return null
  }

  async run(
    input: { path: string; content: string; createParents?: boolean },
    ctx: ToolRunContext,
  ): Promise<ToolRunResult> {
    try {
      const fullPath = isAbsolute(input.path)
        ? input.path
        : resolve(ctx.cwd, input.path)
      const parent = dirname(fullPath)
      if (!existsSync(parent)) {
        if (!input.createParents) {
          return {
            ok: false,
            output: "",
            error: `Parent directory does not exist: ${parent}`,
          }
        }
        mkdirSync(parent, { recursive: true })
      }

      const existed = existsSync(fullPath)
      const originalContent = existed ? readFileSync(fullPath, "utf8") : null
      const hashBefore = originalContent !== null ? sha256Text(originalContent) : undefined
      const nextContent = input.content
      const diff = unifiedDiff(input.path, originalContent || "", nextContent)

      try {
        await Bun.write(fullPath, nextContent)
      } catch (writeError: any) {
        if (originalContent !== null) {
          try {
            await Bun.write(fullPath, originalContent)
          } catch {
            // best-effort rollback only
          }
        }
        throw writeError
      }

      const writtenContent = readFileSync(fullPath, "utf8")
      if (writtenContent !== nextContent) {
        if (originalContent !== null) {
          await Bun.write(fullPath, originalContent)
        }
        return {
          ok: false,
          output: "",
          error: "Write verification failed: content mismatch after write",
        }
      }

      const hashAfter = sha256Text(writtenContent)
      return {
        ok: true,
        output: "File written successfully",
        data: {
          type: existed ? "update" : "create",
          path: input.path,
          originalContent,
          newContent: writtenContent,
          diff,
          structuredPatch: diff,
          hashBefore,
          hashAfter,
        },
      }
    } catch (e: any) {
      return { ok: false, output: "", error: `Error writing file: ${e.message}` }
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
    if (input.replaceAll !== undefined && typeof input.replaceAll !== "boolean") {
      return { ok: false, msg: "replaceAll must be a boolean" }
    }
    if (input.oldString === input.newString)
      return { ok: false, msg: "oldString and newString are the same" }
    if (input.newString.length > DEFAULT_EDIT_MAX_SIZE_BYTES) {
      return {
        ok: false,
        msg: `newString too large; max ${DEFAULT_EDIT_MAX_SIZE_BYTES} chars`,
      }
    }
    return { ok: true }
  }

  async checkPermissions(
    input: { path: string; newString: string },
    ctx: ToolPermissionContext,
  ): Promise<PermissionDecision | null> {
    const escaped = this.isPathEscaped(input.path, ctx)
    if (escaped) return escaped
    if (SECRET_WRITE_PATTERN.test(input.newString)) {
      return {
        behavior: "ask",
        reason: "Replacement content appears to contain secrets and requires confirmation",
        reasonDetail: {
          type: "safetyCheck",
          reason: "Potential secret detected in edit replacement",
          classifierApprovable: true,
        },
      }
    }
    return null
  }

  async run(
    input: { path: string; oldString: string; newString: string; replaceAll?: boolean },
    ctx: ToolRunContext,
  ): Promise<ToolRunResult> {
    try {
      const fullPath = isAbsolute(input.path)
        ? input.path
        : resolve(ctx.cwd, input.path)
      const stats = statSync(fullPath)
      if (stats.size > DEFAULT_EDIT_MAX_SIZE_BYTES) {
        return {
          ok: false,
          output: "",
          error: `File size ${stats.size} exceeds editable limit ${DEFAULT_EDIT_MAX_SIZE_BYTES}`,
        }
      }

      const content = readFileSync(fullPath, "utf8")
      const matches = content.split(input.oldString).length - 1
      if (matches === 0) {
        return { ok: false, output: "", error: "Error: oldString not found in file" }
      }
      const replaceAll = input.replaceAll === true
      if (matches > 1 && !replaceAll) {
        return {
          ok: false,
          output: "",
          error:
            "Error: oldString matched multiple times; set replaceAll=true or provide more context",
        }
      }

      const newContent = replaceAll
        ? content.split(input.oldString).join(input.newString)
        : content.replace(input.oldString, input.newString)
      const hashBefore = sha256Text(content)
      const diff = unifiedDiff(input.path, content, newContent)

      try {
        await Bun.write(fullPath, newContent)
      } catch (writeError: any) {
        try {
          await Bun.write(fullPath, content)
        } catch {
          // best-effort rollback only
        }
        throw writeError
      }

      const writtenContent = readFileSync(fullPath, "utf8")
      if (writtenContent !== newContent) {
        await Bun.write(fullPath, content)
        return {
          ok: false,
          output: "",
          error: "Edit verification failed: content mismatch after write",
        }
      }

      const hashAfter = sha256Text(writtenContent)
      return {
        ok: true,
        output: "File edited successfully",
        data: {
          type: "update",
          path: input.path,
          originalContent: content,
          newContent: writtenContent,
          diff,
          structuredPatch: diff,
          hashBefore,
          hashAfter,
          replaceAll,
          replacedCount: matches,
        },
      }
    } catch (e: any) {
      return { ok: false, output: "", error: `Error editing file: ${e.message}` }
    }
  }
}
