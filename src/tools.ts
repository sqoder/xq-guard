import { ToolContext, PermissionDecision } from "./types"
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

export abstract class Tool {
  abstract name: string
  abstract validate(input: any): { ok: boolean; msg?: string }

  // 工具自带的硬性物理检查（如路径穿越检测）
  async checkPhysicalSafety(
    input: any,
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return null
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
      const forbiddenDirs = [".git", ".ssh", "node_modules"]
      const forbiddenFiles = [
        ".env",
        ".bashrc",
        ".zshrc",
        ".npmrc",
        ".gitconfig",
        ".gitmodules",
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

  abstract run(input: any, ctx: ToolContext): Promise<string>
}

export class FileReadTool extends Tool {
  name = "FileRead"
  validate(input: { path: string }) {
    return input.path ? { ok: true } : { ok: false, msg: "Missing path" }
  }

  async checkPhysicalSafety(
    input: { path: string },
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx)
  }

  async run(input: { path: string }, ctx: ToolContext) {
    try {
      const fullPath = isAbsolute(input.path)
        ? input.path
        : resolve(ctx.cwd, input.path)
      const file = Bun.file(fullPath)
      return (await file.exists()) ? await file.text() : "File not found"
    } catch (e: any) {
      return `Error reading file: ${e.message}`
    }
  }
}

export class BashTool extends Tool {
  name = "Bash"
  validate(input: { cmd: string }) {
    return input.cmd ? { ok: true } : { ok: false, msg: "Empty command" }
  }

  async checkPhysicalSafety(
    input: { cmd: string },
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    const cmd = input.cmd

    // 识别危险操作
    const dangerousPatterns = [
      /\brm\b/,
      /\bmv\b/,
      /\bchmod\b/,
      /\bchown\b/,
      /\bcurl\b/,
      /\bwget\b/,
      /\bgit push\b/,
      /\bnpm publish\b/,
      />/, // 重定向
      /\|/, // 管道
      /&&/, // 复合命令
      /;/ // 复合命令
    ]

    if (dangerousPatterns.some(p => p.test(cmd))) {
      return {
        behavior: "ask",
        reason: `Command contains potentially dangerous operations or complexity: ${cmd}`,
      }
    }

    return null
  }

  async run(input: { cmd: string }, ctx: ToolContext) {
    try {
      const proc = Bun.spawn(["bash", "-lc", input.cmd], {
        cwd: ctx.cwd,
        stdout: "pipe",
        stderr: "pipe",
      })
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ])
      const output = [stdout, stderr].filter(Boolean).join("\n").trim()
      if (exitCode !== 0) {
        return output
          ? `${output}\nExit code ${exitCode}`
          : `Exit code ${exitCode}`
      }
      return output || "(No output)"
    } catch (e: any) {
      return `Error running bash: ${e.message}`
    }
  }
}

export class FileWriteTool extends Tool {
  name = "FileWrite"
  validate(input: { path: string; content: string }) {
    return input.path && input.content !== undefined
      ? { ok: true }
      : { ok: false, msg: "Missing path or content" }
  }

  async checkPhysicalSafety(
    input: { path: string },
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx)
  }

  async run(input: { path: string; content: string }, ctx: ToolContext) {
    try {
      const fullPath = isAbsolute(input.path)
        ? input.path
        : resolve(ctx.cwd, input.path)
      await Bun.write(fullPath, input.content)
      return "File written successfully"
    } catch (e: any) {
      return `Error writing file: ${e.message}`
    }
  }
}

export class FileEditTool extends Tool {
  name = "FileEdit"
  validate(input: { path: string; oldString: string; newString: string }) {
    if (!input.path) return { ok: false, msg: "Missing path" }
    if (typeof input.oldString !== "string")
      return { ok: false, msg: "Missing oldString" }
    if (typeof input.newString !== "string")
      return { ok: false, msg: "Missing newString" }
    if (input.oldString === input.newString)
      return { ok: false, msg: "oldString and newString are the same" }
    return { ok: true }
  }

  async checkPhysicalSafety(
    input: { path: string },
    ctx: ToolContext,
  ): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx)
  }

  async run(
    input: { path: string; oldString: string; newString: string },
    ctx: ToolContext,
  ) {
    try {
      const fullPath = isAbsolute(input.path)
        ? input.path
        : resolve(ctx.cwd, input.path)
      const file = Bun.file(fullPath)
      const content = await file.text()
      const matches = content.split(input.oldString).length - 1
      if (matches === 0) {
        return "Error: oldString not found in file"
      }
      if (matches > 1) {
        return "Error: oldString matched multiple times; provide more context"
      }
      const newContent = content.replace(input.oldString, input.newString)
      await Bun.write(fullPath, newContent)
      return "File edited successfully"
    } catch (e: any) {
      return `Error editing file: ${e.message}`
    }
  }
}
