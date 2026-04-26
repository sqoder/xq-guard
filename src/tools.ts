import { ToolContext, PermissionDecision } from "./types";
import { resolve, relative, isAbsolute } from "path";
import { realpathSync, existsSync } from "fs";

export abstract class Tool {
  abstract name: string;
  abstract validate(input: any): { ok: boolean; msg?: string };
  
  // 工具自带的硬性物理检查（如路径穿越检测）
  async checkPhysicalSafety(input: any, ctx: ToolContext): Promise<PermissionDecision | null> {
    return null; 
  }

  protected isPathEscaped(path: string, ctx: ToolContext): PermissionDecision | null {
    try {
      // 禁止 UNC 路径 (Windows) 或 协议路径
      if (path.startsWith('\\\\') || path.includes('://')) {
        return { behavior: 'deny', reason: `Network or protocol paths are forbidden: ${path}` };
      }

      // 禁止设备文件 (Linux/macOS)
      if (path.startsWith('/dev/')) {
        return { behavior: 'deny', reason: `Access to device files is forbidden: ${path}` };
      }

      const absolutePath = isAbsolute(path) ? path : resolve(ctx.cwd, path);
      
      // 处理符号链接
      let resolvedPath = absolutePath;
      if (existsSync(absolutePath)) {
        resolvedPath = realpathSync(absolutePath);
      }

      const rel = relative(ctx.cwd, resolvedPath);
      
      if (rel.startsWith('..') || isAbsolute(rel)) {
        return { behavior: 'deny', reason: `Path ${resolvedPath} escapes sandbox (${ctx.cwd})` };
      }

      // 禁用敏感路径
      const forbiddenPatterns = [
        /\.git($|\/)/,
        /\.ssh($|\/)/,
        /\.env/,
        /\.bashrc/,
        /\.zshrc/,
        /\.npmrc/,
        /node_modules/
      ];

      if (forbiddenPatterns.some(p => p.test(resolvedPath))) {
        return { behavior: 'deny', reason: `Access to sensitive path ${resolvedPath} is forbidden` };
      }

      return null;
    } catch (e: any) {
      return { behavior: 'deny', reason: `Security check error: ${e.message}` };
    }
  }

  abstract run(input: any): Promise<string>;
}

export class FileReadTool extends Tool {
  name = "FileRead";
  validate(input: { path: string }) {
    return input.path ? { ok: true } : { ok: false, msg: "Missing path" };
  }

  async checkPhysicalSafety(input: { path: string }, ctx: ToolContext): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx);
  }

  async run(input: { path: string }) {
    try {
      const file = Bun.file(input.path);
      return await file.exists() ? await file.text() : "File not found";
    } catch (e: any) {
      return `Error reading file: ${e.message}`;
    }
  }
}

export class BashTool extends Tool {
  name = "Bash";
  validate(input: { cmd: string }) {
    return input.cmd ? { ok: true } : { ok: false, msg: "Empty command" };
  }

  async checkPhysicalSafety(input: { cmd: string }, ctx: ToolContext): Promise<PermissionDecision | null> {
    const cmd = input.cmd;
    
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
      /;/  // 复合命令
    ];

    if (dangerousPatterns.some(p => p.test(cmd))) {
      return { behavior: 'ask', reason: `Command contains potentially dangerous operations or complexity: ${cmd}` };
    }

    return null;
  }

  async run(input: { cmd: string }) {
    try {
      const proc = Bun.spawn(input.cmd.split(" "));
      const text = await new Response(proc.stdout).text();
      return text || "(No output)";
    } catch (e: any) {
      return `Error running bash: ${e.message}`;
    }
  }
}

export class FileWriteTool extends Tool {
  name = "FileWrite";
  validate(input: { path: string, content: string }) {
    return input.path && input.content !== undefined ? { ok: true } : { ok: false, msg: "Missing path or content" };
  }

  async checkPhysicalSafety(input: { path: string }, ctx: ToolContext): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx);
  }

  async run(input: { path: string, content: string }) {
    try {
      await Bun.write(input.path, input.content);
      return "File written successfully";
    } catch (e: any) {
      return `Error writing file: ${e.message}`;
    }
  }
}

export class FileEditTool extends Tool {
  name = "FileEdit";
  validate(input: { path: string, oldString: string, newString: string }) {
    return input.path && input.oldString && input.newString ? { ok: true } : { ok: false, msg: "Missing required fields" };
  }

  async checkPhysicalSafety(input: { path: string }, ctx: ToolContext): Promise<PermissionDecision | null> {
    return this.isPathEscaped(input.path, ctx);
  }

  async run(input: { path: string, oldString: string, newString: string }) {
    try {
      const file = Bun.file(input.path);
      const content = await file.text();
      if (!content.includes(input.oldString)) {
        return "Error: oldString not found in file";
      }
      const newContent = content.replace(input.oldString, input.newString);
      await Bun.write(input.path, newContent);
      return "File edited successfully";
    } catch (e: any) {
      return `Error editing file: ${e.message}`;
    }
  }
}
