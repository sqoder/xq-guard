import { ToolContext, PermissionDecision } from "./types";
import { resolve } from "path";

export abstract class Tool {
  abstract name: string;
  abstract validate(input: any): { ok: boolean; msg?: string };
  
  // 工具自带的硬性物理检查（如路径穿越检测）
  async checkPhysicalSafety(input: any, ctx: ToolContext): Promise<PermissionDecision | null> {
    return null; 
  }

  abstract run(input: any): Promise<string>;
}

export class FileReadTool extends Tool {
  name = "FileRead";
  validate(input: { path: string }) {
    return input.path ? { ok: true } : { ok: false, msg: "Missing path" };
  }

  async checkPhysicalSafety(input: { path: string }, ctx: ToolContext): Promise<PermissionDecision | null> {
    const fullPath = resolve(ctx.cwd, input.path);
    // 简单的路径限制：只能访问当前目录下的文件
    if (!fullPath.startsWith(ctx.cwd)) {
      return { behavior: 'deny', reason: `Path ${fullPath} is outside sandbox (${ctx.cwd})!` };
    }
    return null;
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
