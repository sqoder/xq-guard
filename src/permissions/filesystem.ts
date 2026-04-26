import { existsSync, realpathSync } from "fs"
import { isAbsolute, normalize, relative, resolve } from "path"

export function canonicalizePermissionPath(path: string, cwd: string): string {
  const absolutePath = isAbsolute(path) ? path : resolve(cwd, path)
  if (!existsSync(absolutePath)) {
    return normalize(absolutePath)
  }

  try {
    return realpathSync(absolutePath)
  } catch {
    return normalize(absolutePath)
  }
}

export function isPathInside(child: string, parent: string): boolean {
  const rel = relative(parent, child)
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))
}
