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

function normalizePathLike(path: string): string {
  return path.replace(/\\/g, "/")
}

function pathSegments(path: string): string[] {
  return normalizePathLike(path).split("/").filter(Boolean)
}

function hasWindowsLongPathPrefix(path: string): boolean {
  return /^\\\\\?\\/.test(path) || /^\\\\\.\\/.test(path)
}

function hasNetworkOrProtocolPrefix(path: string): boolean {
  return path.startsWith("\\\\") || path.includes("://")
}

function hasAdsSegment(path: string): boolean {
  const segments = pathSegments(path)
  return segments.some((segment, index) => {
    if (!segment.includes(":")) return false
    // Allow Windows drive-letter roots like C: at the first segment.
    if (index === 0 && /^[a-zA-Z]:$/.test(segment)) {
      return false
    }
    return true
  })
}

function trailingDotOrSpace(segment: string): boolean {
  if (segment === "." || segment === "..") return false
  return /[ .]+$/.test(segment)
}

function isDosDeviceName(segment: string): boolean {
  const trimmed = segment.replace(/[ .]+$/g, "")
  const base = trimmed.split(".")[0]?.toLowerCase()
  if (!base) return false
  return /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/.test(base)
}

function hasWindowsShortNamePattern(segment: string): boolean {
  return /~\d+/.test(segment.toUpperCase())
}

function hasThreePlusDots(segment: string): boolean {
  return /\.{3,}/.test(segment)
}

export function detectPathSecurityRisk(path: string): string | null {
  if (hasWindowsLongPathPrefix(path)) {
    return "Windows long-path prefixes are forbidden"
  }

  if (hasNetworkOrProtocolPrefix(path)) {
    return "Network or protocol paths are forbidden"
  }

  if (path.startsWith("/dev/")) {
    return "Access to device files is forbidden"
  }

  if (hasAdsSegment(path)) {
    return "NTFS alternate data streams are forbidden"
  }

  const segments = pathSegments(path)
  for (const segment of segments) {
    if (trailingDotOrSpace(segment)) {
      return "Path segments with trailing dot or space are forbidden"
    }
    if (isDosDeviceName(segment)) {
      return "Reserved DOS device names are forbidden"
    }
    if (hasWindowsShortNamePattern(segment)) {
      return "Potential 8.3 short-name bypass is forbidden"
    }
    if (hasThreePlusDots(segment)) {
      return "Path segments containing three or more dots are forbidden"
    }
  }

  return null
}
