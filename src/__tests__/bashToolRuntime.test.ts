import { describe, expect, test } from "bun:test"
import { mkdtempSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import { BashTool } from "../tools"

describe("bash tool runtime controls", () => {
  test("does not expose non-allowlisted secret-like env vars", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "xq-guard-bash-"))
    const tool = new BashTool()
    const previous = process.env.XQ_GUARD_TEST_SECRET
    process.env.XQ_GUARD_TEST_SECRET = "super-secret-value"

    try {
      const result = await tool.run(
        { cmd: "echo \"$XQ_GUARD_TEST_SECRET\"" },
        { mode: "default", cwd, allowedPaths: [cwd], interactive: false },
      )
      expect(result.ok).toBe(true)
      expect(result.output).toBe("(No output)")
    } finally {
      if (previous === undefined) {
        delete process.env.XQ_GUARD_TEST_SECRET
      } else {
        process.env.XQ_GUARD_TEST_SECRET = previous
      }
    }
  })

  test("honors timeoutMs and terminates long-running commands", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "xq-guard-bash-"))
    const tool = new BashTool()

    const result = await tool.run(
      { cmd: "sleep 1", timeoutMs: 50 },
      { mode: "default", cwd, allowedPaths: [cwd], interactive: false },
    )

    expect(result.ok).toBe(false)
    expect(result.error).toContain("timed out")
  })

  test("uses a sanitized PATH instead of inheriting unsafe entries", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "xq-guard-bash-"))
    const tool = new BashTool()
    const previousPath = process.env.PATH
    process.env.PATH = `/tmp/xq-guard-evil:${previousPath || ""}`

    try {
      const result = await tool.run(
        { cmd: 'printf "%s" "$PATH"' },
        { mode: "default", cwd, allowedPaths: [cwd], interactive: false },
      )
      expect(result.ok).toBe(true)
      expect(result.output).not.toContain("/tmp/xq-guard-evil")
    } finally {
      if (previousPath === undefined) {
        delete process.env.PATH
      } else {
        process.env.PATH = previousPath
      }
    }
  })

  test("stops streamed output once the limit is reached", async () => {
    const tool = new BashTool()
    const encoder = new TextEncoder()
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("a".repeat(600_000)))
        controller.enqueue(encoder.encode("b".repeat(600_000)))
        controller.close()
      },
    })
    let collected = ""
    let stopped = false

    await (tool as any).readStreamWithLimit(
      stream,
      (chunk: string) => {
        const remaining = 1_000_000 - collected.length
        if (remaining <= 0) {
          return false
        }
        const next = chunk.length <= remaining ? chunk : chunk.slice(0, remaining)
        collected += next
        return next.length === chunk.length && collected.length < 1_000_000
      },
      () => {
        stopped = true
      },
    )

    expect(stopped).toBe(true)
    expect(collected.length).toBe(1_000_000)
    expect(collected).toContain("a".repeat(600_000))
  })

  test("kills background children when Bash times out", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "xq-guard-bash-"))
    const tool = new BashTool()
    const pidFile = join(cwd, "bg.pid")

    const result = await tool.run(
      {
        cmd: `sleep 30 & printf '%s' $! > ${JSON.stringify(pidFile)}`,
        timeoutMs: 100,
      },
      { mode: "default", cwd, allowedPaths: [cwd], interactive: false },
    )

    expect(result.ok).toBe(false)
    expect(result.error).toContain("timed out")

    const pidText = await Bun.file(pidFile).text()
    const pid = Number(pidText.trim())
    expect(pid).toBeGreaterThan(0)

    let alive = false
    for (let i = 0; i < 10; i += 1) {
      try {
        process.kill(pid, 0)
        alive = true
      } catch {
        alive = false
        break
      }
      await new Promise(resolve => setTimeout(resolve, 50))
    }

    expect(alive).toBe(false)
  })
})
