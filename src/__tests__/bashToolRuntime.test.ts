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
})
