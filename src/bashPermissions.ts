import { assessBashCommandRisk } from "./bash/riskClassifier"
import { PermissionDecision } from "./types"

export interface BashPermissionAssessment {
  isReadOnly: boolean
  requiresAsk: boolean
  reason?: string
  decision: "allow" | "ask" | "deny"
}

export function assessBashCommand(cmd: string): BashPermissionAssessment {
  const assessment = assessBashCommandRisk(cmd)
  return {
    isReadOnly: assessment.isReadOnly,
    requiresAsk: assessment.decision !== "allow",
    reason: assessment.reason,
    decision: assessment.decision,
  }
}

export function bashPhysicalSafetyDecision(cmd: string): PermissionDecision | null {
  const assessment = assessBashCommand(cmd)
  if (assessment.decision === "allow") {
    return null
  }

  return {
    behavior: assessment.decision === "deny" ? "deny" : "ask",
    reason: assessment.reason || `Command requires confirmation: ${cmd}`,
  }
}

export function isBashWriteOperation(cmd: string): boolean {
  const assessment = assessBashCommand(cmd)
  return assessment.decision !== "allow" || !assessment.isReadOnly
}
