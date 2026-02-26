import type { GuardAction, Severity } from "../guard/types.js";

export type Detection = {
  detector: string;
  matches: string[];
  severity: Severity;
  // suggested default action by detector
  action: GuardAction;
};

export type PolicyDecision = {
  finalAction: GuardAction;
  reasons: Detection[];
};

// Simple "highest priority wins" policy:
// BLOCK > REWRITE > REDACT > ALLOW
const priority: Record<GuardAction, number> = {
  ALLOW: 0,
  REDACT: 1,
  REWRITE: 2,
  BLOCK: 3
};

export function decide(detections: Detection[]): PolicyDecision {
  if (detections.length === 0) return { finalAction: "ALLOW", reasons: [] };

  let final: GuardAction = "ALLOW";
  for (const d of detections) {
    if (priority[d.action] > priority[final]) final = d.action;
  }
  return { finalAction: final, reasons: detections };
}