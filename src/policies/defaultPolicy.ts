import type { Detection } from "./actions.js";
import type { GuardrailsConfig } from "../guard/types.js";

export function defaultInputPolicy(detections: Detection[], cfg: GuardrailsConfig) {
  // secrets in input => BLOCK
  // pii in input => REDACT (unless allowlisted)
  // prompt injection patterns in input => ALLOW (we handle via system prompt + output filter)
  return detections.map((d) => {
    if (d.detector === "secrets" && cfg.redactSecrets) {
      return { ...d, action: "BLOCK" as const, severity: "high" as const };
    }
    if (d.detector === "pii" && cfg.redactPII) {
      return { ...d, action: "REDACT" as const, severity: "medium" as const };
    }
    return d;
  });
}

export function defaultOutputPolicy(detections: Detection[], cfg: GuardrailsConfig) {
  return detections.map((d) => {
    if (d.detector === "sqlLeak" && cfg.blockSQLLeakage) {
      // better: rewrite once; if still leaking => block
      return { ...d, action: "REWRITE" as const, severity: "high" as const };
    }
    if (d.detector === "promptLeak" && cfg.blockPromptLeakage) {
      return { ...d, action: "REWRITE" as const, severity: "high" as const };
    }
    if (d.detector === "secrets" && cfg.redactSecrets) {
      return { ...d, action: "BLOCK" as const, severity: "high" as const };
    }
    if (d.detector === "pii" && cfg.redactPII) {
      return { ...d, action: "REDACT" as const, severity: "medium" as const };
    }
    return d;
  });
}