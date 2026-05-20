"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultInputPolicy = defaultInputPolicy;
exports.defaultOutputPolicy = defaultOutputPolicy;
function defaultInputPolicy(detections, cfg) {
    // secrets in input => BLOCK
    // pii in input => REDACT (unless allowlisted)
    // prompt injection patterns in input => ALLOW (we handle via system prompt + output filter)
    return detections.map((d) => {
        if (d.detector === "secrets" && cfg.redactSecrets) {
            return { ...d, action: "BLOCK", severity: "high" };
        }
        if (d.detector === "pii" && cfg.redactPII) {
            return { ...d, action: "REDACT", severity: "medium" };
        }
        if (d.detector === "indianPii" && cfg.redactPII) {
            const action = cfg.dpdpEnforce ? "BLOCK" : "REDACT";
            return { ...d, action, severity: "high" };
        }
        if (d.detector === "childSignal") {
            // Without enforcement a child signal only flags (event); with it, blocks.
            const action = cfg.dpdpEnforce ? "BLOCK" : "ALLOW";
            return { ...d, action, severity: "high" };
        }
        if (d.detector === "promptInjection" && cfg.blockPromptInjection) {
            return { ...d, action: "BLOCK", severity: "high" };
        }
        return d;
    });
}
function defaultOutputPolicy(detections, cfg) {
    return detections.map((d) => {
        if (d.detector === "sqlLeak" && cfg.blockSQLLeakage) {
            // better: rewrite once; if still leaking => block
            return { ...d, action: "REWRITE", severity: "high" };
        }
        if (d.detector === "promptLeak" && cfg.blockPromptLeakage) {
            return { ...d, action: "REWRITE", severity: "high" };
        }
        if (d.detector === "secrets" && cfg.redactSecrets) {
            return { ...d, action: "BLOCK", severity: "high" };
        }
        if (d.detector === "pii" && cfg.redactPII) {
            return { ...d, action: "REDACT", severity: "medium" };
        }
        if (d.detector === "indianPii" && cfg.redactPII) {
            const action = cfg.dpdpEnforce ? "BLOCK" : "REDACT";
            return { ...d, action, severity: "high" };
        }
        if (d.detector === "childSignal") {
            const action = cfg.dpdpEnforce ? "BLOCK" : "ALLOW";
            return { ...d, action, severity: "high" };
        }
        return d;
    });
}
