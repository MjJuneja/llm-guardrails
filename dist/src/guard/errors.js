"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DPDPBlockedError = void 0;
/**
 * Thrown by the guardrails pipeline when `dpdpEnforce` is enabled and a
 * DPDP-relevant detector (Indian PII or a child signal) blocks a request.
 *
 * Only thrown under `dpdpEnforce`. Without it, the same detections are handled
 * softly (Indian PII redacted, child signals flagged) and `run()` resolves
 * normally with `blocked` set on the result.
 */
class DPDPBlockedError extends Error {
    /** The pipeline stage that was blocked. */
    phase;
    /** The detector that caused the block (`indianPii` or `childSignal`). */
    detector;
    /** The offending matches (raw — do not log without considering redaction). */
    matches;
    constructor(phase, detector, matches) {
        super(`DPDP enforcement blocked the ${phase} stage: ${detector} detected ` +
            `${matches.length} item(s).`);
        this.name = "DPDPBlockedError";
        this.phase = phase;
        this.detector = detector;
        this.matches = matches;
        Object.setPrototypeOf(this, DPDPBlockedError.prototype);
    }
}
exports.DPDPBlockedError = DPDPBlockedError;
