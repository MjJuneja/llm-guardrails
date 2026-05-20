import type { GuardPhase } from "./types.js";
/**
 * Thrown by the guardrails pipeline when `dpdpEnforce` is enabled and a
 * DPDP-relevant detector (Indian PII or a child signal) blocks a request.
 *
 * Only thrown under `dpdpEnforce`. Without it, the same detections are handled
 * softly (Indian PII redacted, child signals flagged) and `run()` resolves
 * normally with `blocked` set on the result.
 */
export declare class DPDPBlockedError extends Error {
    /** The pipeline stage that was blocked. */
    readonly phase: GuardPhase;
    /** The detector that caused the block (`indianPii` or `childSignal`). */
    readonly detector: string;
    /** The offending matches (raw — do not log without considering redaction). */
    readonly matches: string[];
    constructor(phase: GuardPhase, detector: string, matches: string[]);
}
