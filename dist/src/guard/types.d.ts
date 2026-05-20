export type Role = "system" | "developer" | "user" | "assistant";
export type LLMMessage = {
    role: Role;
    content: string;
};
export type LLMCaller = (messages: LLMMessage[]) => Promise<string>;
export type GuardAction = "ALLOW" | "REDACT" | "BLOCK" | "REWRITE";
export type GuardPhase = "input" | "output" | "tool" | "compliance";
export type Severity = "low" | "medium" | "high" | "critical";
export type GuardEvent = {
    ts: string;
    requestId: string;
    phase: GuardPhase;
    kind: "INPUT_REDACTED" | "INPUT_BLOCKED" | "OUTPUT_REDACTED" | "OUTPUT_BLOCKED" | "OUTPUT_REWRITE_ATTEMPT" | "OUTPUT_REWRITE_SUCCESS" | "OUTPUT_REWRITE_FAILED" | "OUTPUT_JSON_INVALID" | "TOOL_CALL_BLOCKED" | "TOOL_RESULT_REDACTED" | "CHILD_SIGNAL_DETECTED" | "DPDP_BLOCKED" | "CONSENT_RECORDED" | "EVIDENCE_RECORDED";
    detector: string;
    severity?: Severity;
    matches?: string[];
    meta?: Record<string, unknown>;
};
/**
 * A consent record for the DPDP audit trail. Logged via `recordConsent`.
 * `dataPrincipalId` is stored as-is in the event meta — pass a pseudonymous id
 * if you do not want raw identifiers in your logs.
 */
export type ConsentRecord = {
    dataPrincipalId: string;
    purpose: string;
    granted: boolean;
    noticeVersion?: string;
    meta?: Record<string, unknown>;
};
/** Evidence of a processing activity for the DPDP audit trail. */
export type EvidenceRecord = {
    action: string;
    purpose: string;
    dataPrincipalId?: string;
    meta?: Record<string, unknown>;
};
export type OutputJsonValidatorResult = {
    ok: true;
    value: any;
} | {
    ok: false;
    error: string;
};
export type OutputJsonValidator = (text: string) => OutputJsonValidatorResult;
export type ToolCall = {
    name: string;
    args: unknown;
};
export type ToolCallDecision = {
    allowed: true;
    reason?: string;
} | {
    allowed: false;
    reason: string;
};
export type ToolPolicy = {
    block?: boolean;
    validateCall?: (call: ToolCall) => ToolCallDecision;
    maxChars?: number;
    maxRows?: number;
    stripFields?: string[];
    sanitizeText?: boolean;
};
export type GuardrailsConfig = {
    mode?: "full" | "input_only" | "output_only";
    redactPII?: boolean;
    redactSecrets?: boolean;
    blockSQLLeakage?: boolean;
    blockPromptLeakage?: boolean;
    detectChildSignals?: boolean;
    dpdpEnforce?: boolean;
    maxRewriteAttempts?: number;
    outputMode?: "text" | "json";
    systemGuardPrompt?: string;
    outputJsonValidator?: OutputJsonValidator;
    onEvent?: (e: GuardEvent) => void;
    emitOnAllow?: boolean;
    redactEventPayloads?: boolean;
    requestIdFactory?: () => string;
    allowPatterns?: RegExp[];
    piiOptions?: Record<string, any>;
    toolPolicies?: Record<string, ToolPolicy>;
    blockMessage?: string;
};
export type GuardrailsRunInput = {
    userMessage?: string;
    context?: string;
    preMessages?: LLMMessage[];
    llm?: LLMCaller;
    output?: string;
    requestId?: string;
};
export type GuardrailsRunResult = {
    safeText: string;
    blocked: boolean;
    events: GuardEvent[];
    rawModelText?: string;
    inputDetections?: unknown;
    outputDetections?: unknown;
    json?: any;
};
export type ValidatePhaseResult = {
    ok: boolean;
    blocked: boolean;
    sanitizedText: string;
    events: GuardEvent[];
    detections?: unknown;
    json?: any;
};
export type Guardrails = {
    run(input: GuardrailsRunInput): Promise<GuardrailsRunResult>;
    validateInput(text: string, requestId?: string): ValidatePhaseResult;
    validateOutput(text: string, requestId?: string): ValidatePhaseResult;
    validateToolCall(call: ToolCall, requestId?: string): ToolCallDecision;
    sanitizeToolResult(toolName: string, payload: unknown, requestId?: string): {
        payload: unknown;
        events: GuardEvent[];
    };
    recordConsent(record: ConsentRecord): GuardEvent;
    recordEvidence(record: EvidenceRecord): GuardEvent;
};
