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
  kind:
    | "INPUT_REDACTED"
    | "INPUT_BLOCKED"
    | "OUTPUT_REDACTED"
    | "OUTPUT_BLOCKED"
    | "OUTPUT_REWRITE_ATTEMPT"
    | "OUTPUT_REWRITE_SUCCESS"
    | "OUTPUT_REWRITE_FAILED"
    | "OUTPUT_JSON_INVALID"
    | "TOOL_CALL_BLOCKED"
    | "TOOL_RESULT_REDACTED"
    // DPDP / India compliance
    | "CHILD_SIGNAL_DETECTED"
    | "DPDP_BLOCKED"
    | "CONSENT_RECORDED"
    | "EVIDENCE_RECORDED";
  detector: string;
  severity?: Severity;
  matches?: string[]; // ideally hashed when redactEventPayloads=true
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

export type OutputJsonValidatorResult =
  | { ok: true; value: any }
  | { ok: false; error: string };

export type OutputJsonValidator = (text: string) => OutputJsonValidatorResult;

export type ToolCall = {
  name: string;
  args: unknown;
};

export type ToolCallDecision =
  | { allowed: true; reason?: string }
  | { allowed: false; reason: string };

export type ToolPolicy = {
  // block tool entirely
  block?: boolean;

  // allow/deny rules for args (optional)
  validateCall?: (call: ToolCall) => ToolCallDecision;

  // output shaping
  maxChars?: number;
  maxRows?: number;

  // remove fields from array-of-objects results
  stripFields?: string[];

  // run guardrails output sanitization on tool result text
  sanitizeText?: boolean;
};

export type GuardrailsConfig = {
  // new vNext mode
  mode?: "full" | "input_only" | "output_only";

  // toggles
  redactPII?: boolean;
  redactSecrets?: boolean;
  blockSQLLeakage?: boolean;
  blockPromptLeakage?: boolean;

  // DPDP / India compliance
  // detectChildSignals: heuristically flag content involving minors (default false)
  detectChildSignals?: boolean;
  // dpdpEnforce: escalate Indian PII + child signals to a hard BLOCK and throw
  // DPDPBlockedError instead of redacting/flagging (default false)
  dpdpEnforce?: boolean;

  // behavior
  maxRewriteAttempts?: number; // default 1
  outputMode?: "text" | "json";
  systemGuardPrompt?: string;

  // for json mode
  outputJsonValidator?: OutputJsonValidator;

  // audit
  onEvent?: (e: GuardEvent) => void;
  emitOnAllow?: boolean; // if true, emits allow events (optional)
  redactEventPayloads?: boolean; // if true, hash matches in events
  requestIdFactory?: () => string;

  // allowlist patterns
  allowPatterns?: RegExp[];

  // PII detector options (your new pii.ts supports it)
  piiOptions?: Record<string, any>;

  // tool firewall
  toolPolicies?: Record<string, ToolPolicy>;

  // messages
  blockMessage?: string;
};

export type GuardrailsRunInput = {
  userMessage?: string; // not required for output_only
  context?: string;
  preMessages?: LLMMessage[];

  // For full/input_only mode
  llm?: LLMCaller;

  // For output_only mode (or full-mode fallback)
  output?: string;

  // Optional ids for tracing
  requestId?: string;
};

export type GuardrailsRunResult = {
  safeText: string;
  blocked: boolean;
  events: GuardEvent[];

  // optional debug: don’t log in prod
  rawModelText?: string;

  // diagnostics (helpful for internal use)
  inputDetections?: unknown;
  outputDetections?: unknown;

  // json mode convenience
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

  // vNext helpers
  validateInput(text: string, requestId?: string): ValidatePhaseResult;
  validateOutput(text: string, requestId?: string): ValidatePhaseResult;

  // tool firewall helpers
  validateToolCall(call: ToolCall, requestId?: string): ToolCallDecision;
  sanitizeToolResult(toolName: string, payload: unknown, requestId?: string): { payload: unknown; events: GuardEvent[] };

  // DPDP audit-trail helpers — emit a compliance event via onEvent and return it
  recordConsent(record: ConsentRecord): GuardEvent;
  recordEvidence(record: EvidenceRecord): GuardEvent;
};