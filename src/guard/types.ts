export type Role = "system" | "developer" | "user" | "assistant";

export type LLMMessage = {
  role: Role;
  content: string;
};

export type LLMCaller = (messages: LLMMessage[]) => Promise<string>;

export type GuardAction = "ALLOW" | "REDACT" | "BLOCK" | "REWRITE";

export type GuardEvent = {
  ts: string;
  kind:
    | "INPUT_REDACTED"
    | "INPUT_BLOCKED"
    | "OUTPUT_REDACTED"
    | "OUTPUT_BLOCKED"
    | "OUTPUT_REWRITE_ATTEMPT"
    | "OUTPUT_REWRITE_SUCCESS"
    | "OUTPUT_REWRITE_FAILED";
  detector: string;
  matches?: string[];
  meta?: Record<string, unknown>;
};

export type GuardrailsConfig = {
  // toggles
  redactPII?: boolean;
  redactSecrets?: boolean;
  blockSQLLeakage?: boolean;
  blockPromptLeakage?: boolean;

  // behavior
  maxRewriteAttempts?: number; // default 1
  outputMode?: "text" | "json"; // v1 uses text; json mode just enforces "no leak tokens" stricter

  // optional: add your own system guard prompt
  systemGuardPrompt?: string;

  // audit hook
  onEvent?: (e: GuardEvent) => void;

  // allowlist patterns (advanced)
  allowPatterns?: RegExp[];

  //pii options
  piiOptions?: Record<string, any>;
  
  // for flow of the function
  checkInputOnly?: boolean; // if true, only check input and skip output checks (for future use)
  checkOutputOnly?: boolean; // if true, only check output and skip input checks (for future use)
};

export type GuardrailsRunInput = {
  userMessage: string;
  context?: string; // optional RAG context
  llm?: LLMCaller;
  // optional extra messages (e.g. developer instruction)
  preMessages?: LLMMessage[];
  output?: string; // for "json" outputMode: the raw output from LLM (if already obtained outside guard, e.g. via streaming) - if not provided, guard will call llm to get it (required for "text" mode),
  // for flow of the function
  checkInputOnly?: boolean; // if true, only check input and skip output checks (for future use)
  checkOutputOnly?: boolean; // if true, only check output and skip input checks (for future use)
};

export type GuardrailsRunResult = {
  safeText: string;
  blocked: boolean;
  events: GuardEvent[];
  // debugging (never show to end user in prod):
  rawModelText?: string;
  outputDetections?: any[]; // from output detectors, for debugging
  inputDetections?: any[]; // from input detectors, for debugging
};

export type Guardrails = {
  run(input: GuardrailsRunInput): Promise<GuardrailsRunResult>;
};