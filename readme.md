# @mjjuneja/llm-guardrails

A security middleware for LLM applications that sanitizes inputs,
outputs, and tool interactions to reduce leakage of:

-   PII (emails, phones, addresses, etc.)
-   Indian IDs (Aadhaar & GSTIN with checksum validation, PAN, IFSC, voter ID, UPI)
-   Secrets (API keys, RSA/SSH keys, tokens, JWTs)
-   SQL queries / schema / table / column names
-   System / developer prompt text
-   Unsafe tool calls (DB, HTTP, file access)
-   Invalid structured outputs (JSON enforcement mode)
-   Child signals + India DPDP enforcement (Aadhaar/PAN leak blocking, audit trail)

Designed for:

-   Chatbots\
-   RAG systems\
-   Agentic workflows\
-   Function/tool calling\
-   Enterprise AI platforms

------------------------------------------------------------------------

## Install

``` bash
npm i @mjjuneja/llm-guardrails
```

------------------------------------------------------------------------

# Quick Start (Full Mode)

``` ts
import { createGuardrails } from "@mjjuneja/llm-guardrails";

const guard = createGuardrails({
  mode: "full",
  redactPII: true,
  redactSecrets: true,
  blockSQLLeakage: true,
  blockPromptLeakage: true,
  maxRewriteAttempts: 1,
  onEvent: console.log
});

const result = await guard.run({
  userMessage: "Show me the SQL query you ran and table names",
  llm: async (messages) => {
    // call any LLM here
    return "SELECT * FROM users;";
  }
});

console.log(result.safeText);
```

If SQL leakage is detected:

-   The model is asked to rewrite\
-   If still unsafe → response is blocked

------------------------------------------------------------------------

# Modes

## 1. `mode: "full"` (default)

Runs:

-   Input validation\
-   LLM call\
-   Output validation\
-   Rewrite loop (if needed)

Use this for production chat endpoints.

------------------------------------------------------------------------

## 2. `mode: "input_only"`

Sanitizes input before calling any LLM.

``` ts
const guard = createGuardrails({ mode: "input_only" });

const result = await guard.run({
  userMessage: "Email me at dummy@dummy.com"
});

console.log(result.safeText); // email redacted
```

No LLM required.

------------------------------------------------------------------------

## 3. `mode: "output_only"`

Sanitizes existing output (no rewrite possible).

``` ts
const guard = createGuardrails({
  mode: "output_only"
});

const result = await guard.run({
  output: "SELECT * FROM users;"
});
```

If unsafe → blocked.

------------------------------------------------------------------------

# JSON Mode (Structured Output Enforcement)

Force the model to return strict JSON:

``` ts
const guard = createGuardrails({
  mode: "full",
  outputMode: "json"
});
```

Expected schema:

``` json
{
  "answer": "string",
  "sources": [],
  "confidence": 0.0
}
```

Behavior:

-   Invalid JSON → rewrite\
-   Still invalid → block\
-   Valid JSON → available as `result.json`

------------------------------------------------------------------------

# Tool Firewall (Agent Safety)

Prevent unsafe tool usage in agent workflows.

## Example Tool Policy

``` ts
const guard = createGuardrails({
  toolPolicies: {
    "db.schema": { block: true },
    "db.query": {
      maxRows: 10,
      stripFields: ["password"],
      validateCall: (call) => {
        const sql = call.args.sql?.toLowerCase();
        if (!sql.startsWith("select")) {
          return { allowed: false, reason: "Only SELECT allowed" };
        }
        return { allowed: true };
      }
    }
  }
});
```

------------------------------------------------------------------------

# DPDP / India Compliance

Built-in support for India's Digital Personal Data Protection (DPDP) Act:
Indian identifier detection, child-signal detection, hard enforcement, and a
compliance audit trail.

## Indian PII detection

Indian identifiers are detected automatically whenever `redactPII` is on (the
default). Aadhaar and GSTIN are validated with their published checksums
(Verhoeff / mod-36), so a random 12-digit number is not mistaken for an Aadhaar.

Detected: **Aadhaar, PAN, GSTIN, IFSC, voter ID, Indian mobile, UPI ID**.

``` ts
const guard = createGuardrails({ mode: "output_only", redactPII: true });

const result = await guard.run({
  output: "The customer Aadhaar is 2345 6789 0124 and PAN ABCPK5672Z."
});

console.log(result.safeText);
// "The customer Aadhaar is [Aadhaar removed] and PAN [PAN removed]."
```

## Child-signal detection

Under DPDP s. 9, processing a child's data needs verifiable parental consent.
Enable `detectChildSignals` to heuristically flag content involving minors
(ages under 18, school grades, parent-of-minor phrasing).

``` ts
const guard = createGuardrails({
  mode: "input_only",
  detectChildSignals: true,
  onEvent: (e) => {
    if (e.kind === "CHILD_SIGNAL_DETECTED") {
      console.log("Minor may be involved:", e.matches);
    }
  }
});

await guard.run({ userMessage: "my daughter is 8, suggest gift ideas" });
```

By default this only **flags** (emits an event). It is heuristic — expect some
false positives. To make it **block**, enable `dpdpEnforce` (below).

## Enforcement mode (`dpdpEnforce`)

`dpdpEnforce: true` escalates Indian PII and child signals from soft handling
(redact / flag) to a hard block, and throws a typed `DPDPBlockedError` instead
of resolving with `blocked: true`.

``` ts
import { createGuardrails, DPDPBlockedError } from "@mjjuneja/llm-guardrails";

const guard = createGuardrails({
  mode: "full",
  redactPII: true,
  detectChildSignals: true,
  dpdpEnforce: true
});

try {
  const result = await guard.run({
    userMessage: "Summarise this record",
    context: "Aadhaar: 2345 6789 0124",
    llm: callYourModel
  });
  console.log(result.safeText);
} catch (err) {
  if (err instanceof DPDPBlockedError) {
    console.error(`Blocked at ${err.phase} stage by ${err.detector}`);
    // err.phase    -> "input" | "output"
    // err.detector -> "indianPii" | "childSignal"
    // err.matches  -> string[]
  }
}
```

Non-DPDP blocks (e.g. a secret in the input) are unaffected — they still
resolve normally with `blocked: true`. Only Indian PII and child signals throw.

## Compliance audit trail

Record consent and processing evidence for the DPDP audit trail. Both methods
emit a `compliance`-phase event through `onEvent` and return it.

``` ts
const guard = createGuardrails({
  onEvent: (e) => myAuditLog.write(e)   // persist events however you like
});

// Record that a data principal granted consent
guard.recordConsent({
  dataPrincipalId: "user-123",       // use a pseudonymous id if preferred
  purpose: "marketing-personalisation",
  granted: true,
  noticeVersion: "privacy-notice-v2"
});

// Record evidence of a processing activity
guard.recordEvidence({
  action: "model_inference",
  purpose: "support-ticket-summarisation",
  dataPrincipalId: "user-123"
});
```

> The guardrail does not persist anything itself — it has no database and makes
> no network calls. Wire `onEvent` to your own store to keep the audit trail.

------------------------------------------------------------------------

# Audit Events

Every detection, redaction, block, and compliance action emits a structured
`GuardEvent` through `onEvent`.

``` ts
const guard = createGuardrails({
  redactEventPayloads: true,   // hash matched values in events (default true)
  onEvent: (event) => {
    console.log(event.phase, event.kind, event.detector);
  }
});
```

Event `kind` values:

| Kind | Meaning |
|---|---|
| `INPUT_REDACTED` / `INPUT_BLOCKED` | Input PII redacted / blocked |
| `OUTPUT_REDACTED` / `OUTPUT_BLOCKED` | Output sanitised / blocked |
| `OUTPUT_REWRITE_ATTEMPT` / `_SUCCESS` / `_FAILED` | Rewrite-loop progress |
| `OUTPUT_JSON_INVALID` | JSON-mode validation failed |
| `TOOL_CALL_BLOCKED` / `TOOL_RESULT_REDACTED` | Tool firewall actions |
| `CHILD_SIGNAL_DETECTED` | Content involving a minor flagged |
| `DPDP_BLOCKED` | A request hard-blocked under `dpdpEnforce` |
| `CONSENT_RECORDED` / `EVIDENCE_RECORDED` | Compliance audit-trail entries |

Set `redactEventPayloads: false` only in trusted debugging — it puts raw
matched values into `event.matches`.

------------------------------------------------------------------------

## Security Model

This package:

- Does NOT perform any outbound network requests
- Does NOT send telemetry
- Does NOT load remote code
- Does NOT access filesystem unless explicitly used in tool policies
- Performs only in-memory text inspection and transformation

All URL patterns in the source code are used strictly for validation and detection purposes.

------------------------------------------------------------------------

# License

MIT