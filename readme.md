# @mjjuneja/llm-guardrails

A security middleware for LLM applications that sanitizes inputs,
outputs, and tool interactions to reduce leakage of:

-   PII (emails, phones, addresses, etc.)
-   Secrets (API keys, RSA/SSH keys, tokens, JWTs)
-   SQL queries / schema / table / column names
-   System / developer prompt text
-   Unsafe tool calls (DB, HTTP, file access)
-   Invalid structured outputs (JSON enforcement mode)

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
  userMessage: "Email me at mukul@muol.com"
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

# Audit Events

All detections emit structured events.

``` ts
const guard = createGuardrails({
  onEvent: (event) => {
    console.log(event);
  }
});
```

------------------------------------------------------------------------

# License

MIT