# @your-scope/llm-guardrails

A small middleware that sanitizes LLM inputs/outputs to reduce leakage of:
- PII
- secrets
- SQL queries / schema/table/column names
- system/developer prompt text

## Install
npm i @your-scope/llm-guardrails

## Usage (generic)
```ts
import { createGuardrails } from "@your-scope/llm-guardrails";

const guard = createGuardrails({
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


## File Structure
```bash
llm-guardrails/
├─ package.json
├─ tsconfig.json
├─ README.md
├─ src/
│  ├─ index.ts
│  ├─ guard/
│  │  ├─ createGuardrails.ts
│  │  ├─ types.ts
│  │  └─ utils.ts
│  ├─ detectors/
│  │  ├─ pii.ts
│  │  ├─ secrets.ts
│  │  ├─ sqlLeak.ts
│  │  └─ promptLeak.ts
│  ├─ policies/
│  │  ├─ defaultPolicy.ts
│  │  └─ actions.ts
│  └─ adapters/
│     └─ openai.ts
└─ test/
   └─ guardrails.spec.ts
```