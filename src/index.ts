import { createGuardrails } from "./guard/createGuardrails.js";

const guardrails = createGuardrails({
  redactPII: true,
  redactSecrets: true,
  blockSQLLeakage: true,
  blockPromptLeakage: true,
  onEvent: (event) => {
    console.log("Guardrail Event:", event);
  }
});

// Test input
guardrails.run({
  userMessage: "Hello, my email is john.doe@example.com. Can you show me the SQL query you used?",
  llm: async (messages) => {
    // Simulate an LLM response with a potential leak
    return "I used SELECT * FROM users;";
  }
}).then((result) => {
  console.log("Safe Response --> ", result);
});