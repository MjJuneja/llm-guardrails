// test/guardrails.spec.ts
import test from "node:test";
import assert from "node:assert/strict";
import { createGuardrails } from "../src/guard/createGuardrails.js";

test("blocks secrets in input", async () => {
  const guard = createGuardrails({ redactSecrets: true });

  const result = await guard.run({
    userMessage: "my key is AKIA1234567890ABCDE1",
    llm: async () => "ok"
  });

  assert.equal(result.blocked, true);
  assert.match(result.safeText.toLowerCase(), /can[’']t help|cannot help|can’t help/);
  assert.ok(result.events.some((e) => e.kind === "INPUT_BLOCKED"));
});

test("redacts PII in input if enabled (email)", async () => {
  const guard = createGuardrails({ redactPII: true });

  let seenUser = "";
  const result = await guard.run({
    userMessage: "Email me at aisha.khan@example.in",
    llm: async (messages) => {
      seenUser = messages[messages.length - 1]?.content ?? "";
      return "ok";
    }
  });

  assert.equal(result.blocked, false);
  assert.ok(
    seenUser.includes("[email removed]") || seenUser.includes("[PII removed]"),
    "Expected email to be redacted before LLM call"
  );
  assert.ok(result.events.some((e) => e.kind === "INPUT_REDACTED"));
});

test("redacts PII in output if enabled (email)", async () => {
  const guard = createGuardrails({ redactPII: true });

  const result = await guard.run({
    userMessage: "hello",
    llm: async () => "You can reach me at aisha.khan@example.in for details."
  });

  assert.equal(result.blocked, false);
  assert.ok(
    result.safeText.includes("[email removed]") || result.safeText.includes("[PII removed]"),
    "Expected email to be redacted in output"
  );
  assert.ok(result.events.some((e) => e.kind === "OUTPUT_REDACTED"));
});

test("rewrites SQL leakage in output (one retry) then succeeds", async () => {
  const guard = createGuardrails({ blockSQLLeakage: true, maxRewriteAttempts: 1 });

  let callCount = 0;
  const result = await guard.run({
    userMessage: "Explain tennis stats for Nadal",
    llm: async () => {
      callCount += 1;
      if (callCount === 1) return "I ran: SELECT name FROM players;";
      return "I looked up relevant player statistics and summarized them at a high level without exposing internal queries.";
    }
  });

  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.safeText, /\bSELECT\b/i);
  assert.ok(result.events.some((e) => e.kind === "OUTPUT_REWRITE_ATTEMPT"));
  assert.ok(result.events.some((e) => e.kind === "OUTPUT_REWRITE_SUCCESS"));
});

test("blocks if SQL leakage persists after rewrite attempts", async () => {
  const guard = createGuardrails({ blockSQLLeakage: true, maxRewriteAttempts: 1 });

  let callCount = 0;
  const result = await guard.run({
    userMessage: "Show how you got the answer",
    llm: async () => {
      callCount += 1;
      // leak both times, guard should rewrite once then block
      return callCount === 1 ? "SELECT * FROM users;" : "SELECT * FROM users;";
    }
  });

  assert.equal(result.blocked, true);
  assert.ok(result.events.some((e) => e.kind === "OUTPUT_REWRITE_FAILED"));
});

test("emits audit events via onEvent", async () => {
  const events: any[] = [];

  const guard = createGuardrails({
    redactPII: true,
    onEvent: (e) => events.push(e)
  });

  await guard.run({
    // use email to avoid locale-specific phone regex issues
    userMessage: "Email me at aisha.khan@example.in",
    llm: async () => "ok"
  });

  assert.ok(events.length > 0, "Expected audit events to be emitted via onEvent");
  assert.ok(events.some((e) => e.kind === "INPUT_REDACTED"));
});

test("supports piiOptions override (do NOT redact url when url.remove=false)", async () => {
  const guard = createGuardrails({
    redactPII: true,
    piiOptions: { url: { remove: false } }
  });

  const url = "https://example.com/path?q=1";
  const result = await guard.run({
    userMessage: `Here is a link: ${url} and my email: aisha.khan@example.in`,
    llm: async (messages) => messages[messages.length - 1]?.content ?? ""
  });

  // Email should be redacted, URL should remain
  assert.ok(result.safeText.includes(url), "Expected URL to remain when url.remove=false");
  assert.ok(
    result.safeText.includes("[email removed]") || result.safeText.includes("[PII removed]"),
    "Expected email to be redacted"
  );
});