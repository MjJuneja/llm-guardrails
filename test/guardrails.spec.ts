import test from "node:test";
import assert from "node:assert/strict";
import { createGuardrails } from "../src/guard/createGuardrails.js";

test("mode=input_only sanitizes PII in input and does not call llm", async () => {
  const guard = createGuardrails({
    mode: "input_only",
    redactPII: true,
    redactSecrets: true,
    redactEventPayloads: false
  });

  const res = await guard.run({
    userMessage: "Email me at mukul@muol.com"
  });

  assert.equal(res.blocked, false);
  assert.ok(
    res.safeText.includes("[email removed]") || res.safeText.includes("[PII removed]"),
    "Expected email redaction in input_only mode"
  );
});

test("mode=output_only redacts PII in output without llm", async () => {
  const guard = createGuardrails({
    mode: "output_only",
    redactPII: true,
    redactEventPayloads: false
  });

  const res = await guard.run({
    output: "Sure. data is mukul@muol.com"
  });

  assert.equal(res.blocked, false);
  assert.ok(
    res.safeText.includes("[email removed]") || res.safeText.includes("[PII removed]"),
    "Expected email redaction in output_only mode"
  );
});

test("full mode blocks secrets in input", async () => {
  const guard = createGuardrails({
    mode: "full",
    redactSecrets: true,
    redactEventPayloads: false
  });

  const res = await guard.run({
    userMessage: "rsa_key=SECRET",
    llm: async () => "ok"
  });

  assert.equal(res.blocked, true);
  assert.match(res.safeText.toLowerCase(), /can[’']t help|cannot help|can’t help/i);
});

test("full mode rewrites SQL leakage (one retry) then succeeds", async () => {
  const guard = createGuardrails({
    mode: "full",
    blockSQLLeakage: true,
    maxRewriteAttempts: 1,
    redactEventPayloads: false
  });

  let callCount = 0;
  const res = await guard.run({
    userMessage: "Explain tennis stats",
    llm: async () => {
      callCount += 1;
      if (callCount === 1) return "I ran: SELECT name FROM players;";
      return "I summarized relevant statistics at a high level without exposing internal queries.";
    }
  });

  assert.equal(res.blocked, false);
  assert.doesNotMatch(res.safeText, /\bSELECT\b/i);
});

test("json mode (full): invalid JSON triggers rewrite then succeeds", async () => {
  const guard = createGuardrails({
    mode: "full",
    outputMode: "json",
    maxRewriteAttempts: 1,
    redactEventPayloads: false
  });

  let callCount = 0;

  const res = await guard.run({
    userMessage: "Explain tennis scoring",
    llm: async () => {
      callCount += 1;
      if (callCount === 1) return "Not JSON at all"; // invalid
      return JSON.stringify({
        answer: "Tennis scoring uses 15, 30, 40, and game.",
        sources: [],
        confidence: 0.9
      });
    }
  });

  assert.equal(res.blocked, false);
  assert.ok(res.json, "Expected parsed json on success");
  assert.equal(res.json.answer.includes("Tennis scoring"), true);
});

test("json mode (output_only): invalid JSON blocks (no rewrite available)", async () => {
  const guard = createGuardrails({
    mode: "output_only",
    outputMode: "json",
    redactEventPayloads: false
  });

  const res = await guard.run({ output: "still not json" });

  assert.equal(res.blocked, true);
  assert.match(res.safeText.toLowerCase(), /can[’']t help|cannot help|can’t help/i);
});

test("json mode (output_only): valid JSON passes and res.json is available", async () => {
  const guard = createGuardrails({
    mode: "output_only",
    outputMode: "json",
    redactEventPayloads: false
  });

  const payload = JSON.stringify({ answer: "Hello", sources: [], confidence: 0.7 });
  const res = await guard.run({ output: payload });

  assert.equal(res.blocked, false);
  assert.ok(res.json);
  assert.equal(res.json.answer, "Hello");
});

test("audit events: redactEventPayloads=true hashes matches instead of raw", async () => {
  const events: any[] = [];

  const guard = createGuardrails({
    mode: "output_only",
    redactPII: true,
    redactEventPayloads: true,
    onEvent: (e) => events.push(e)
  });

  await guard.run({ output: "Email is mukul@muol.com" });

  const redacted = events.find((e) => e.kind === "OUTPUT_REDACTED");
  assert.ok(redacted, "Expected OUTPUT_REDACTED event");
  assert.ok(Array.isArray(redacted.matches), "Expected matches array");

  // ensure it does NOT contain the raw email
  const joined = (redacted.matches ?? []).join(" ");
  assert.equal(joined.includes("mukul@muol.com"), false);
});

test("audit events: redactEventPayloads=false shows raw matches", async () => {
  const events: any[] = [];

  const guard = createGuardrails({
    mode: "output_only",
    redactPII: true,
    redactEventPayloads: false,
    onEvent: (e) => events.push(e)
  });

  await guard.run({ output: "Email is mukul@muol.com" });

  const redacted = events.find((e) => e.kind === "OUTPUT_REDACTED");
  assert.ok(redacted, "Expected OUTPUT_REDACTED event");

  const joined = (redacted.matches ?? []).join(" ");
  assert.equal(joined.includes("mukul@muol.com"), true);
});

test("tool firewall: blocks configured tool", async () => {
  const guard = createGuardrails({
    toolPolicies: {
      "db.schema": { block: true }
    }
  });

  const decision = guard.validateToolCall({ name: "db.schema", args: {} });

  assert.equal(decision.allowed, false);
});

test("tool firewall: strips fields and limits rows", async () => {
  const guard = createGuardrails({
    toolPolicies: {
      "db.query": { maxRows: 1, stripFields: ["password"] }
    }
  });

  const raw = [
    { id: 1, email: "a@b.com", password: "secret" },
    { id: 2, email: "c@d.com", password: "secret2" }
  ];

  const { payload } = guard.sanitizeToolResult("db.query", raw);

  assert.equal(Array.isArray(payload), true);
  const arr = payload as any[];
  assert.equal(arr.length, 1);
  assert.equal(arr[0].password, undefined);
});