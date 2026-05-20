import test from "node:test";
import assert from "node:assert/strict";
import { createGuardrails } from "../src/guard/createGuardrails.js";
import {
  detectIndianPII,
  isValidAadhaar,
} from "../src/detectors/indianPii.js";
import { detectChildSignals } from "../src/detectors/childSignal.js";
import { DPDPBlockedError } from "../src/guard/errors.js";

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

// ---------------------------------------------------------------------------
// Indian PII detectors (Aadhaar / PAN / GSTIN)
// ---------------------------------------------------------------------------

test("indianPii: Verhoeff checksum accepts valid and rejects invalid Aadhaar", () => {
  assert.equal(isValidAadhaar("234567890124"), true);
  assert.equal(isValidAadhaar("234567890123"), false);
});

test("indianPii: detector returns only checksum-valid Aadhaar numbers", () => {
  const d = detectIndianPII("good 234567890124 bad 234567890123");
  const aadhaar = d.detectedItems.find((x) => x.type === "aadhaar");
  assert.ok(aadhaar, "Expected an aadhaar detection");
  assert.deepEqual(aadhaar!.items, ["234567890124"]);
});

test("indianPii: detector finds PAN and a valid GSTIN", () => {
  const d = detectIndianPII("PAN ABCPK1234Z GSTIN 22AAAAA0000A1ZC");
  assert.ok(d.detectedItems.find((x) => x.type === "pan"), "Expected PAN");
  assert.ok(d.detectedItems.find((x) => x.type === "gstin"), "Expected GSTIN");
});

test("indianPii: valid Aadhaar is redacted in output", async () => {
  const guard = createGuardrails({
    mode: "output_only",
    redactPII: true,
    redactEventPayloads: false,
  });

  const res = await guard.run({ output: "Your Aadhaar 234567890124 is on file." });

  assert.equal(res.blocked, false);
  assert.ok(res.safeText.includes("[Aadhaar removed]"));
  assert.equal(res.safeText.includes("234567890124"), false);
});

test("indianPii: number with bad Aadhaar checksum is not labelled Aadhaar", async () => {
  const guard = createGuardrails({
    mode: "output_only",
    redactPII: true,
    redactEventPayloads: false,
  });

  const res = await guard.run({ output: "Reference number 234567890123 here." });

  assert.equal(res.safeText.includes("[Aadhaar removed]"), false);
});

// ---------------------------------------------------------------------------
// Bug fix: secrets regex no longer matches bare keywords
// ---------------------------------------------------------------------------

test("secrets: a plain sentence containing 'password' does not block input", async () => {
  const guard = createGuardrails({
    mode: "input_only",
    redactSecrets: true,
    redactEventPayloads: false,
  });

  const res = await guard.run({
    userMessage: "I forgot my password, can you help me reset it?",
  });

  assert.equal(res.blocked, false);
});

test("secrets: a real key=value secret still blocks input", async () => {
  const guard = createGuardrails({
    mode: "input_only",
    redactSecrets: true,
    redactEventPayloads: false,
  });

  const res = await guard.run({
    userMessage: "use api_key=sk_live_abcdef123456 please",
  });

  assert.equal(res.blocked, true);
});

// ---------------------------------------------------------------------------
// Bug fix: allowlist is a per-match filter, not a whole-text bypass
// ---------------------------------------------------------------------------

test("allowlist: an allowlisted token does not disable secret detection", async () => {
  const guard = createGuardrails({
    mode: "input_only",
    redactSecrets: true,
    redactEventPayloads: false,
    allowPatterns: [/SAFE-TOKEN-OK/],
  });

  const res = await guard.run({
    userMessage: "SAFE-TOKEN-OK and api_key=supersecretvalue123",
  });

  assert.equal(res.blocked, true);
});

test("allowlist: an allowlisted PII match is left untouched", async () => {
  const guard = createGuardrails({
    mode: "input_only",
    redactPII: true,
    redactEventPayloads: false,
    allowPatterns: [/support@muoro\.com/],
  });

  const res = await guard.run({ userMessage: "Contact support@muoro.com for help" });

  assert.equal(res.blocked, false);
  assert.equal(res.safeText.includes("support@muoro.com"), true);
});

// ---------------------------------------------------------------------------
// RAG context is sanitized before it reaches the prompt
// ---------------------------------------------------------------------------

test("context: PII in RAG context is redacted before the LLM call", async () => {
  const guard = createGuardrails({
    mode: "full",
    redactPII: true,
    redactEventPayloads: false,
  });

  let seenContext = "";
  const res = await guard.run({
    userMessage: "Summarize the customer record",
    context: "Customer email is jane@example.com",
    llm: async (messages) => {
      seenContext =
        messages.find((m) => m.role === "developer")?.content ?? "";
      return "Here is a safe summary.";
    },
  });

  assert.equal(res.blocked, false);
  assert.equal(seenContext.includes("jane@example.com"), false);
  assert.ok(seenContext.includes("[email removed]"));
});

// ---------------------------------------------------------------------------
// Child-signal detector
// ---------------------------------------------------------------------------

test("childSignal detector: flags minors, ignores adult ages", () => {
  assert.ok(detectChildSignals("my daughter is 8 years old").length > 0);
  assert.ok(detectChildSignals("she is in grade 5").length > 0);
  assert.equal(
    detectChildSignals("I am 34 years old and a backend developer").length,
    0,
  );
});

test("childSignal: flag mode emits an event without blocking", async () => {
  const events: any[] = [];
  const guard = createGuardrails({
    mode: "input_only",
    detectChildSignals: true,
    dpdpEnforce: false,
    redactEventPayloads: false,
    onEvent: (e) => events.push(e),
  });

  const res = await guard.run({
    userMessage: "my daughter is 8 years old, suggest some books",
  });

  assert.equal(res.blocked, false);
  assert.ok(
    events.find((e) => e.kind === "CHILD_SIGNAL_DETECTED"),
    "Expected a CHILD_SIGNAL_DETECTED event",
  );
});

// ---------------------------------------------------------------------------
// dpdpEnforce: hard block + DPDPBlockedError
// ---------------------------------------------------------------------------

test("dpdpEnforce: Aadhaar in input throws DPDPBlockedError", async () => {
  const guard = createGuardrails({
    mode: "input_only",
    redactPII: true,
    dpdpEnforce: true,
    redactEventPayloads: false,
  });

  await assert.rejects(
    guard.run({ userMessage: "my aadhaar number is 234567890124" }),
    (err) => err instanceof DPDPBlockedError && err.detector === "indianPii",
  );
});

test("dpdpEnforce: child signal in input throws DPDPBlockedError", async () => {
  const guard = createGuardrails({
    mode: "input_only",
    detectChildSignals: true,
    dpdpEnforce: true,
    redactEventPayloads: false,
  });

  await assert.rejects(
    guard.run({ userMessage: "my daughter is 8 years old" }),
    (err) => err instanceof DPDPBlockedError && err.detector === "childSignal",
  );
});

test("dpdpEnforce: Aadhaar in output throws DPDPBlockedError", async () => {
  const guard = createGuardrails({
    mode: "output_only",
    redactPII: true,
    dpdpEnforce: true,
    redactEventPayloads: false,
  });

  await assert.rejects(
    guard.run({ output: "The Aadhaar on record is 234567890124." }),
    (err) => err instanceof DPDPBlockedError && err.phase === "output",
  );
});

test("dpdpEnforce: a non-DPDP block (secret) still returns, does not throw", async () => {
  const guard = createGuardrails({
    mode: "input_only",
    redactSecrets: true,
    dpdpEnforce: true,
    redactEventPayloads: false,
  });

  const res = await guard.run({
    userMessage: "api_key=supersecretvalue123",
  });

  assert.equal(res.blocked, true);
});

// ---------------------------------------------------------------------------
// Consent / evidence audit-trail events
// ---------------------------------------------------------------------------

test("recordConsent: emits a CONSENT_RECORDED compliance event", () => {
  const events: any[] = [];
  const guard = createGuardrails({ onEvent: (e) => events.push(e) });

  const e = guard.recordConsent({
    dataPrincipalId: "user-123",
    purpose: "marketing-personalisation",
    granted: true,
    noticeVersion: "v2",
  });

  assert.equal(e.kind, "CONSENT_RECORDED");
  assert.equal(e.phase, "compliance");
  assert.equal(events.length, 1);
  assert.equal(events[0].meta?.purpose, "marketing-personalisation");
  assert.equal(events[0].meta?.granted, true);
});

test("recordEvidence: emits an EVIDENCE_RECORDED compliance event", () => {
  const events: any[] = [];
  const guard = createGuardrails({ onEvent: (e) => events.push(e) });

  const e = guard.recordEvidence({
    action: "model_inference",
    purpose: "support-summarisation",
    dataPrincipalId: "user-123",
  });

  assert.equal(e.kind, "EVIDENCE_RECORDED");
  assert.equal(e.phase, "compliance");
  assert.equal(events.length, 1);
  assert.equal(events[0].meta?.action, "model_inference");
});