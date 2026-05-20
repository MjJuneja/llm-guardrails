"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const createGuardrails_js_1 = require("../src/guard/createGuardrails.js");
const indianPii_js_1 = require("../src/detectors/indianPii.js");
const childSignal_js_1 = require("../src/detectors/childSignal.js");
const errors_js_1 = require("../src/guard/errors.js");
(0, node_test_1.default)("mode=input_only sanitizes PII in input and does not call llm", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "input_only",
        redactPII: true,
        redactSecrets: true,
        redactEventPayloads: false
    });
    const res = await guard.run({
        userMessage: "Email me at mukul@muol.com"
    });
    strict_1.default.equal(res.blocked, false);
    strict_1.default.ok(res.safeText.includes("[email removed]") || res.safeText.includes("[PII removed]"), "Expected email redaction in input_only mode");
});
(0, node_test_1.default)("mode=output_only redacts PII in output without llm", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "output_only",
        redactPII: true,
        redactEventPayloads: false
    });
    const res = await guard.run({
        output: "Sure. data is mukul@muol.com"
    });
    strict_1.default.equal(res.blocked, false);
    strict_1.default.ok(res.safeText.includes("[email removed]") || res.safeText.includes("[PII removed]"), "Expected email redaction in output_only mode");
});
(0, node_test_1.default)("full mode blocks secrets in input", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "full",
        redactSecrets: true,
        redactEventPayloads: false
    });
    const res = await guard.run({
        userMessage: "rsa_key=SECRET",
        llm: async () => "ok"
    });
    strict_1.default.equal(res.blocked, true);
    strict_1.default.match(res.safeText.toLowerCase(), /can[’']t help|cannot help|can’t help/i);
});
(0, node_test_1.default)("full mode rewrites SQL leakage (one retry) then succeeds", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
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
            if (callCount === 1)
                return "I ran: SELECT name FROM players;";
            return "I summarized relevant statistics at a high level without exposing internal queries.";
        }
    });
    strict_1.default.equal(res.blocked, false);
    strict_1.default.doesNotMatch(res.safeText, /\bSELECT\b/i);
});
(0, node_test_1.default)("json mode (full): invalid JSON triggers rewrite then succeeds", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
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
            if (callCount === 1)
                return "Not JSON at all"; // invalid
            return JSON.stringify({
                answer: "Tennis scoring uses 15, 30, 40, and game.",
                sources: [],
                confidence: 0.9
            });
        }
    });
    strict_1.default.equal(res.blocked, false);
    strict_1.default.ok(res.json, "Expected parsed json on success");
    strict_1.default.equal(res.json.answer.includes("Tennis scoring"), true);
});
(0, node_test_1.default)("json mode (output_only): invalid JSON blocks (no rewrite available)", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "output_only",
        outputMode: "json",
        redactEventPayloads: false
    });
    const res = await guard.run({ output: "still not json" });
    strict_1.default.equal(res.blocked, true);
    strict_1.default.match(res.safeText.toLowerCase(), /can[’']t help|cannot help|can’t help/i);
});
(0, node_test_1.default)("json mode (output_only): valid JSON passes and res.json is available", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "output_only",
        outputMode: "json",
        redactEventPayloads: false
    });
    const payload = JSON.stringify({ answer: "Hello", sources: [], confidence: 0.7 });
    const res = await guard.run({ output: payload });
    strict_1.default.equal(res.blocked, false);
    strict_1.default.ok(res.json);
    strict_1.default.equal(res.json.answer, "Hello");
});
(0, node_test_1.default)("audit events: redactEventPayloads=true hashes matches instead of raw", async () => {
    const events = [];
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "output_only",
        redactPII: true,
        redactEventPayloads: true,
        onEvent: (e) => events.push(e)
    });
    await guard.run({ output: "Email is mukul@muol.com" });
    const redacted = events.find((e) => e.kind === "OUTPUT_REDACTED");
    strict_1.default.ok(redacted, "Expected OUTPUT_REDACTED event");
    strict_1.default.ok(Array.isArray(redacted.matches), "Expected matches array");
    // ensure it does NOT contain the raw email
    const joined = (redacted.matches ?? []).join(" ");
    strict_1.default.equal(joined.includes("mukul@muol.com"), false);
});
(0, node_test_1.default)("audit events: redactEventPayloads=false shows raw matches", async () => {
    const events = [];
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "output_only",
        redactPII: true,
        redactEventPayloads: false,
        onEvent: (e) => events.push(e)
    });
    await guard.run({ output: "Email is mukul@muol.com" });
    const redacted = events.find((e) => e.kind === "OUTPUT_REDACTED");
    strict_1.default.ok(redacted, "Expected OUTPUT_REDACTED event");
    const joined = (redacted.matches ?? []).join(" ");
    strict_1.default.equal(joined.includes("mukul@muol.com"), true);
});
(0, node_test_1.default)("tool firewall: blocks configured tool", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        toolPolicies: {
            "db.schema": { block: true }
        }
    });
    const decision = guard.validateToolCall({ name: "db.schema", args: {} });
    strict_1.default.equal(decision.allowed, false);
});
(0, node_test_1.default)("tool firewall: strips fields and limits rows", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        toolPolicies: {
            "db.query": { maxRows: 1, stripFields: ["password"] }
        }
    });
    const raw = [
        { id: 1, email: "a@b.com", password: "secret" },
        { id: 2, email: "c@d.com", password: "secret2" }
    ];
    const { payload } = guard.sanitizeToolResult("db.query", raw);
    strict_1.default.equal(Array.isArray(payload), true);
    const arr = payload;
    strict_1.default.equal(arr.length, 1);
    strict_1.default.equal(arr[0].password, undefined);
});
// ---------------------------------------------------------------------------
// Indian PII detectors (Aadhaar / PAN / GSTIN)
// ---------------------------------------------------------------------------
(0, node_test_1.default)("indianPii: Verhoeff checksum accepts valid and rejects invalid Aadhaar", () => {
    strict_1.default.equal((0, indianPii_js_1.isValidAadhaar)("234567890124"), true);
    strict_1.default.equal((0, indianPii_js_1.isValidAadhaar)("234567890123"), false);
});
(0, node_test_1.default)("indianPii: detector returns only checksum-valid Aadhaar numbers", () => {
    const d = (0, indianPii_js_1.detectIndianPII)("good 234567890124 bad 234567890123");
    const aadhaar = d.detectedItems.find((x) => x.type === "aadhaar");
    strict_1.default.ok(aadhaar, "Expected an aadhaar detection");
    strict_1.default.deepEqual(aadhaar.items, ["234567890124"]);
});
(0, node_test_1.default)("indianPii: detector finds PAN and a valid GSTIN", () => {
    const d = (0, indianPii_js_1.detectIndianPII)("PAN ABCPK1234Z GSTIN 22AAAAA0000A1ZC");
    strict_1.default.ok(d.detectedItems.find((x) => x.type === "pan"), "Expected PAN");
    strict_1.default.ok(d.detectedItems.find((x) => x.type === "gstin"), "Expected GSTIN");
});
(0, node_test_1.default)("indianPii: valid Aadhaar is redacted in output", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "output_only",
        redactPII: true,
        redactEventPayloads: false,
    });
    const res = await guard.run({ output: "Your Aadhaar 234567890124 is on file." });
    strict_1.default.equal(res.blocked, false);
    strict_1.default.ok(res.safeText.includes("[Aadhaar removed]"));
    strict_1.default.equal(res.safeText.includes("234567890124"), false);
});
(0, node_test_1.default)("indianPii: number with bad Aadhaar checksum is not labelled Aadhaar", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "output_only",
        redactPII: true,
        redactEventPayloads: false,
    });
    const res = await guard.run({ output: "Reference number 234567890123 here." });
    strict_1.default.equal(res.safeText.includes("[Aadhaar removed]"), false);
});
// ---------------------------------------------------------------------------
// Bug fix: secrets regex no longer matches bare keywords
// ---------------------------------------------------------------------------
(0, node_test_1.default)("secrets: a plain sentence containing 'password' does not block input", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "input_only",
        redactSecrets: true,
        redactEventPayloads: false,
    });
    const res = await guard.run({
        userMessage: "I forgot my password, can you help me reset it?",
    });
    strict_1.default.equal(res.blocked, false);
});
(0, node_test_1.default)("secrets: a real key=value secret still blocks input", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "input_only",
        redactSecrets: true,
        redactEventPayloads: false,
    });
    const res = await guard.run({
        userMessage: "use api_key=sk_live_abcdef123456 please",
    });
    strict_1.default.equal(res.blocked, true);
});
// ---------------------------------------------------------------------------
// Bug fix: allowlist is a per-match filter, not a whole-text bypass
// ---------------------------------------------------------------------------
(0, node_test_1.default)("allowlist: an allowlisted token does not disable secret detection", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "input_only",
        redactSecrets: true,
        redactEventPayloads: false,
        allowPatterns: [/SAFE-TOKEN-OK/],
    });
    const res = await guard.run({
        userMessage: "SAFE-TOKEN-OK and api_key=supersecretvalue123",
    });
    strict_1.default.equal(res.blocked, true);
});
(0, node_test_1.default)("allowlist: an allowlisted PII match is left untouched", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "input_only",
        redactPII: true,
        redactEventPayloads: false,
        allowPatterns: [/support@muoro\.com/],
    });
    const res = await guard.run({ userMessage: "Contact support@muoro.com for help" });
    strict_1.default.equal(res.blocked, false);
    strict_1.default.equal(res.safeText.includes("support@muoro.com"), true);
});
// ---------------------------------------------------------------------------
// RAG context is sanitized before it reaches the prompt
// ---------------------------------------------------------------------------
(0, node_test_1.default)("context: PII in RAG context is redacted before the LLM call", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
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
    strict_1.default.equal(res.blocked, false);
    strict_1.default.equal(seenContext.includes("jane@example.com"), false);
    strict_1.default.ok(seenContext.includes("[email removed]"));
});
// ---------------------------------------------------------------------------
// Child-signal detector
// ---------------------------------------------------------------------------
(0, node_test_1.default)("childSignal detector: flags minors, ignores adult ages", () => {
    strict_1.default.ok((0, childSignal_js_1.detectChildSignals)("my daughter is 8 years old").length > 0);
    strict_1.default.ok((0, childSignal_js_1.detectChildSignals)("she is in grade 5").length > 0);
    strict_1.default.equal((0, childSignal_js_1.detectChildSignals)("I am 34 years old and a backend developer").length, 0);
});
(0, node_test_1.default)("childSignal: flag mode emits an event without blocking", async () => {
    const events = [];
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "input_only",
        detectChildSignals: true,
        dpdpEnforce: false,
        redactEventPayloads: false,
        onEvent: (e) => events.push(e),
    });
    const res = await guard.run({
        userMessage: "my daughter is 8 years old, suggest some books",
    });
    strict_1.default.equal(res.blocked, false);
    strict_1.default.ok(events.find((e) => e.kind === "CHILD_SIGNAL_DETECTED"), "Expected a CHILD_SIGNAL_DETECTED event");
});
// ---------------------------------------------------------------------------
// dpdpEnforce: hard block + DPDPBlockedError
// ---------------------------------------------------------------------------
(0, node_test_1.default)("dpdpEnforce: Aadhaar in input throws DPDPBlockedError", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "input_only",
        redactPII: true,
        dpdpEnforce: true,
        redactEventPayloads: false,
    });
    await strict_1.default.rejects(guard.run({ userMessage: "my aadhaar number is 234567890124" }), (err) => err instanceof errors_js_1.DPDPBlockedError && err.detector === "indianPii");
});
(0, node_test_1.default)("dpdpEnforce: child signal in input throws DPDPBlockedError", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "input_only",
        detectChildSignals: true,
        dpdpEnforce: true,
        redactEventPayloads: false,
    });
    await strict_1.default.rejects(guard.run({ userMessage: "my daughter is 8 years old" }), (err) => err instanceof errors_js_1.DPDPBlockedError && err.detector === "childSignal");
});
(0, node_test_1.default)("dpdpEnforce: Aadhaar in output throws DPDPBlockedError", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "output_only",
        redactPII: true,
        dpdpEnforce: true,
        redactEventPayloads: false,
    });
    await strict_1.default.rejects(guard.run({ output: "The Aadhaar on record is 234567890124." }), (err) => err instanceof errors_js_1.DPDPBlockedError && err.phase === "output");
});
(0, node_test_1.default)("dpdpEnforce: a non-DPDP block (secret) still returns, does not throw", async () => {
    const guard = (0, createGuardrails_js_1.createGuardrails)({
        mode: "input_only",
        redactSecrets: true,
        dpdpEnforce: true,
        redactEventPayloads: false,
    });
    const res = await guard.run({
        userMessage: "api_key=supersecretvalue123",
    });
    strict_1.default.equal(res.blocked, true);
});
// ---------------------------------------------------------------------------
// Consent / evidence audit-trail events
// ---------------------------------------------------------------------------
(0, node_test_1.default)("recordConsent: emits a CONSENT_RECORDED compliance event", () => {
    const events = [];
    const guard = (0, createGuardrails_js_1.createGuardrails)({ onEvent: (e) => events.push(e) });
    const e = guard.recordConsent({
        dataPrincipalId: "user-123",
        purpose: "marketing-personalisation",
        granted: true,
        noticeVersion: "v2",
    });
    strict_1.default.equal(e.kind, "CONSENT_RECORDED");
    strict_1.default.equal(e.phase, "compliance");
    strict_1.default.equal(events.length, 1);
    strict_1.default.equal(events[0].meta?.purpose, "marketing-personalisation");
    strict_1.default.equal(events[0].meta?.granted, true);
});
(0, node_test_1.default)("recordEvidence: emits an EVIDENCE_RECORDED compliance event", () => {
    const events = [];
    const guard = (0, createGuardrails_js_1.createGuardrails)({ onEvent: (e) => events.push(e) });
    const e = guard.recordEvidence({
        action: "model_inference",
        purpose: "support-summarisation",
        dataPrincipalId: "user-123",
    });
    strict_1.default.equal(e.kind, "EVIDENCE_RECORDED");
    strict_1.default.equal(e.phase, "compliance");
    strict_1.default.equal(events.length, 1);
    strict_1.default.equal(events[0].meta?.action, "model_inference");
});
