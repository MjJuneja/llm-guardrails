"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const createGuardrails_js_1 = require("../src/guard/createGuardrails.js");
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
