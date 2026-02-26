"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultToolPolicies = void 0;
// helpers
function deny(reason) {
    return { allowed: false, reason };
}
function allow(reason) {
    return { allowed: true, reason };
}
function hasAnyKey(obj, keys) {
    if (!obj || typeof obj !== "object")
        return false;
    return keys.some((k) => k in obj);
}
function stringIncludesAny(s, needles) {
    const x = s.toLowerCase();
    return needles.some((n) => x.includes(n.toLowerCase()));
}
// heuristic for "data exfil" style requests
const DANGEROUS_SQL = [
    "information_schema",
    "pg_catalog",
    "sqlite_master",
    "show tables",
    "describe ",
    "explain ",
    "pragma ",
    "show create table",
    "dump",
    "union select"
];
const WRITE_SQL = ["insert ", "update ", "delete ", "drop ", "alter ", "truncate ", "create "];
// common sensitive columns
const SENSITIVE_FIELDS = [
    "password",
    "pass",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "ssn",
    "credit",
    "card",
    "cvv",
    "dob",
    "pan",
    "aadhar",
    "aadhaar"
];
exports.defaultToolPolicies = {
    /**
     * Block schema/tooling that reveals internals by design.
     */
    "db.schema": {
        block: true
    },
    "db.introspect": {
        block: true
    },
    /**
     * DB query tool: allow only SELECT, block metadata & write queries.
     * Also shape output: max rows, strip known sensitive fields.
     */
    "db.query": {
        maxRows: 25,
        stripFields: [...SENSITIVE_FIELDS],
        validateCall: (call) => {
            const args = call.args ?? {};
            // allow either `sql` or `query`
            const sql = args.sql ?? args.query;
            if (!sql || typeof sql !== "string") {
                return deny("db.query requires args.sql (string)");
            }
            const normalized = sql.trim().toLowerCase();
            // Must be read-only (SELECT only)
            if (!normalized.startsWith("select")) {
                return deny("Only SELECT queries are allowed");
            }
            // block obvious metadata / schema fishing
            if (stringIncludesAny(normalized, DANGEROUS_SQL)) {
                return deny("Schema/metadata queries are blocked");
            }
            // block write ops just in case model sneaks them in
            if (stringIncludesAny(normalized, WRITE_SQL)) {
                return deny("Write queries are blocked");
            }
            // block selecting obviously sensitive fields (best-effort)
            if (stringIncludesAny(normalized, SENSITIVE_FIELDS.map((f) => ` ${f}`))) {
                return deny("Query appears to request sensitive fields");
            }
            // enforce a LIMIT if missing (soft-deny or strict-deny)
            if (!normalized.includes(" limit ")) {
                return deny("Query must include a LIMIT clause");
            }
            return allow();
        }
    },
    /**
     * HTTP GET: only allow whitelisted domains. This prevents SSRF/exfil.
     */
    "http.get": {
        maxChars: 20_000,
        validateCall: (call) => {
            const args = call.args ?? {};
            const url = args.url;
            if (!url || typeof url !== "string")
                return deny("http.get requires args.url (string)");
            // allowlist domains (edit this list per client)
            const allowDomains = ["api.example.com", "stats.atp.com", "raw.githubusercontent.com"];
            try {
                const u = new URL(url);
                if (!allowDomains.includes(u.hostname)) {
                    return deny(`Domain not allowed: ${u.hostname}`);
                }
            }
            catch {
                return deny("Invalid URL");
            }
            return allow();
        }
    },
    /**
     * File reads: allow only within a specific folder prefix.
     */
    "file.read": {
        maxChars: 50_000,
        validateCall: (call) => {
            const args = call.args ?? {};
            const path = args.path;
            if (!path || typeof path !== "string")
                return deny("file.read requires args.path (string)");
            // prevent path traversal
            if (path.includes(".."))
                return deny("Path traversal blocked");
            // allow only a safe prefix
            if (!path.startsWith("data/"))
                return deny("Only data/ directory is readable");
            return allow();
        }
    },
    /**
     * File writes: block by default in most chatbots.
     */
    "file.write": {
        block: true
    },
    /**
     * Slack/Email sending: allow but prevent secrets/PII from being sent as raw.
     * This uses sanitizeText to run output-guardrails on the tool result,
     * but for "send" tools you'd typically sanitize the message BEFORE sending.
     */
    "slack.send": {
        validateCall: (call) => {
            const args = call.args ?? {};
            if (!hasAnyKey(args, ["channel", "text"]))
                return deny("slack.send requires channel and text");
            if (typeof args.text !== "string")
                return deny("slack.send text must be string");
            if (args.text.length > 2000)
                return deny("Message too long");
            return allow();
        }
    },
    "email.send": {
        validateCall: (call) => {
            const args = call.args ?? {};
            if (!hasAnyKey(args, ["to", "subject", "body"]))
                return deny("email.send requires to, subject, body");
            if (typeof args.body !== "string")
                return deny("email body must be string");
            if (args.body.length > 10_000)
                return deny("Email body too long");
            return allow();
        }
    }
};
