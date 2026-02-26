"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateToolCall = validateToolCall;
exports.sanitizeToolResultPayload = sanitizeToolResultPayload;
function validateToolCall(call, policies) {
    const policy = policies?.[call.name];
    if (!policy)
        return { allowed: true };
    if (policy.block)
        return { allowed: false, reason: `Tool "${call.name}" is blocked by policy` };
    if (policy.validateCall)
        return policy.validateCall(call);
    return { allowed: true };
}
function sanitizeToolResultPayload(toolName, payload, policy) {
    if (!policy)
        return payload;
    let out = payload;
    // enforce maxRows for array results
    if (Array.isArray(out) && typeof policy.maxRows === "number") {
        out = out.slice(0, policy.maxRows);
    }
    // strip fields for array-of-objects
    if (Array.isArray(out) && policy.stripFields?.length) {
        out = out.map((row) => {
            if (!row || typeof row !== "object")
                return row;
            const copy = { ...row };
            for (const f of policy.stripFields)
                delete copy[f];
            return copy;
        });
    }
    // maxChars for string-like outputs
    if (typeof out === "string" && typeof policy.maxChars === "number") {
        out = out.slice(0, policy.maxChars);
    }
    return out;
}
