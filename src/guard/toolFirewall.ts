import type { ToolCall, ToolPolicy, ToolCallDecision } from "./types.js";

export function validateToolCall(call: ToolCall, policies?: Record<string, ToolPolicy>): ToolCallDecision {
  const policy = policies?.[call.name];
  if (!policy) return { allowed: true };

  if (policy.block) return { allowed: false, reason: `Tool "${call.name}" is blocked by policy` };
  if (policy.validateCall) return policy.validateCall(call);
  return { allowed: true };
}

export function sanitizeToolResultPayload(toolName: string, payload: unknown, policy?: ToolPolicy): unknown {
  if (!policy) return payload;

  let out: any = payload;

  // enforce maxRows for array results
  if (Array.isArray(out) && typeof policy.maxRows === "number") {
    out = out.slice(0, policy.maxRows);
  }

  // strip fields for array-of-objects
  if (Array.isArray(out) && policy.stripFields?.length) {
    out = out.map((row) => {
      if (!row || typeof row !== "object") return row;
      const copy: any = { ...(row as any) };
      for (const f of policy.stripFields!) delete copy[f];
      return copy;
    });
  }

  // maxChars for string-like outputs
  if (typeof out === "string" && typeof policy.maxChars === "number") {
    out = out.slice(0, policy.maxChars);
  }

  return out;
}