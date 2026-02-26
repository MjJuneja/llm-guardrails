import type { ToolCall, ToolPolicy, ToolCallDecision } from "./types.js";
export declare function validateToolCall(call: ToolCall, policies?: Record<string, ToolPolicy>): ToolCallDecision;
export declare function sanitizeToolResultPayload(toolName: string, payload: unknown, policy?: ToolPolicy): unknown;
