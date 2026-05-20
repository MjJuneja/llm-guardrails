import type { GuardEvent } from "./types.js";
export declare function nowIso(): string;
export declare function emit(events: GuardEvent[], onEvent: ((e: GuardEvent) => void) | undefined, e: GuardEvent): void;
export declare function unique(arr: string[]): string[];
/** Length of the longest common prefix of two strings. */
export declare function commonPrefixLen(a: string, b: string): number;
export declare function clipMatches(matches: string[], max?: number, maxLen?: number): string[];
export declare function applyRedactions(input: string, redactions: Array<{
    start: number;
    end: number;
    replacement: string;
}>): string;
/**
 * Drop detector matches that are themselves allowlisted.
 *
 * This is a per-match filter, not a whole-text bypass: an allowlisted token no
 * longer disables scanning for the rest of the message. The global flag is
 * stripped before `.test()` so matching is not stateful across calls.
 */
export declare function filterAllowlisted(matches: string[], allowPatterns?: RegExp[]): string[];
