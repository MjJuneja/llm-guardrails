import type { GuardEvent } from "./types.js";
export declare function nowIso(): string;
export declare function emit(events: GuardEvent[], onEvent: ((e: GuardEvent) => void) | undefined, e: GuardEvent): void;
export declare function unique(arr: string[]): string[];
export declare function clipMatches(matches: string[], max?: number, maxLen?: number): string[];
export declare function applyRedactions(input: string, redactions: Array<{
    start: number;
    end: number;
    replacement: string;
}>): string;
export declare function passesAllowlist(text: string, allowPatterns?: RegExp[]): boolean;
