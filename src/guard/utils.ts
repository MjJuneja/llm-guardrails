import type { GuardEvent } from "./types.js";

export function nowIso() {
  return new Date().toISOString();
}

export function emit(events: GuardEvent[], onEvent: ((e: GuardEvent) => void) | undefined, e: GuardEvent) {
  events.push(e);
  onEvent?.(e);
}

export function unique(arr: string[]) {
  return Array.from(new Set(arr));
}

export function clipMatches(matches: string[], max = 8, maxLen = 64) {
  const clipped = matches.slice(0, max).map((m) => (m.length > maxLen ? m.slice(0, maxLen) + "…" : m));
  return clipped;
}

export function applyRedactions(input: string, redactions: Array<{ start: number; end: number; replacement: string }>) {
  if (redactions.length === 0) return input;
  // apply from back to front
  const sorted = [...redactions].sort((a, b) => b.start - a.start);
  let out = input;
  for (const r of sorted) {
    out = out.slice(0, r.start) + r.replacement + out.slice(r.end);
  }
  return out;
}

export function passesAllowlist(text: string, allowPatterns?: RegExp[]) {
  if (!allowPatterns || allowPatterns.length === 0) return false;
  return allowPatterns.some((re) => re.test(text));
}