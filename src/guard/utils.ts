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

/** Length of the longest common prefix of two strings. */
export function commonPrefixLen(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  let i = 0;
  while (i < n && a[i] === b[i]) i++;
  return i;
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

/**
 * Drop detector matches that are themselves allowlisted.
 *
 * This is a per-match filter, not a whole-text bypass: an allowlisted token no
 * longer disables scanning for the rest of the message. The global flag is
 * stripped before `.test()` so matching is not stateful across calls.
 */
export function filterAllowlisted(matches: string[], allowPatterns?: RegExp[]) {
  if (!allowPatterns || allowPatterns.length === 0) return matches;
  return matches.filter(
    (m) =>
      !allowPatterns.some((re) => {
        const r = re.global ? new RegExp(re.source, re.flags.replace("g", "")) : re;
        return r.test(m);
      }),
  );
}