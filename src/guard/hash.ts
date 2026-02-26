import { createHash } from "node:crypto";

export function hashMatch(s: string) {
  return createHash("sha256").update(s).digest("hex").slice(0, 16);
}

export function maybeHash(matches: string[], enabled: boolean) {
  if (!enabled) return matches;
  return matches.map(hashMatch);
}