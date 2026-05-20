/**
 * Synchronous SHA-256 — pure JS, no `node:crypto`.
 *
 * `node:crypto` is unavailable on edge runtimes (Vercel Edge, Cloudflare
 * Workers, Next.js middleware), and Web Crypto's `subtle.digest` is async,
 * which would force every event emit path to become async. A small, standard
 * SHA-256 keeps `hashMatch` synchronous and lets the package run anywhere.
 */
/** Compute the SHA-256 digest of a string and return it as lowercase hex. */
export declare function sha256Hex(input: string): string;
/** A short, stable, non-reversible token for an audit-event value. */
export declare function hashMatch(s: string): string;
export declare function maybeHash(matches: string[], enabled: boolean): string[];
