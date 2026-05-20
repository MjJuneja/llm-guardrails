const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  // 1) Private key blocks (PEM / OpenSSH) – strongest signals
  { name: "pem_private_key", re: /-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY-----[\s\S]*?-----END (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY-----/g },
  { name: "openssh_private_key", re: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g },

  // 2) Public-key lines (not always secret, but often should not be leaked in answers)
  // Keep as "medium" if you want; many teams still redact these to be safe.
  { name: "ssh_public_key", re: /\bssh-(?:rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{50,}(?:\s+\S+)?/g },

  // 3) JWT / Bearer tokens
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: "bearer_token", re: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/gi },

  // 4) Cloud/API keys (common)
  { name: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "aws_secret_key_hint", re: /\baws_secret_access_key\b\s*[:=]\s*["']?[A-Za-z0-9/+=]{30,}["']?/gi },

  // 5) Generic key/value secrets (THIS will catch rsa_key=SECRET)
  // - catches: rsa_key=..., private_key: ..., apiKey=..., token=..., secret=...
  // - avoids very short values
  // The keyword alternation is grouped so the `[:=] value` requirement applies
  // to every keyword. Without the group, `|` precedence attached it only to the
  // last branch, so bare words ("secret", "password") matched anywhere.
  { name: "generic_kv_secret", re: /\b(?:(?:rsa|dsa|ecdsa|ed25519)?_?(?:private_?)?key|api_?key|apikey|access_?key|secret|token|pass(?:word)?|pwd|client_?secret|refresh_?token)\b\s*[:=]\s*["']?[^\s"']{6,}["']?/gi },

  // 6) PEM-ish base64 blobs that often indicate keys/certs (optional, conservative)
  // { name: "base64_blob", re: /\b[A-Za-z0-9+/]{120,}={0,2}\b/g },
];

export function detectSecrets(text: string): string[] {
  const matches: string[] = [];
  for (const { re } of SECRET_PATTERNS) {
    const found = text.match(re);
    if (found) matches.push(...found);
  }

  // de-dupe
  return Array.from(new Set(matches));
}

export function redactSecrets(text: string, replacement = "[secret removed]"): string {
  let out = text;
  for (const { name, re } of SECRET_PATTERNS) {
    out = out.replace(re, (m) => {
      // preserve key name for debugging readability for kv secrets
      if (name === "generic_kv_secret") {
        // normalize to "key=[secret removed]"
        const idx = m.indexOf(":") >= 0 ? m.indexOf(":") : m.indexOf("=");
        if (idx > 0) return m.slice(0, idx + 1) + " " + replacement;
      }
      return replacement;
    });
  }
  return out;
}