export function detectSecrets(text: string): string[] {
  const matches: string[] = [];

  const patterns: RegExp[] = [
    // AWS Access Key ID (typical)
    /\bAKIA[0-9A-Z]{16}\b/g,
    // AWS Secret Access Key (very loose)
    /\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*([A-Za-z0-9/+=]{40})\b/g,
    // JWT
    /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,
    // OpenAI-like keys (loose)
    /\b(sk|rk|pk)-[A-Za-z0-9]{20,}\b/g,
    // Private key blocks
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    // DB URLs
    /\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^\s'"]+/gi
  ];

  for (const re of patterns) {
    const found = text.match(re);
    if (found) matches.push(...found);
  }

  return dedupe(matches);
}

function dedupe(a: string[]) {
  return Array.from(new Set(a));
}

export function redactSecrets(text: string): string {
  let out = text;
  for (const m of detectSecrets(text)) {
    out = out.split(m).join("[SECRET]");
  }
  return out;
}