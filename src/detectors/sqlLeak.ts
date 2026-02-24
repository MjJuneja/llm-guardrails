export function detectSQLLeak(text: string): string[] {
  const matches: string[] = [];

  const patterns: RegExp[] = [
    // Classic SQL keywords
    /\bSELECT\b[\s\S]{0,400}?\bFROM\b[\s\S]{0,200}?(?:;|$)/gi,
    /\bINSERT\s+INTO\b[\s\S]{0,250}?(?:;|$)/gi,
    /\bUPDATE\b[\s\S]{0,250}?\bSET\b[\s\S]{0,250}?(?:;|$)/gi,
    /\bDELETE\s+FROM\b[\s\S]{0,250}?(?:;|$)/gi,
    // schema/table mentions
    /\b(?:table|tables|schema|schemas|column|columns)\s*[:=]\s*[A-Za-z0-9_.`"-]{2,}/gi,
    // postgres/mysql system schemas
    /\b(?:information_schema|pg_catalog)\b/gi
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

export function redactSQLLeak(text: string): string {
  let out = text;
  for (const m of detectSQLLeak(text)) {
    out = out.split(m).join("[REDACTED_SQL]");
  }
  return out;
}