export function detectPromptLeak(text: string): string[] {
  const matches: string[] = [];

  const patterns: RegExp[] = [
    /\b(system prompt|developer message|hidden instructions|internal instructions)\b/gi,
    /\bhere(?:'s| is) (?:the )?(?:system|developer) prompt\b/gi,
    /\bI was instructed to\b/gi,
    /\btool output\b/gi,
    /\bfunction call\b/gi,
    /\bchain of thought\b/gi
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

export function redactPromptLeak(text: string): string {
  // v1: not redaction, better to rewrite/block. Keep for completeness.
  let out = text;
  for (const m of detectPromptLeak(text)) {
    out = out.split(m).join("[REDACTED_INTERNAL]");
  }
  return out;
}