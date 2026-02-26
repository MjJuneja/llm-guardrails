"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectPromptLeak = detectPromptLeak;
exports.redactPromptLeak = redactPromptLeak;
function detectPromptLeak(text) {
    const matches = [];
    const patterns = [
        /\b(system prompt|developer message|hidden instructions|internal instructions)\b/gi,
        /\bhere(?:'s| is) (?:the )?(?:system|developer) prompt\b/gi,
        /\bI was instructed to\b/gi,
        /\btool output\b/gi,
        /\bfunction call\b/gi,
        /\bchain of thought\b/gi
    ];
    for (const re of patterns) {
        const found = text.match(re);
        if (found)
            matches.push(...found);
    }
    return dedupe(matches);
}
function dedupe(a) {
    return Array.from(new Set(a));
}
function redactPromptLeak(text) {
    // v1: not redaction, better to rewrite/block. Keep for completeness.
    let out = text;
    for (const m of detectPromptLeak(text)) {
        out = out.split(m).join("[REDACTED_INTERNAL]");
    }
    return out;
}
