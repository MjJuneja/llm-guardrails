"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nowIso = nowIso;
exports.emit = emit;
exports.unique = unique;
exports.clipMatches = clipMatches;
exports.applyRedactions = applyRedactions;
exports.passesAllowlist = passesAllowlist;
function nowIso() {
    return new Date().toISOString();
}
function emit(events, onEvent, e) {
    events.push(e);
    onEvent?.(e);
}
function unique(arr) {
    return Array.from(new Set(arr));
}
function clipMatches(matches, max = 8, maxLen = 64) {
    const clipped = matches.slice(0, max).map((m) => (m.length > maxLen ? m.slice(0, maxLen) + "…" : m));
    return clipped;
}
function applyRedactions(input, redactions) {
    if (redactions.length === 0)
        return input;
    // apply from back to front
    const sorted = [...redactions].sort((a, b) => b.start - a.start);
    let out = input;
    for (const r of sorted) {
        out = out.slice(0, r.start) + r.replacement + out.slice(r.end);
    }
    return out;
}
function passesAllowlist(text, allowPatterns) {
    if (!allowPatterns || allowPatterns.length === 0)
        return false;
    return allowPatterns.some((re) => re.test(text));
}
