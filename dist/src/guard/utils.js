"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nowIso = nowIso;
exports.emit = emit;
exports.unique = unique;
exports.clipMatches = clipMatches;
exports.applyRedactions = applyRedactions;
exports.filterAllowlisted = filterAllowlisted;
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
/**
 * Drop detector matches that are themselves allowlisted.
 *
 * This is a per-match filter, not a whole-text bypass: an allowlisted token no
 * longer disables scanning for the rest of the message. The global flag is
 * stripped before `.test()` so matching is not stateful across calls.
 */
function filterAllowlisted(matches, allowPatterns) {
    if (!allowPatterns || allowPatterns.length === 0)
        return matches;
    return matches.filter((m) => !allowPatterns.some((re) => {
        const r = re.global ? new RegExp(re.source, re.flags.replace("g", "")) : re;
        return r.test(m);
    }));
}
