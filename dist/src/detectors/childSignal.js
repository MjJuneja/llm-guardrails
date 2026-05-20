"use strict";
/**
 * Child-signal detector.
 *
 * Heuristic detection of content that involves a minor. Under the DPDP Act
 * (s. 9) processing a child's data needs verifiable parental consent, and
 * tracking / targeted advertising at children is prohibited — so an LLM
 * pipeline needs to know when a child may be involved.
 *
 * This is deliberately a *signal*, not a verdict: it is heuristic and will
 * have false positives ("my kid brother"). It is opt-in (detectChildSignals)
 * and, unless dpdpEnforce is set, only flags via an audit event.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectChildSignals = detectChildSignals;
const RELATION_RE = /\bmy (?:son|daughter|child|children|kid|kids|toddler|newborn|infant)\b/gi;
const MINOR_TERM_RE = /\b(?:under[\s-]?18|underage|minors?)\b/gi;
const SCHOOL_RE = /\b(?:(?:in\s+)?(?:grade|class|standard)\s+(?:[1-9]|1[0-2])|[1-9](?:st|nd|rd|th)\s+graders?|pre[\s-]?school|kindergarten|nursery school|elementary school|middle school|high school)\b/gi;
// Captures an age in one of three shapes; the numeric check happens in code.
const AGE_RE = /\b(?:(\d{1,2})\s*(?:years?|yrs?)\s*old|aged?\s*[:=]?\s*(\d{1,2})\b|(?:i am|i'm)\s+(\d{1,2})\b)/gi;
const CHILD_AGE_CEILING = 18;
/**
 * Return the substrings that signal a minor may be involved. Age-based matches
 * are only included when the captured age is below 18.
 */
function detectChildSignals(text) {
    const matches = [];
    for (const re of [RELATION_RE, MINOR_TERM_RE, SCHOOL_RE]) {
        const found = text.match(re);
        if (found)
            matches.push(...found);
    }
    const ageRe = new RegExp(AGE_RE.source, AGE_RE.flags);
    let match;
    while ((match = ageRe.exec(text)) !== null) {
        const ageStr = match[1] ?? match[2] ?? match[3];
        const age = Number(ageStr);
        if (Number.isFinite(age) && age >= 1 && age < CHILD_AGE_CEILING) {
            matches.push(match[0]);
        }
    }
    return Array.from(new Set(matches));
}
