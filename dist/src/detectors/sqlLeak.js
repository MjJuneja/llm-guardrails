"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectSQLLeak = detectSQLLeak;
exports.redactSQLLeak = redactSQLLeak;
function detectSQLLeak(text) {
    const matches = [];
    const patterns = [
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
        if (found)
            matches.push(...found);
    }
    return dedupe(matches);
}
function dedupe(a) {
    return Array.from(new Set(a));
}
function redactSQLLeak(text) {
    let out = text;
    for (const m of detectSQLLeak(text)) {
        out = out.split(m).join("[REDACTED_SQL]");
    }
    return out;
}
