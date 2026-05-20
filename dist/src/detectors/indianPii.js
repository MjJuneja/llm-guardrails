"use strict";
/**
 * Indian PII detectors.
 *
 * Aadhaar and GSTIN are validated with their published checksums (Verhoeff and
 * the GSTIN mod-36 scheme). Checksum validation is what keeps these precise — a
 * regex alone would flag any 12-digit number as an Aadhaar.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.isValidAadhaar = isValidAadhaar;
exports.isValidGstin = isValidGstin;
exports.detectIndianPII = detectIndianPII;
exports.redactIndianPII = redactIndianPII;
// Verhoeff dihedral-group tables (used by Aadhaar).
const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
/**
 * Validate a 12-digit Aadhaar number (the trailing digit is its Verhoeff
 * check digit). Input must be digits only.
 */
function isValidAadhaar(digits) {
    if (!/^[2-9][0-9]{11}$/.test(digits))
        return false;
    let c = 0;
    const reversed = digits.split("").reverse();
    for (let i = 0; i < reversed.length; i++) {
        const digit = Number(reversed[i]);
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
    }
    return c === 0;
}
const GSTIN_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const GSTIN_FORMAT = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]$/;
/** Validate a 15-character GSTIN against its mod-36 check digit. */
function isValidGstin(gstin) {
    if (!GSTIN_FORMAT.test(gstin))
        return false;
    let sum = 0;
    for (let i = 0; i < 14; i++) {
        const value = GSTIN_CHARSET.indexOf(gstin[i]);
        if (value < 0)
            return false;
        const factor = i % 2 === 0 ? 1 : 2;
        const product = value * factor;
        sum += Math.floor(product / 36) + (product % 36);
    }
    const check = (36 - (sum % 36)) % 36;
    return GSTIN_CHARSET[check] === gstin[14];
}
// Order matters: GSTIN before PAN (a GSTIN contains a PAN substring), and
// Aadhaar before the mobile number so redaction labels each correctly.
const INDIAN_PII_PATTERNS = [
    {
        type: "aadhaar",
        re: /\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/g,
        replacement: "[Aadhaar removed]",
        validate: (m) => isValidAadhaar(m.replace(/\D/g, "")),
    },
    {
        type: "gstin",
        re: /\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]\b/g,
        replacement: "[GSTIN removed]",
        validate: isValidGstin,
    },
    {
        // 4th char is the holder type (one of A B C F G H J L P T).
        type: "pan",
        re: /\b[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z]\b/g,
        replacement: "[PAN removed]",
    },
    {
        type: "ifsc",
        re: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
        replacement: "[IFSC removed]",
    },
    {
        type: "voterId",
        re: /\b[A-Z]{3}[0-9]{7}\b/g,
        replacement: "[Voter ID removed]",
    },
    {
        type: "indianMobile",
        re: /(?<![0-9])(?:\+?91[\s-]?)?[6-9][0-9]{9}(?![0-9])/g,
        replacement: "[mobile removed]",
    },
    {
        type: "upiId",
        re: /\b[a-zA-Z0-9.\-_]{2,}@(?:oksbi|okhdfcbank|okaxis|okicici|okbizaxis|ybl|paytm|apl|axl|ibl|aubl|sbi|hdfcbank|icici|axisbank|upi|airtel|fbl)\b/g,
        replacement: "[UPI ID removed]",
    },
];
/** Detect Indian PII, dropping regex matches that fail their checksum. */
function detectIndianPII(text) {
    const detectedItems = [];
    for (const pattern of INDIAN_PII_PATTERNS) {
        const re = new RegExp(pattern.re.source, pattern.re.flags);
        const items = [];
        let match;
        while ((match = re.exec(text)) !== null) {
            const value = match[0];
            if (pattern.validate && !pattern.validate(value))
                continue;
            items.push(value);
        }
        if (items.length) {
            detectedItems.push({ type: pattern.type, count: items.length, items });
        }
    }
    return { hasPII: detectedItems.length > 0, detectedItems };
}
/** Redact Indian PII. Matches that fail their checksum are left untouched. */
function redactIndianPII(text) {
    let out = text;
    for (const pattern of INDIAN_PII_PATTERNS) {
        const re = new RegExp(pattern.re.source, pattern.re.flags);
        out = out.replace(re, (match) => {
            if (pattern.validate && !pattern.validate(match))
                return match;
            return pattern.replacement;
        });
    }
    return out;
}
