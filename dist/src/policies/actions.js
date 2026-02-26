"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decide = decide;
// Simple "highest priority wins" policy:
// BLOCK > REWRITE > REDACT > ALLOW
const priority = {
    ALLOW: 0,
    REDACT: 1,
    REWRITE: 2,
    BLOCK: 3
};
function decide(detections) {
    if (detections.length === 0)
        return { finalAction: "ALLOW", reasons: [] };
    let final = "ALLOW";
    for (const d of detections) {
        if (priority[d.action] > priority[final])
            final = d.action;
    }
    return { finalAction: final, reasons: detections };
}
