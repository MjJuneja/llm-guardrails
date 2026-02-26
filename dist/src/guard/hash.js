"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashMatch = hashMatch;
exports.maybeHash = maybeHash;
const node_crypto_1 = require("node:crypto");
function hashMatch(s) {
    return (0, node_crypto_1.createHash)("sha256").update(s).digest("hex").slice(0, 16);
}
function maybeHash(matches, enabled) {
    if (!enabled)
        return matches;
    return matches.map(hashMatch);
}
