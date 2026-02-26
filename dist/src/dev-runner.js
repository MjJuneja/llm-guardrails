"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const createGuardrails_js_1 = require("./guard/createGuardrails.js");
const toolPolicies_js_1 = require("./policies/toolPolicies.js");
const guard = (0, createGuardrails_js_1.createGuardrails)({
    toolPolicies: toolPolicies_js_1.defaultToolPolicies,
    onEvent: (e) => console.log("[EVENT]", e)
});
