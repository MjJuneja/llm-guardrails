"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ToolGuard = void 0;
exports.normalizePath = normalizePath;
exports.isPathInside = isPathInside;
exports.isPrivateHost = isPrivateHost;
exports.createFilesystemValidator = createFilesystemValidator;
exports.createSqlValidator = createSqlValidator;
exports.createShellValidator = createShellValidator;
exports.createHttpValidator = createHttpValidator;
exports.createFinancialValidator = createFinancialValidator;
exports.createCustomValidator = createCustomValidator;
/**
 * Orchestrates security validations on tool/function calls before execution.
 */
class ToolGuard {
    globalValidators = [];
    toolSpecificRules = new Map();
    allowlist = null;
    denylist = null;
    defaultAction = "allow";
    constructor(config = {}) {
        if (config.allowlist) {
            this.allowlist = new Set(config.allowlist);
        }
        if (config.denylist) {
            this.denylist = new Set(config.denylist);
        }
        if (config.defaultAction) {
            this.defaultAction = config.defaultAction;
        }
        if (config.validators) {
            this.globalValidators.push(...config.validators);
        }
        if (config.toolRules) {
            for (const [toolName, validators] of Object.entries(config.toolRules)) {
                this.toolSpecificRules.set(toolName, [...validators]);
            }
        }
    }
    /**
     * Registers a new validator. If a toolName is provided, the validator is registered
     * specifically for that tool. Otherwise, it is run globally on all tool calls.
     */
    registerValidator(validator, toolName) {
        if (toolName) {
            const existing = this.toolSpecificRules.get(toolName) || [];
            existing.push(validator);
            this.toolSpecificRules.set(toolName, existing);
        }
        else {
            this.globalValidators.push(validator);
        }
    }
    /**
     * Validates a proposed tool call against all configured allowlists, denylists, and active validators.
     */
    async validate(call) {
        const { name } = call;
        // 1. Check Denylist
        if (this.denylist && this.denylist.has(name)) {
            return {
                action: "block",
                riskScore: 100,
                matchedRules: ["tool_denylist"],
                reason: `Tool "${name}" is blocked by denylist.`,
                validatorName: "ToolGuard"
            };
        }
        // 2. Check Allowlist
        if (this.allowlist && !this.allowlist.has(name)) {
            return {
                action: "block",
                riskScore: 100,
                matchedRules: ["tool_allowlist_violation"],
                reason: `Tool "${name}" is not in the allowlist.`,
                validatorName: "ToolGuard"
            };
        }
        // 3. Gather applicable validators
        const activeValidators = [...this.globalValidators];
        const specific = this.toolSpecificRules.get(name);
        if (specific) {
            activeValidators.push(...specific);
        }
        if (activeValidators.length === 0) {
            return {
                action: this.defaultAction,
                riskScore: 0,
                matchedRules: [],
                reason: `No validators registered. Default action applied.`,
                validatorName: "ToolGuard"
            };
        }
        // Run all validations in parallel (or sequential, since it's promise-based)
        const results = await Promise.all(activeValidators.map(async (v) => {
            try {
                return await v.validate(call);
            }
            catch (err) {
                return {
                    action: "block",
                    riskScore: 100,
                    matchedRules: ["validation_error"],
                    reason: `Validator "${v.name}" threw an error: ${err?.message || err}`,
                    validatorName: v.name
                };
            }
        }));
        // 4. Aggregate results
        let finalAction = "allow";
        let maxRiskScore = 0;
        const matchedRules = [];
        const reasons = [];
        const triggeredValidators = [];
        for (const res of results) {
            // Find the highest severity action: block > require_confirmation > allow
            if (res.action === "block") {
                finalAction = "block";
            }
            else if (res.action === "require_confirmation" && finalAction !== "block") {
                finalAction = "require_confirmation";
            }
            if (res.riskScore > maxRiskScore) {
                maxRiskScore = res.riskScore;
            }
            if (res.matchedRules.length > 0) {
                matchedRules.push(...res.matchedRules);
            }
            if (res.action !== "allow") {
                reasons.push(`${res.validatorName}: ${res.reason}`);
                triggeredValidators.push(res.validatorName);
            }
        }
        const uniqueRules = Array.from(new Set(matchedRules));
        const uniqueValidators = Array.from(new Set(triggeredValidators));
        return {
            action: finalAction,
            riskScore: maxRiskScore,
            matchedRules: uniqueRules,
            reason: reasons.length > 0 ? reasons.join("; ") : "All checks passed.",
            validatorName: uniqueValidators.length > 0 ? uniqueValidators.join(", ") : "ToolGuard"
        };
    }
}
exports.ToolGuard = ToolGuard;
// ==========================================
// Helper functions (Edge runtime compatible)
// ==========================================
function normalizePath(p) {
    let cleaned = p.replace(/\\/g, "/");
    const parts = cleaned.split("/");
    const stack = [];
    const isAbsolute = cleaned.startsWith("/") || /^[a-zA-Z]:/.test(cleaned);
    for (const part of parts) {
        if (part === "." || part === "") {
            continue;
        }
        if (part === "..") {
            if (stack.length > 0 && stack[stack.length - 1] !== "..") {
                stack.pop();
            }
            else if (!isAbsolute) {
                stack.push("..");
            }
        }
        else {
            stack.push(part);
        }
    }
    let result = stack.join("/");
    if (cleaned.startsWith("/")) {
        result = "/" + result;
    }
    return result;
}
function isPathInside(filePath, rootDir) {
    const normFile = normalizePath(filePath);
    const normRoot = normalizePath(rootDir);
    if (normFile === normRoot) {
        return true;
    }
    const separator = normRoot.endsWith("/") ? "" : "/";
    return normFile.startsWith(normRoot + separator);
}
function cleanSql(sql) {
    // Strip block comments /* ... */
    let cleaned = sql.replace(/\/\*[\s\S]*?\*\//g, "");
    // Strip line comments -- ...
    cleaned = cleaned.replace(/--.*$/gm, "");
    // Strip string literals
    cleaned = cleaned.replace(/'([^'\\]|\\.)*'/g, "''");
    cleaned = cleaned.replace(/"([^"\\]|\\.)*"/g, '""');
    cleaned = cleaned.replace(/`([^`\\]|\\.)*`/g, "``");
    return cleaned;
}
function isPrivateHost(host) {
    const lower = host.toLowerCase().trim();
    if (lower === "localhost") {
        return true;
    }
    const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const ip4Match = lower.match(ipv4Regex);
    if (ip4Match) {
        const octets = ip4Match.slice(1).map(Number);
        if (octets.some((o) => o > 255))
            return false;
        const [o1, o2, o3, o4] = octets;
        // Loopback: 127.0.0.0/8
        if (o1 === 127)
            return true;
        // Private Class A: 10.0.0.0/8
        if (o1 === 10)
            return true;
        // Private Class B: 172.16.0.0/12
        if (o1 === 172 && o2 >= 16 && o2 <= 31)
            return true;
        // Private Class C: 192.168.0.0/16
        if (o1 === 192 && o2 === 168)
            return true;
        // Link-local / metadata: 169.254.0.0/16
        if (o1 === 169 && o2 === 254)
            return true;
        // Broadcast & local network
        if (o1 === 0)
            return true;
        if (o1 === 255 && o2 === 255 && o3 === 255 && o4 === 255)
            return true;
    }
    if (lower.includes(":")) {
        const cleanIpv6 = lower.replace(/[\[\]]/g, "");
        // Loopback: ::1
        if (cleanIpv6 === "::1" || cleanIpv6 === "0:0:0:0:0:0:0:1" || cleanIpv6 === "::0.0.0.1") {
            return true;
        }
        // Unique Local Address: fc00::/7
        if (cleanIpv6.startsWith("fc") || cleanIpv6.startsWith("fd")) {
            return true;
        }
        // Link-local: fe80::/10
        if (/^fe[89ab]/i.test(cleanIpv6)) {
            return true;
        }
    }
    return false;
}
function parseUrlSafe(val) {
    try {
        let urlStr = val.trim();
        if (!/^[a-zA-Z]+:\/\//.test(urlStr)) {
            urlStr = "http://" + urlStr;
        }
        return new URL(urlStr);
    }
    catch {
        return null;
    }
}
function findArgRecursive(obj, keys) {
    if (!obj || typeof obj !== "object")
        return null;
    for (const k of keys) {
        if (k in obj) {
            return { key: k, value: obj[k] };
        }
    }
    for (const val of Object.values(obj)) {
        if (val && typeof val === "object") {
            const res = findArgRecursive(val, keys);
            if (res)
                return res;
        }
    }
    return null;
}
function createFilesystemValidator(config = {}) {
    const rootDirs = config.rootDirs || [];
    const allowTraversal = config.allowTraversal ?? false;
    const argNames = config.argNames || ["path", "filePath", "filename", "file", "directory", "dir", "src", "dest"];
    const action = config.actionOnViolation ?? "block";
    const riskScore = config.riskScoreOnViolation ?? 90;
    return {
        name: "filesystem",
        validate(call) {
            const pathArg = findArgRecursive(call.args, argNames);
            if (!pathArg || typeof pathArg.value !== "string") {
                return { action: "allow", riskScore: 0, matchedRules: [], reason: "No path argument detected.", validatorName: "filesystem" };
            }
            const pathStr = pathArg.value;
            // Check Directory Traversal
            if (!allowTraversal) {
                const segments = pathStr.split(/[\/\\]/);
                if (segments.some((seg) => seg === "..")) {
                    return {
                        action,
                        riskScore,
                        matchedRules: ["directory_traversal"],
                        reason: `Directory traversal (..) detected in path: "${pathStr}"`,
                        validatorName: "filesystem"
                    };
                }
            }
            // Check root directory boundary
            if (rootDirs.length > 0) {
                const isInside = rootDirs.some((dir) => isPathInside(pathStr, dir));
                if (!isInside) {
                    return {
                        action,
                        riskScore,
                        matchedRules: ["root_directory_violation"],
                        reason: `Access to path "${pathStr}" is outside configured root directories.`,
                        validatorName: "filesystem"
                    };
                }
            }
            return {
                action: "allow",
                riskScore: 10,
                matchedRules: [],
                reason: "Path validated successfully.",
                validatorName: "filesystem"
            };
        }
    };
}
function createSqlValidator(config = {}) {
    const readOnly = config.readOnly ?? false;
    const allowlist = config.allowlist || [];
    const argNames = config.argNames || ["query", "sql"];
    const action = config.actionOnViolation ?? "block";
    const riskScore = config.riskScoreOnViolation ?? 95;
    return {
        name: "sql",
        validate(call) {
            const queryArg = findArgRecursive(call.args, argNames);
            if (!queryArg || typeof queryArg.value !== "string") {
                return { action: "allow", riskScore: 0, matchedRules: [], reason: "No SQL query argument detected.", validatorName: "sql" };
            }
            const sqlStr = queryArg.value;
            const cleaned = cleanSql(sqlStr);
            // 1. Detect Destructive statements
            const destructiveRegex = /\b(DROP|DELETE|TRUNCATE|ALTER)\b/i;
            if (destructiveRegex.test(cleaned)) {
                return {
                    action,
                    riskScore,
                    matchedRules: ["sql_destructive_statement"],
                    reason: `Destructive SQL statement detected: "${sqlStr}"`,
                    validatorName: "sql"
                };
            }
            // 2. Detect Multiple statements (separated by semicolon)
            const statements = cleaned.split(";").map((s) => s.trim()).filter((s) => s.length > 0);
            if (statements.length > 1) {
                return {
                    action,
                    riskScore,
                    matchedRules: ["sql_multiple_statements"],
                    reason: `Multiple SQL statements separated by semicolons are not allowed.`,
                    validatorName: "sql"
                };
            }
            // 3. Read Only checks
            if (readOnly) {
                const writeRegex = /\b(INSERT|UPDATE|CREATE|REPLACE|GRANT|REVOKE|MERGE|RENAME)\b/i;
                if (writeRegex.test(cleaned)) {
                    // Check if the query is allowlisted despite the write keyword
                    let isAllowlisted = false;
                    if (allowlist.length > 0) {
                        isAllowlisted = allowlist.some((pattern) => {
                            try {
                                const re = new RegExp(pattern, "i");
                                return re.test(sqlStr);
                            }
                            catch {
                                return false;
                            }
                        });
                    }
                    if (!isAllowlisted) {
                        return {
                            action,
                            riskScore,
                            matchedRules: ["sql_read_only_violation"],
                            reason: `Non-read-only SQL keyword detected in read-only mode.`,
                            validatorName: "sql"
                        };
                    }
                }
            }
            return {
                action: "allow",
                riskScore: 20,
                matchedRules: [],
                reason: "SQL query validated successfully.",
                validatorName: "sql"
            };
        }
    };
}
function createShellValidator(config = {}) {
    const customBlocked = config.blockedCommands || [];
    const argNames = config.argNames || ["command", "cmd", "args", "script"];
    const action = config.actionOnViolation ?? "block";
    const riskScore = config.riskScoreOnViolation ?? 98;
    const dangerousShellPatterns = [
        { name: "sudo", re: /\bsudo\b/i },
        { name: "rm_rf", re: /\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\b|\brm\s+-rf\b/i },
        { name: "shutdown", re: /\bshutdown\b/i },
        { name: "reboot", re: /\breboot\b/i },
        { name: "pipe_to_shell", re: /(?:curl|wget|fetch|git\s+clone)\b.*\|\s*(?:bash|sh|zsh|ksh|tcsh|csh)\b/i }
    ];
    return {
        name: "shell",
        validate(call) {
            const commandArg = findArgRecursive(call.args, argNames);
            if (!commandArg || typeof commandArg.value !== "string") {
                return { action: "allow", riskScore: 0, matchedRules: [], reason: "No shell command argument detected.", validatorName: "shell" };
            }
            const cmdStr = commandArg.value;
            // 1. Check default dangerous patterns
            for (const pattern of dangerousShellPatterns) {
                if (pattern.re.test(cmdStr)) {
                    return {
                        action,
                        riskScore,
                        matchedRules: [`shell_${pattern.name}`],
                        reason: `Dangerous shell command pattern "${pattern.name}" matched: "${cmdStr}"`,
                        validatorName: "shell"
                    };
                }
            }
            // 2. Check custom blocked commands
            for (const blocked of customBlocked) {
                const re = new RegExp(`\\b${blocked}\\b`, "i");
                if (re.test(cmdStr)) {
                    return {
                        action,
                        riskScore,
                        matchedRules: ["shell_custom_blocked"],
                        reason: `Blocked shell command "${blocked}" detected.`,
                        validatorName: "shell"
                    };
                }
            }
            return {
                action: "allow",
                riskScore: 30,
                matchedRules: [],
                reason: "Shell command validated successfully.",
                validatorName: "shell"
            };
        }
    };
}
function createHttpValidator(config = {}) {
    const allowlist = config.allowlist || [];
    const denylist = config.denylist || [];
    const blockPrivateIPs = config.blockPrivateIPs ?? true;
    const argNames = config.argNames || ["url", "uri", "endpoint", "link"];
    const action = config.actionOnViolation ?? "block";
    const riskScore = config.riskScoreOnViolation ?? 95;
    function matchesPatterns(host, patterns) {
        return patterns.some((pattern) => {
            const escaped = pattern.replace(/\./g, "\\.").replace(/\*/g, ".*");
            const re = new RegExp(`^${escaped}$`, "i");
            return re.test(host);
        });
    }
    return {
        name: "http",
        validate(call) {
            const urlArg = findArgRecursive(call.args, argNames);
            if (!urlArg || typeof urlArg.value !== "string") {
                return { action: "allow", riskScore: 0, matchedRules: [], reason: "No HTTP URL argument detected.", validatorName: "http" };
            }
            const urlStr = urlArg.value;
            const parsed = parseUrlSafe(urlStr);
            if (!parsed) {
                return {
                    action: "block",
                    riskScore: 80,
                    matchedRules: ["http_invalid_url"],
                    reason: `Invalid URL format: "${urlStr}"`,
                    validatorName: "http"
                };
            }
            const host = parsed.hostname;
            // 1. Block Localhost & Private IP Ranges (SSRF)
            if (blockPrivateIPs && isPrivateHost(host)) {
                return {
                    action,
                    riskScore,
                    matchedRules: ["http_ssrf_risk"],
                    reason: `Access to private or local network host "${host}" is blocked.`,
                    validatorName: "http"
                };
            }
            // 2. Check Denylist
            if (denylist.length > 0 && matchesPatterns(host, denylist)) {
                return {
                    action,
                    riskScore,
                    matchedRules: ["http_denylist_violation"],
                    reason: `Domain "${host}" is blocked by configuration.`,
                    validatorName: "http"
                };
            }
            // 3. Check Allowlist
            if (allowlist.length > 0 && !matchesPatterns(host, allowlist)) {
                return {
                    action,
                    riskScore,
                    matchedRules: ["http_allowlist_violation"],
                    reason: `Domain "${host}" is not in the allowed domains list.`,
                    validatorName: "http"
                };
            }
            return {
                action: "allow",
                riskScore: 10,
                matchedRules: [],
                reason: "HTTP request validated successfully.",
                validatorName: "http"
            };
        }
    };
}
function createFinancialValidator(config) {
    const maxAmount = config.maxAmount;
    const currency = config.currency?.toUpperCase();
    const amountArgNames = config.amountArgNames || ["amount", "value", "price", "transferAmount", "refundAmount", "paymentAmount"];
    const currencyArgNames = config.currencyArgNames || ["currency", "unit"];
    const action = config.actionOnViolation ?? "block";
    const riskScore = config.riskScoreOnViolation ?? 90;
    return {
        name: "financial",
        validate(call) {
            const amountArg = findArgRecursive(call.args, amountArgNames);
            if (!amountArg) {
                return { action: "allow", riskScore: 0, matchedRules: [], reason: "No financial amount detected.", validatorName: "financial" };
            }
            const rawAmount = Number(amountArg.value);
            if (isNaN(rawAmount)) {
                return {
                    action: "block",
                    riskScore: 80,
                    matchedRules: ["financial_invalid_amount"],
                    reason: `Invalid financial amount value: "${amountArg.value}"`,
                    validatorName: "financial"
                };
            }
            // Validate Currency if configured
            if (currency) {
                const currencyArg = findArgRecursive(call.args, currencyArgNames);
                if (currencyArg) {
                    const callCurrency = String(currencyArg.value).toUpperCase();
                    if (callCurrency !== currency) {
                        return {
                            action,
                            riskScore,
                            matchedRules: ["financial_currency_mismatch"],
                            reason: `Currency mismatch: Expected "${currency}" but got "${callCurrency}".`,
                            validatorName: "financial"
                        };
                    }
                }
            }
            // Check limit
            if (rawAmount > maxAmount) {
                return {
                    action,
                    riskScore,
                    matchedRules: ["financial_limit_exceeded"],
                    reason: `Financial amount of ${rawAmount} exceeds the maximum limit of ${maxAmount}.`,
                    validatorName: "financial"
                };
            }
            return {
                action: "allow",
                riskScore: 10,
                matchedRules: [],
                reason: "Financial validation passed successfully.",
                validatorName: "financial"
            };
        }
    };
}
function createCustomValidator(name, fn) {
    return {
        name,
        validate(call) {
            return fn(call);
        }
    };
}
