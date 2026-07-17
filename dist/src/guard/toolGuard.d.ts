export type ToolValidationAction = "allow" | "block" | "require_confirmation";
export type ToolValidationResult = {
    action: ToolValidationAction;
    riskScore: number;
    matchedRules: string[];
    reason: string;
    validatorName: string;
};
import type { ToolCall } from "./types.js";
export interface ToolValidator {
    name: string;
    validate(call: ToolCall): ToolValidationResult | Promise<ToolValidationResult>;
}
export type ToolGuardConfig = {
    allowlist?: string[];
    denylist?: string[];
    defaultAction?: ToolValidationAction;
    validators?: ToolValidator[];
    toolRules?: Record<string, ToolValidator[]>;
};
/**
 * Orchestrates security validations on tool/function calls before execution.
 */
export declare class ToolGuard {
    private globalValidators;
    private toolSpecificRules;
    private allowlist;
    private denylist;
    private defaultAction;
    constructor(config?: ToolGuardConfig);
    /**
     * Registers a new validator. If a toolName is provided, the validator is registered
     * specifically for that tool. Otherwise, it is run globally on all tool calls.
     */
    registerValidator(validator: ToolValidator, toolName?: string): void;
    /**
     * Validates a proposed tool call against all configured allowlists, denylists, and active validators.
     */
    validate(call: ToolCall): Promise<ToolValidationResult>;
}
export declare function normalizePath(p: string): string;
export declare function isPathInside(filePath: string, rootDir: string): boolean;
export declare function isPrivateHost(host: string): boolean;
export type FilesystemValidatorConfig = {
    rootDirs?: string[];
    allowTraversal?: boolean;
    argNames?: string[];
    actionOnViolation?: ToolValidationAction;
    riskScoreOnViolation?: number;
};
export declare function createFilesystemValidator(config?: FilesystemValidatorConfig): ToolValidator;
export type SqlValidatorConfig = {
    readOnly?: boolean;
    allowlist?: string[];
    argNames?: string[];
    actionOnViolation?: ToolValidationAction;
    riskScoreOnViolation?: number;
};
export declare function createSqlValidator(config?: SqlValidatorConfig): ToolValidator;
export type ShellValidatorConfig = {
    blockedCommands?: string[];
    argNames?: string[];
    actionOnViolation?: ToolValidationAction;
    riskScoreOnViolation?: number;
};
export declare function createShellValidator(config?: ShellValidatorConfig): ToolValidator;
export type HttpValidatorConfig = {
    allowlist?: string[];
    denylist?: string[];
    blockPrivateIPs?: boolean;
    argNames?: string[];
    actionOnViolation?: ToolValidationAction;
    riskScoreOnViolation?: number;
};
export declare function createHttpValidator(config?: HttpValidatorConfig): ToolValidator;
export type FinancialValidatorConfig = {
    maxAmount: number;
    currency?: string;
    amountArgNames?: string[];
    currencyArgNames?: string[];
    actionOnViolation?: ToolValidationAction;
    riskScoreOnViolation?: number;
};
export declare function createFinancialValidator(config: FinancialValidatorConfig): ToolValidator;
export type CustomValidatorFn = (call: ToolCall) => ToolValidationResult | Promise<ToolValidationResult>;
export declare function createCustomValidator(name: string, fn: CustomValidatorFn): ToolValidator;
