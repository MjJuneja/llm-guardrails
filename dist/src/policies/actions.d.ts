import type { GuardAction, Severity } from "../guard/types.js";
export type Detection = {
    detector: string;
    matches: string[];
    severity: Severity;
    action: GuardAction;
};
export type PolicyDecision = {
    finalAction: GuardAction;
    reasons: Detection[];
};
export declare function decide(detections: Detection[]): PolicyDecision;
