/**
 * Indian PII detectors.
 *
 * Aadhaar and GSTIN are validated with their published checksums (Verhoeff and
 * the GSTIN mod-36 scheme). Checksum validation is what keeps these precise — a
 * regex alone would flag any 12-digit number as an Aadhaar.
 */
/**
 * Validate a 12-digit Aadhaar number (the trailing digit is its Verhoeff
 * check digit). Input must be digits only.
 */
export declare function isValidAadhaar(digits: string): boolean;
/** Validate a 15-character GSTIN against its mod-36 check digit. */
export declare function isValidGstin(gstin: string): boolean;
export type IndianPIIType = "aadhaar" | "pan" | "gstin" | "ifsc" | "voterId" | "indianMobile" | "upiId";
export type IndianPIIDetectionItem = {
    type: IndianPIIType;
    count: number;
    items: string[];
};
export type IndianPIIDetection = {
    hasPII: boolean;
    detectedItems: IndianPIIDetectionItem[];
};
/** Detect Indian PII, dropping regex matches that fail their checksum. */
export declare function detectIndianPII(text: string): IndianPIIDetection;
/** Redact Indian PII. Matches that fail their checksum are left untouched. */
export declare function redactIndianPII(text: string): string;
