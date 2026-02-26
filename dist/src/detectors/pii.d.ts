declare function redactPII(text: string, options?: {}): string;
declare function redactPIIDetailed(text: string, options?: Record<string, any>): {
    cleanedText: string;
    removedItems: {
        type: string;
        count: number;
        items: string[];
        description: string;
    }[];
    originalLength: number;
    cleanedLength: number;
    reductionPercentage: number;
};
declare function detectPII(text: string, options?: Record<string, any>): {
    text: string;
    detectedItems: {
        type: string;
        count: number;
        items: string[];
        positions: {
            start: number;
            end: number;
            value: string;
        }[];
        description: string;
    }[];
    hasPII: boolean;
    totalMatches: number;
    types: string[];
};
declare function analyzePII(text: string, options?: {}): {
    original: {
        text: string;
        length: number;
        wordCount: number;
    };
    cleaned: {
        text: string;
        length: number;
        wordCount: number;
    };
    pii: {
        detected: {
            type: string;
            count: number;
            items: string[];
            positions: {
                start: number;
                end: number;
                value: string;
            }[];
            description: string;
        }[];
        removed: {
            type: string;
            count: number;
            items: string[];
            description: string;
        }[];
        totalCount: number;
        types: string[];
        reductionPercentage: number;
    };
    risk: {
        level: string;
        score: any;
    };
};
declare function validatePIICompliance(text: string, options?: {}): {
    isCompliant: boolean;
    violations: {
        type: string;
        count: number;
        items: string[];
        positions: {
            start: number;
            end: number;
            value: string;
        }[];
        description: string;
    }[];
    violationCount: number;
    riskLevel: string;
    riskScore: any;
    recommendations: string[];
};
declare function processBatch(texts: string[], options?: {}): ({
    cleanedText: string;
    removedItems: {
        type: string;
        count: number;
        items: string[];
        description: string;
    }[];
    originalLength: number;
    cleanedLength: number;
    reductionPercentage: number;
    index: number;
    success: boolean;
    error?: undefined;
    originalText?: undefined;
} | {
    index: number;
    success: boolean;
    error: string;
    originalText: string;
})[];
declare function getAvailableTypes(): {
    type: string;
    description: string;
    defaultReplacement: string;
}[];
declare function createCustomPattern(type: string, pattern: RegExp, replacement: string, description: string): {
    [type]: {
        pattern: RegExp;
        replacement: string;
        description: string;
    };
};
export { redactPII, redactPIIDetailed, detectPII, analyzePII, validatePIICompliance, processBatch, getAvailableTypes, createCustomPattern };
export default redactPII;
