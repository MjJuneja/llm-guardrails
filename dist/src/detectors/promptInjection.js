"use strict";
/**
 * Prompt-injection / jailbreak detector (input side).
 *
 * Heuristically flags attempts to override the system prompt, extract hidden
 * instructions, or jailbreak the model. This complements `promptLeak`, which
 * runs on the output side — this one runs on untrusted input (user messages
 * and, importantly, RAG context, where indirect injection hides).
 *
 * It is heuristic and opt-in (`blockPromptInjection`). Expect occasional false
 * positives on legitimate text that quotes these phrases.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectPromptInjection = detectPromptInjection;
const INJECTION_PATTERNS = [
    // "ignore previous instructions" and variants
    /\bignore (?:all |any |the )?(?:previous|prior|above|earlier|preceding) (?:instructions?|prompts?|messages?|context|rules?)\b/gi,
    /\bdisregard (?:all |any |the )?(?:previous|prior|above|earlier|system) (?:instructions?|prompts?|rules?|guidelines?)\b/gi,
    /\bforget (?:all |everything|your|the|previous|prior) ?(?:previous |prior )?(?:instructions?|rules?|context|training|guidelines?)\b/gi,
    // attempts to extract the system / developer prompt
    /\b(?:reveal|show|print|repeat|expose|leak|display|output|tell me) (?:me )?(?:your |the )?(?:system|developer|initial|original|hidden) (?:prompt|instructions?|message)\b/gi,
    /\bwhat (?:are|were) your (?:original |initial |system )?instructions\b/gi,
    // role / persona override
    /\b(?:you are|act|behave|pretend to be|roleplay as|simulate) (?:now )?(?:a |an )?(?:DAN|jailbroken|unrestricted|unfiltered|uncensored)\b/gi,
    /\bdo anything now\b/gi,
    // mode escalation
    /\b(?:developer|debug|god|admin|sudo|root) mode\b/gi,
    // disabling safety
    /\b(?:bypass|override|disable|turn off|ignore|remove) (?:your |the |all )?(?:safety|security|content|guard ?rails?|restrictions?|guidelines?|filters?|policies)\b/gi,
    // injected instruction blocks
    /\bnew (?:instructions?|system prompt|rules?|directive)\s*[:=]/gi,
    /^\s*(?:system|assistant)\s*[:：]/gim,
];
/** Return the substrings that look like prompt-injection / jailbreak attempts. */
function detectPromptInjection(text) {
    const matches = [];
    for (const re of INJECTION_PATTERNS) {
        const found = text.match(re);
        if (found)
            matches.push(...found.map((m) => m.trim()));
    }
    return Array.from(new Set(matches));
}
