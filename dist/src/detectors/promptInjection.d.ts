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
/** Return the substrings that look like prompt-injection / jailbreak attempts. */
export declare function detectPromptInjection(text: string): string[];
