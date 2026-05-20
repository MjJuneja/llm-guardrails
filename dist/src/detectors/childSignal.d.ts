/**
 * Child-signal detector.
 *
 * Heuristic detection of content that involves a minor. Under the DPDP Act
 * (s. 9) processing a child's data needs verifiable parental consent, and
 * tracking / targeted advertising at children is prohibited — so an LLM
 * pipeline needs to know when a child may be involved.
 *
 * This is deliberately a *signal*, not a verdict: it is heuristic and will
 * have false positives ("my kid brother"). It is opt-in (detectChildSignals)
 * and, unless dpdpEnforce is set, only flags via an audit event.
 */
/**
 * Return the substrings that signal a minor may be involved. Age-based matches
 * are only included when the captured age is below 18.
 */
export declare function detectChildSignals(text: string): string[];
