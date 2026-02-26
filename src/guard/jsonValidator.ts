import type { OutputJsonValidator } from "./types.js";

export const defaultAnswerJsonValidator: OutputJsonValidator = (text: string) => {
  let obj: any;
  try {
    obj = JSON.parse(text);
  } catch {
    return { ok: false, error: "Response is not valid JSON" };
  }

  if (!obj || typeof obj !== "object") return { ok: false, error: "JSON must be an object" };
  if (typeof obj.answer !== "string" || obj.answer.trim().length === 0) return { ok: false, error: "`answer` must be a non-empty string" };

  if (obj.sources !== undefined && !Array.isArray(obj.sources)) return { ok: false, error: "`sources` must be an array" };
  if (obj.confidence !== undefined && typeof obj.confidence !== "number") return { ok: false, error: "`confidence` must be a number" };

  return { ok: true, value: obj };
};