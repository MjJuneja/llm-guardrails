// Detection benchmark for @mjjuneja/llm-guardrails.
//
// Runs the detectors over the labelled corpus and reports per-tag precision,
// recall, and F1. Run with `npm run benchmark` (it builds first).

import { corpus } from "./corpus.mjs";
import { detectPII } from "../dist/src/detectors/pii.js";
import { detectIndianPII } from "../dist/src/detectors/indianPii.js";
import { detectSecrets } from "../dist/src/detectors/secrets.js";
import { detectPromptInjection } from "../dist/src/detectors/promptInjection.js";
import { detectChildSignals } from "../dist/src/detectors/childSignal.js";

const FOCUS = [
  "email",
  "phone",
  "creditCard",
  "bankAccount",
  "aadhaar",
  "pan",
  "gstin",
  "secret",
  "promptInjection",
  "childSignal",
];

function detectTags(text) {
  const tags = new Set();
  for (const t of detectPII(text).types) tags.add(t);
  for (const item of detectIndianPII(text).detectedItems) tags.add(item.type);
  if (detectSecrets(text).length) tags.add("secret");
  if (detectPromptInjection(text).length) tags.add("promptInjection");
  if (detectChildSignals(text).length) tags.add("childSignal");
  return tags;
}

const stats = {};
for (const tag of FOCUS) stats[tag] = { tp: 0, fp: 0, fn: 0 };

const misses = [];
for (const c of corpus) {
  const detected = detectTags(c.text);
  const expected = new Set(c.expect);
  for (const tag of FOCUS) {
    const d = detected.has(tag);
    const e = expected.has(tag);
    if (d && e) stats[tag].tp++;
    else if (d && !e) {
      stats[tag].fp++;
      misses.push({ kind: "FP", tag, text: c.text });
    } else if (!d && e) {
      stats[tag].fn++;
      misses.push({ kind: "FN", tag, text: c.text });
    }
  }
}

const pct = (x) => (x * 100).toFixed(1) + "%";
function metrics(s) {
  const precision = s.tp + s.fp === 0 ? 1 : s.tp / (s.tp + s.fp);
  const recall = s.tp + s.fn === 0 ? 1 : s.tp / (s.tp + s.fn);
  const f1 =
    precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision, recall, f1 };
}

console.log(
  `\n  llm-guardrails detection benchmark — ${corpus.length} labelled cases\n`,
);
console.log(
  "  " + "tag".padEnd(17) + "precision  recall    F1       TP/FP/FN",
);
console.log("  " + "-".repeat(60));

let TP = 0;
let FP = 0;
let FN = 0;
for (const tag of FOCUS) {
  const s = stats[tag];
  TP += s.tp;
  FP += s.fp;
  FN += s.fn;
  const m = metrics(s);
  console.log(
    "  " +
      tag.padEnd(17) +
      pct(m.precision).padEnd(11) +
      pct(m.recall).padEnd(10) +
      pct(m.f1).padEnd(9) +
      `${s.tp}/${s.fp}/${s.fn}`,
  );
}

const micro = metrics({ tp: TP, fp: FP, fn: FN });
console.log("  " + "-".repeat(60));
console.log(
  "  " +
    "overall (micro)".padEnd(17) +
    pct(micro.precision).padEnd(11) +
    pct(micro.recall).padEnd(10) +
    pct(micro.f1).padEnd(9) +
    `${TP}/${FP}/${FN}`,
);

if (misses.length) {
  console.log("\n  misses:");
  for (const m of misses) {
    console.log(`  [${m.kind} ${m.tag}] ${m.text}`);
  }
}
console.log("");
