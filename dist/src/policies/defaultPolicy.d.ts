import type { Detection } from "./actions.js";
import type { GuardrailsConfig } from "../guard/types.js";
export declare function defaultInputPolicy(detections: Detection[], cfg: GuardrailsConfig): Detection[];
export declare function defaultOutputPolicy(detections: Detection[], cfg: GuardrailsConfig): Detection[];
