import { redactPII } from "./pii";

const text = "John's email is john@example.com and his phone number is 123-456-7890.";
const cleanedText = redactPII(text);

console.log("Original:", text);
console.log("Cleaned:", cleanedText);