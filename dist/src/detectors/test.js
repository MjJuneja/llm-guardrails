"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const pii_1 = require("./pii");
const text = "John's email is john@example.com and his phone number is 123-456-7890.";
const cleanedText = (0, pii_1.redactPII)(text);
console.log("Original:", text);
console.log("Cleaned:", cleanedText);
