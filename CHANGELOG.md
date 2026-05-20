# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-05-21

### Changed

- Packaging: the published tarball now ships only `dist/src` (the library),
  not the compiled test suite. Removed two unreferenced dead files
  (`detectors/test.ts` scratch demo and an unused `policies/toolPolicies.ts`
  example). This eliminates test-fixture email domains and example allowlist
  domains from the published code, which were tripping supply-chain scanners.
  No runtime behaviour changed — the package makes no network requests.

## [0.3.0] - 2026-05-20

First public release.

### Added

- Core guardrail pipeline (`createGuardrails`, `run`) — scans input, output, and
  tool interactions with redact / block / rewrite actions and three modes
  (`full`, `input_only`, `output_only`).
- Generic PII detection — email, phone, SSN, credit card, IP address, street
  address, passport, driver's licence, ZIP code, date of birth.
- Indian PII detection with checksum validation — Aadhaar (Verhoeff), GSTIN
  (mod-36), PAN, IFSC, voter ID, Indian mobile, UPI ID.
- Secret detection — API keys, RSA/SSH private keys, JWTs, bearer tokens, and
  generic `key=value` secrets.
- SQL-leak and system/developer-prompt-leak detection on model output.
- Tool firewall — declarative per-tool policies, call validation, and result
  sanitization (row caps, field stripping, output truncation).
- JSON output enforcement mode with a rewrite loop.
- India DPDP support — `dpdpEnforce` hard-block mode, typed `DPDPBlockedError`,
  heuristic child-signal detection, and `recordConsent` / `recordEvidence`
  audit-trail helpers.
- Prompt-injection / jailbreak detection on input and RAG context
  (`blockPromptInjection`).
- Streaming output guard (`runStream`) — scans and redacts a streamed response
  with a holdback buffer so a match spanning chunk boundaries is caught before
  emission.
- Structured audit events delivered through `onEvent`, with optional hashing of
  matched values (`redactEventPayloads`).
- Credit-card detection validated with the Luhn checksum.
- Context-required `bankAccount` detection (a bare long number is not treated as
  an account number).
- Detection benchmark (`npm run benchmark`) over a labelled corpus reporting
  per-detector precision and recall.

### Compatibility

- No runtime dependencies and no Node-only built-ins — runs on Node 18+ and on
  edge runtimes (Vercel Edge, Cloudflare Workers, Next.js middleware).
