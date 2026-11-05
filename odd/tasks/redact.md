# Feature: roadmap slice 1.7, streaming redaction

`internal/redact`: replaces every active secret value and its common encodings in a byte stream,
across chunk boundaries, with `[REDACTED:NAME]`. Consumed by `exec` (slice 1.8) and the host
adapters. Branch `feat/cli-skeleton`.

## Specs

- S1. ROADMAP 1.7: "`redact`: streaming multi-encoding + fuzz" (R-RED-01..03).
- S2. R-RED-01: "The redactor MUST replace, in any byte stream it is given, every active secret value and its encodings: raw, base64 (standard and URL-safe, with and without padding), percent-encoded, JSON-escaped, and the value with surrounding quotes stripped. Replacement token: `[REDACTED:NAME]`."
- S3. R-RED-02: "The redactor MUST work on streams (chunk boundaries must not defeat it): keep a sliding buffer of at least the longest active value's encoded length."
- S4. R-RED-03: "Values shorter than 8 bytes MUST still be redacted but MUST log an audit warning that short secrets produce false positives."
- S5. TESTING.md: "`redact` | raw, base64 std/url ±padding, percent, JSON-escaped, quoted; chunk boundaries at every offset of a value (fuzz); short-value warning; overlapping values" and "`FuzzRedactStream` — random values, random chunking, random surrounding bytes; invariant: output never contains the value in any modeled encoding."
- S6. AGENTS.md invariants 1 and 5.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1-S6 | worker | `internal/redact` package, tests, fuzz, docs | this commit (feat(redact)) | done |

## Log

- L1. User: "dale" (proceed with slice 1.7).
- L2. Decision: also redact the value when it is embedded inside a larger base64 blob (for example HTTP Basic auth `base64(user:token)`): for each of the three byte alignments, redact the stable inner base64 substring of the value. Applies to values of at least 8 bytes (shorter ones would produce constant false positives).
- L3. Decision: matching prefers, at the earliest position, the longest pattern; overlapping values (one secret contains another) redact as the longer one.
- L4. Decision: the package is pure (no vault, no audit). It reports short-value warnings (names) to its caller, which audits them in slice 1.8. A `qbit-vault redact` CLI subcommand for host read hooks arrives with the host adapters.
- L5. Worker result: tests, 30 s fuzz (~487k execs) and leakgrep green; benchmark 1 MiB with 16 secrets ~8 ms (~130 MB/s). Code was written before tests; RED was shown by mutation (disabling hold-back, L2 and longest-first each fails tests). Percent and JSON encoders are hand-written over []byte (no unwipable strings) and checked against the standard library; extra variants: strict percent, ASCII-only JSON \uXXXX.
- L6. Independent verify: S1-S6 pass, no blockers (897k fuzz execs, 18 probe suites). Fixed after it, test-first: multi-line values get per-line patterns (lines >= 16 bytes) and LF/CRLF-translated forms; Python quote, JS encodeURIComponent and JSON `\/` dialects. Documented as not modeled in THREAT_MODEL R2: wrapped base64, hex, reversed, chained overlap of two secrets sharing bytes, derived patterns < 4 bytes.
