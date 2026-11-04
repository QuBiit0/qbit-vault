# Feature: roadmap Phase 2, broker contract, request, manage and MCP

The contract `gentle-ai.secrets-broker/v1` as code: one entry point that decodes and validates
envelopes, dispatches every op and answers with exactly one JSON object (success or typed
refusal); `broker --op` for the Pi extension; the four model tools over a stdio MCP server.
Branch `feat/cli-skeleton`.

## Specs

- S1. ROADMAP 2.1: "`broker` package implementing all ops + refusals; `broker --op` CLI; schema validation" (CONTRACT.md).
- S2. CONTRACT.md § Envelope: "Every request and response carries: `{ "contract": "gentle-ai.secrets-broker/v1", "op": "request", "v": 1, "session": "pi:2f1c…", "cwd": "/home/me/repo", ... }`" and "Responses carry `ok: true` with the op's payload, or `ok: false` with a **refusal** (see below). No other error shape exists."
- S3. CONTRACT.md § `list`, § `exec`, § `grant`, § `revoke`, § `capabilities` request and response shapes; the `policy` strings "are normative (hosts ship them verbatim) and the same text is the MCP server's `instructions`".
- S4. CONTRACT.md § `grant`: "Only the host UI (Pi extension prompt, native dialog) may send it, and only as the result of a user interaction. The MCP server does not expose it as a tool. The CLI accepts it only from an interactive TTY or with `--from-prompt-token <t>` issued by the broker's own prompt."
- S5. ROADMAP 2.2: "`request` with existence non-disclosure, layer choice, reason heuristic, rate limit; `list` with `policy`" (R-API-02,03,06, R-CAP-02,03a,05). 2.2a: "`manage` op" (R-API-07,08). 2.2b/2.2c: multi-field `request` and its rendering (R-CAP-08,09).
- S6. ROADMAP 2.3: "`mcp` stdio server, four tools, normative descriptions, `policy` as server `instructions`, `grant` refusal" (R-API-01,05,06). 2.4: "Contract conformance test harness".
- S7. AGENTS.md invariants 1, 4, 5, 6: no value crosses the boundary; injection per child; output redacted; every capture and grant an explicit user action.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1-S4, S7 | inline | `internal/broker`: envelope decode and validation, dispatch, capabilities, normative policy; `broker --op`; CLI backend for `list`, `exec`, `grant`, `revoke` | 60ee2ac | done |
| T2 | S5, S7 | inline | `request` (single name): reason heuristic, cooldown, non-disclosure, in-process prompt, store and grant | 8de9a67 | done |
| T3 | S5 | inline | multi-field `request` (2.2b) and backend rendering (2.2c) | | pending |
| T4 | S5 | inline | `manage` (2.2a) | | pending |
| T5 | S6 | inline | `mcp` stdio server (2.3) | | pending |
| T6 | S6 | inline | conformance harness (2.4) | | pending |

## Log

- L1. User: "si" to "¿Arranco con la Phase 2 ahora, o preferís revisar primero estos commits?" (read as: start Phase 2).
- L2. Decision: `internal/broker` owns the contract (decode, validate, dispatch, capabilities, policy text, transport rules such as `grant` over MCP -> `not_model_callable`); the operations are implemented by `internal/cli` behind a `broker.Backend` interface, reusing the tested command code with the envelope's `cwd` and `session`, never the process ones. The MCP server (T5) calls the same broker in-process.
- L3. Decision: a request that fails validation is a refusal, never another error shape: a bad secret name is `invalid_name`, an unsupported `contract` or `v` is `contract_mismatch`, any other invalid field is `internal` with the fixed message `invalid request: <field>` (the field name, never its value).
- L4. Decision: over `broker --op` a `grant` needs `prompt_token`; there is no terminal fallback there (the host is not a person at a keyboard). Without one it is `not_model_callable`.
- L5. Decision: `list` reports the grant that applies to the envelope's session for each record (project over session over once), `kind` is `secret` until body schema 2 (Phase 2S) and `unlinked_match` is `null` until sync.
- L6. T1 note: the broker package had an observed RED (build) before its code; the CLI broker tests were written first but first run after the backend existed, so no RED was observed for them. An exec child now gets an empty stdin under the broker (`globals.execStdin`), because the broker's stdin is the request or the MCP stream.
- L7. T2 notes: RED observed for every request test and for the grants cooldown tests. `record` no longer forces `by: user`: it is the default, and a broker capture is audited `by: agent` (R-AUD-01). Cooldowns live in `grants.enc` (new `cooldowns` array; the empty-body encoding gained `"cooldowns":[]`). A blank value at the request prompt is `internal` (`empty value`) without a cooldown.
- L8. Order change: T4 (`manage`) and T5 (MCP) before T3 (multi-field), so the model-facing surface is usable end to end before the larger prompt-rendering work.
- L9. T5 notes: go-sdk v1.8.0 (ServerOptions.Instructions confirmed in its source). The server uses `IOTransport` over the command's stdin/stdout instead of `StdioTransport`, so the end-to-end test drives real JSON-RPC through `execute`. The test keeps stdin open until the last answer arrives: a closed stdin ends the session before queued requests are answered, as with a real host closing the stream. Tool descriptions are checked verbatim against CONTRACT.md. Transitive compiled deps listed in AGENTS.md.
