# Feature: roadmap slice 1.6, grants

Encrypted grant store bound to (name, layer), scopes `once`/`session`/`project` with TTL,
prompt tokens, the `grant`/`revoke`/`grants` commands, `set --grant`, and the grant check that
`exec` (slice 1.8) will call. Branch `feat/cli-skeleton`.

## Specs

- S1. ROADMAP 1.6: "`grants`: encrypted `grants.enc`, (name, layer) binding, scopes, TTL, project root resolution, `grant`/`revoke`/`grants` (TTY-only)" (R-GRANT-01,02,04,06).
- S2. R-GRANT-01: "A grant binds (secret name, layer, session id, scope, expiry). A grant for the global `NAME` does not cover a project `NAME`, and the reverse." R-GRANT-02: "Scopes: `once` (this exec only), `session` (this host session, default TTL 30 min, configurable), `project` (this repository root until revoked; survives sessions). Secrets flagged `sensitive` MUST only accept `once`."
- S3. R-GRANT-03: "A grant MUST be created only from an explicit user confirmation delivered through the host UI or the native prompt. The MCP tool surface MUST NOT be able to create a grant on its own." CLI.md: "`grant NAME ... --scope once|session|project [--ttl 30m]` | Interactive confirmation then grant. Refuses when stdin is not a TTY unless `--from-prompt-token` is present."
- S4. R-GRANT-04: grants persisted encrypted at `grants.enc`. R-GRANT-06: "`gentle-vault revoke <name> [--all]` and `gentle-vault revoke --session <id>` MUST take effect immediately for any later exec."
- S5. STORAGE.md § Grants evaluation steps 1-7 (purge expired; resolve name for cwd; match name **and** layer; once/session/project rules; otherwise `grant_required`), and "`mv`, `rm` and `relink` rewrite or drop the grants of the affected record".
- S6. CONTRACT.md refusals `grant_required`, `scope_not_allowed`, `not_model_callable`; STORAGE.md `prompt_token_hash` paragraph.
- S7. AGENTS.md invariant 6: "Every capture and every grant is an explicit user action. No auto-approval paths in v1."

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S4, S5 | worker | `internal/envelope` extracted from vault; vault-owned `grants.enc` persistence with its own counter; grants dropped/rewritten by rm, mv, value replace, relink | 8d165d5 | done |
| T2 | S2, S5, S6 | worker | `internal/grants`: grant model, scopes, TTL, evaluation/consume, prompt tokens | ae77456 | done |
| T3 | S1-S4, S6, S7 | worker | CLI `grant`, `revoke`, `grants`, `set --grant`, grants in `describe`, audit events, docs | next commit (cli) | done |

## Log

- L1. User: "sigue" (proceed with slice 1.6).
- L2. Decision: `grants.enc` is a separate file in the same AEAD envelope format (`format: "gentle-vault-grants/1"`), managed by `internal/vault` under the same `vault.lock`, with its own write counter `grants_writes` in `state.json`. No backup snapshots for grants (losing them loses permissions, never secrets).
- L3. Decision: a corrupt or rolled-back `grants.enc` fails closed: it is treated as empty (no grant allows anything), replaced with an empty store on the next write, and the CLI records an audit `warning` with detail `grants reset`. Rollback could otherwise revive revoked grants.
- L4. Decision: creating a grant is fail-closed on audit: the `grant` audit record is appended before the grant is persisted; if the append fails, the grant is not created (refusal `internal`). Revoke stays best-effort (it only narrows access).
- L5. Decision: confirmation for `grant` and `set --grant` is a y/N question on the TTY (stdin and stdout both terminals) or a valid `--from-prompt-token`. Prompt tokens are random 32-byte values issued by `internal/grants` (stored as SHA-256 only, single use, bound to name, layer, scope and session, 2-minute expiry); the CLI issuer (`gentle-vault prompt`) arrives with slices 1.9/1.10.
- L6. Decision: residual risk R9 in THREAT_MODEL.md: an agent can run the CLI from its shell and fake a TTY with a PTY (`script`), answering its own confirmation; the prompt token is the strong boundary. Closed by moving CLI confirmation to the native out-of-band dialog (slice 1.10) and by host hooks refusing `gentle-vault` mutating subcommands in the agent shell (phase 3). Same note covers `set`/`rm --yes`/`mv`/`edit` run by the agent's shell.
- L7. Decision: replacing a value with `set` drops that record's grants (consistent with `manage replace`, R-API-07).
- L8. Worker result: all checks green. Correction applied before commit: every vault record has a random `id` (new on create and on value replace, kept by edit/mv/relink) and grants store `record_id`; Check only matches the same record, so a stale grant left by a failed drop can never authorize a re-created secret. Other choices: `set --grant` requires `--from-prompt-token` (stdin carries the value); a bad or mismatched token is burned and refused as `not_model_callable`; `revoke NAME` without a layer flag revokes every layer; describe/grants purge expired grants (they write). Follow-up: a reset detected during an rm/mv drop heals on the next grants/describe/grant.
- L9. Independent verify: S1-S7 pass, no blockers. Fixed after it: `edit --sensitive=true` drops non-once grants and `Check` ignores broad grants on sensitive records; `relink` drops project grants instead of carrying them (can only narrow; R9 lists it); prompt tokens bind TTL and record id when known; project scope on a global record has its own message. Note for slice 1.8: `Check` expects a case-folded cwd on Windows.
