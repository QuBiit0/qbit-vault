# Feature: roadmap slice 1.5, hash-chained audit log

`internal/audit`: append-only, hash-chained `audit.jsonl`, `audit` and `audit --verify`
commands, and audit records written by the existing CLI commands. Branch `feat/cli-skeleton`.

## Specs

- S1. ROADMAP 1.5: "`audit`: hash chain, `--verify`, event writers" (R-AUD-*).
- S2. R-AUD-01: "An append-only JSONL log at `$GENTLE_VAULT_HOME/audit.jsonl` MUST record: capture (name, layer, session, reason, `by: agent|user`), grant (name, layer, session, scope, expiry), exec (R-EXEC-06), manage (action, name, layer, session, reason, outcome), refusal (type, name, session), revoke, rm, mv. Never values."
- S3. R-AUD-02: "Each record MUST include the SHA-256 of the previous record (hash chain) so tampering is detectable by `gentle-vault audit --verify`." STORAGE.md § Audit log record example with `ts`, `seq`, `prev` ("hash of previous line"), `event`, `session`, `host`, `names`, `cwd`, `hash` ("hash of this line without the hash field").
- S4. docs/CLI.md: "`audit [--tail N] [--since 24h] [--name NAME] [--event exec] [--json]` | Read the log." "`audit --verify` | Validate the hash chain."
- S5. TESTING.md: "`audit` | hash chain; verify detects an edited middle line, a deleted line, a truncated file".
- S6. R-AUD-03: "The log MUST never leave the machine." AGENTS.md invariant 1: never values.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S3, S5, S6 | worker | `internal/lockfile` extracted from vault; `internal/audit`: record, append, chain, head anchor, verify, read/filter | 0156295 | done |
| T2 | S1, S2, S4 | worker | CLI: `audit` command; event writers in init, set, rm, edit, mv, relink and refusals; docs | next commit (cli) | done |

## Log

- L1. User: "continua" (proceed with slice 1.5 after the slice 1.4 report).
- L2. Decision: `prev` = `sha256:` + hex SHA-256 of the previous line's raw bytes (without the newline); the first record's `prev` is `sha256:` + 64 zeros. `hash` = SHA-256 of the record's canonical JSON with the `hash` field omitted.
- L3. Decision: truncation anchor `audit.head` (`{seq, hash}`, written atomically after each append). Verify reports truncation when the log ends before the anchor. This catches accidental truncation and naive deletion; it does not stop a local attacker who rewrites both files (documented with THREAT_MODEL R8).
- L4. Decision: audit writes are best-effort for the operations that exist today (vault mutations already committed): a failed append prints the fixed warning `warning: audit log write failed` to stderr and does not change the exit code. Grant and exec (slices 1.6, 1.8) will decide fail-closed separately.
- L5. Decision: CLI records use `session` = the `--session` value or `cli` when empty, `by: "user"`. New event names `edit` and `relink` join the list in STORAGE.md.
- L6. Decision: appends serialize across processes with their own `audit.lock`, using a shared `internal/lockfile` package extracted from `internal/vault/lock.go` with unchanged vault behavior.
- L7. Worker result: all checks green incl. FuzzVerify and a cli end-to-end (init → set → edit → mv → rm → refusal → audit → verify → tamper → verify fails). Correction: a deleted/emptied log with head seq > 0 continues the chain from the head (`audit.head` = {seq, hash, line}) and verify reports `truncated` at line 1. Remaining (documented R8): deleting both files restarts at genesis. Follow-ups: grant/exec/manage/revoke events come with their slices; TESTING.md audit row not updated; legacy-head fallback in head.go is dead code (no release wrote it) and can be removed.
