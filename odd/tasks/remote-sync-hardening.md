# Feature: Phase 2S hardening (open minors)

Close the open minors that verification left in odd/tasks/remote-sync.md (Log L16, L18, L20, L22) before Phase 3.
Branch `feat/cli-skeleton`. Spec authority: docs/REMOTE_SYNC.md, docs/CLI.md, AGENTS.md.

## Specs

- S1. User (2026-11-04): "Cerrar minors de 2S y después Fase 3".
- S2. Clear recovery messages (remote-sync L16 m1/m2/m3/m8, L18): when a command fails after the account or the key already changed, the error says what state the device is in and the exact command that finishes it; `approve` shows the confirmation code even when its local roster write fails after the server accepted; after three conflict retries the push warning names the conflict, not "server unreachable".
- S3. No hidden prompts or mutations (remote-sync L16 m6, L22): `remote status` never prompts (CLI.md: "Read-only: it never prompts"); `audit --verify` never prompts and never finishes a rekey for its anchor check (unavailable instead); a `ReadRemote` error during `audit --verify` is reported, not skipped silently.
- S4. Restore order (remote-sync L22): `remote restore --version N` asks its confirmation before any sync round that could pull or push; a cancel makes no request that changes anything.
- S5. Release hygiene (remote-sync L20): the `rotateCrash` test seam is not compiled into release binaries; `swapKey` closes the vault it opened on every failure path.
- S6. Missing tests (remote-sync L16 m7, L22): a sync round refuses an older generation and a tampered blob (state unchanged); a grant bound to a record restored unchanged keeps working and one bound to a replaced record does not; a revoked device stays revoked after restore (CLI); plain `audit` makes no request with sync enabled.

Not in scope, by decision: the broker's second session for a syncing vault (performance, L18), broker `request` not pushing (the spec lists no push for it, L18), a local `restore` of an older backup propagating deletions (it is a user restore; documented), one extra version after a retried pending push or a rotation (harmless, L16), the passphrase prompt of an automatic key swap without a terminal (needs a design for an unlock cache, Phase 5).

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| H1 | S2-S6 | worker | all of S2-S6 in internal/cli (+ vault for S5 if needed), tests first | b7c2092 | done |
| H2 | S2-S6 | inline | parent review, full suite, e2e battery, commit | b7c2092 | done |

## Log

- L1. User request (verbatim answer to "¿Cómo seguimos después de la Fase 2S?"): "Cerrar minors de 2S y después Fase 3 (Recomendado)".
- L2. H1 done by gentle-ai-worker (RED per spec reported for S2-S5; the S6 tests passed on their first run). Decisions: `openSessionQuiet` (keychain or unlock cache only, never prompts, never finishes a rekey) for `remote status` and the anchor check of `audit --verify`; `rotateCrash` behind the build tag `crashseam`, run from a default-tag test through a subprocess; a failed join after the key swap points to `remote join --recovery` because the approver's roster refuses a second pairing for the same id. Left out: `remote devices` can still prompt; a register that fails locally leaves an empty account on the server (no delete-account API).
- L3. H2 parent check: the Go suite passed but the Docker battery failed 2 checks: in passphrase mode `remote status` could no longer open the vault without a prompt, so it showed `locked` and lost the conflict count and its warnings. Fix: every sync round records counts (conflicts, live devices, devices added by recovery; no names or labels) in `state.json.remote.summary`, and a locked `status` shows them marked `(as of the last sync)` with `"counts_from":"last_sync"`. `vault.RemoteSummary` is a value field (`omitzero`), so `vault.Remote` stays comparable in tests.
