# Polish for a stable 1.4.1

Close every small defect left after 1.4.0 so the release can be shared: clearer messages, a visible `sync` summary after `update`, missing tests, a graceful Pi footer on an older binary, and the PowerShell 5.1 test quirk. No new features.

## Specs

- S1. User (verbatim, 2026-11-12): "corrijamos todo y dejemos una version estable lista para compartir"; "asi ya cerramos con esto".
- S2. Signature fetch vs signature check (`internal/selfupdate`, `scripts/install.sh`, `scripts/install.ps1`; review advisories R3-002/R3-003/R4 of `odd/tasks/minisign.md` L11): a `.minisig` that cannot be downloaded (network error, HTTP error other than 404, timeout) says `could not download the signature of the release <version>: <short reason>; nothing was changed` (installers: `... nothing was installed`); a release that has no `.minisig` (not listed, or 404) and a signature that does not verify keep the exact current "not signed" messages. Never a fallback to SHA-256 only. Reasons are fixed short strings (no URL with tokens, no file content).
- S3. `qbit-vault update` shows what the `sync` it runs printed (host lines, the Codex `/hooks` trust notice), after its own `updated ...` line; a `sync` failure stays a stderr note with exit 0, as today. `QBIT_VAULT_NO_SYNC=1` unchanged. `--json` output unchanged (sync text not mixed into it; add `"sync_output"` only if it fits the existing JSON contract, otherwise leave JSON as is).
- S4. Tests: cancel of the unlock dialog for `secret_exec` and `secret_list` (review advisory R3-exec-list-cancel-untested, `internal/cli/agentunlock.go:104-106`) with the exact refusal; `install_test.sh:268` advisory R3-004 (read it and fix what it flagged).
- S5. Pi extension footer with a binary older than 1.4.0 (`grants --no-prompt` unknown; advisory R4-pi-footer-binary-skew, `packages/qbit-vault-pi/src/status.ts:53-54`): instead of a blank footer, show `🔐 update qbit-vault` (or similar fixed text) and notify once `qbit-vault-pi needs qbit-vault 1.4.0 or newer; run 'qbit-vault update'`; never fall back to a call that could open a dialog. qbit-vault-pi 0.2.3 (version, `ExtensionVersion`, install lines; tag after merge).
- S6. `scripts/install_test.ps1` passes under Windows PowerShell 5.1 started from pwsh 7 without unsetting `PSModulePath` by hand (the test runner, or `install.ps1` if a real user can hit it: find out which and fix there; record the finding).
- S7. Docs: close the stale task rows (`odd/tasks/output-guard.md` T7, `odd/tasks/minisign.md` T5, `odd/tasks/unlock-zero-friction.md` T2) with their evidence; AGENT_INTEGRATIONS Codex section says plainly that the Windows hook shell (`commandWindows` through PowerShell) is not verified in a live Codex session; CHANGELOG `[1.4.1]` (fixes only); INSTALL/CLI where messages changed.

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T1 | S2-S7 | worker | | in progress |
| T2 | verify, review, PR, release 1.4.1, pi-v0.2.3 | parent | | pending |

## Log

- L1. User (verbatim): see S1. Items come from the 1.3.0/1.4.0 review advisories and the owner check (Engram `odd/minisign/tasks`, `odd/output-guard/tasks`).
