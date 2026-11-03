# Feature: roadmap slices 1.4 and 1.4a, secret commands and file permissions

User-facing secret commands on top of `internal/vault` and `internal/keychain`: a vault-only
`init`, `set --stdin`, `rm`, `list`, `describe`, `edit`, `mv`, `relink`, typed refusals with
exit codes, and owner-only file permissions. Branch `feat/cli-skeleton` (stacked).

## Specs

- S1. ROADMAP 1.4: "`set --stdin`, `rm`, `list`, `describe`, `edit` with `--global`/`--project`, permissions enforcement" (R-VAULT-03,05,06, R-CAP-07). ROADMAP 1.4a: "`mv`, `relink`, `list --layer`" (R-LAYER-04,05).
- S2. docs/CLI.md § Secrets table rows for `set`, `rm`, `mv`, `list`, `describe`, `edit`, `relink`, and the **Layers** paragraph: "Commands that take `NAME` act on the record that `NAME` resolves to from the current directory (project first, then global); `--global` or `--project` picks a layer explicitly. `--project` outside a repository fails with `no_project` (exit 3)."
- S3. docs/CLI.md: "Values are **never** accepted as arguments." R-CAP-04: "Blank or whitespace-only input MUST fail the capture without writing anything. Surrounding whitespace MUST be trimmed."
- S4. R-VAULT-03: "The vault file, key file, grants file and audit log MUST be created with mode `0600` (owner-only ACL on Windows)." STORAGE.md § File permissions table.
- S5. CONTRACT.md § Refusals: "A refusal is `{ "ok": false, "refusal": { "type": "<type>", "name": "<secret name or null>", "message": "<human text, no values>", "retryable": true|false } }`." CLI.md exit codes 3 (typed refusal), 4 (vault locked), 5 (vault corrupt / rollback).
- S6. Slice 1.3 follow-up: "Setup writes the key before `vault.Init`, so the CLI slice (1.4) must remove an orphan key if Init fails."

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S5, S6 | worker | `internal/refusal`; CLI vault session helper (home, unlock, open, error mapping); vault-only `init` | 604acd6 (refusal) + next commit (cli) | done |
| T2 | S1-S3, S5 | worker | `set --stdin`, `rm`, `describe`, `edit`, `list --layer` | next commit (cli) | done |
| T3 | S1, S2 | worker | `mv`, `relink` (vault API + CLI) | 9ba9eea (vault) + next commit (cli) | done |
| T4 | S4 | worker | permissions: POSIX mode enforcement, Windows owner-only DACL | eba8752 | done |

## Log

- L1. User: "ok" (continue the roadmap after slice 1.3; earlier: "necesito avanzar con esto a fondo", "Continua").
- L2. Decision: `init` in this slice is vault-only (key + empty vault, no host registration); slice 3.6 extends it. If the vault already exists, `init` is idempotent and reports it.
- L3. Decision: interactive masked capture is slice 1.9. Until then `set` requires `--stdin`; without it `set` fails with a usage error naming `--stdin`. Passphrase-mode vaults need slice 1.9 for the interactive passphrase, except when an unexpired unlock cache exists.
- L4. Decision: `--grant` on `set` is added with grants in slice 1.6, not now.
- L5. Decision: `vault.ErrLocked` (another process holds the vault) maps to refusal `internal` with `retryable: true` and message "vault is busy" until the contract decides on a dedicated type (slice 2.1 follow-up).
- L6. Decision: Windows owner-only ACLs use `golang.org/x/sys/windows` (already an indirect dependency via x/crypto and go-keyring); justification: the standard library has no API to set a DACL.
- L7. Worker result: all checks green; end-to-end test init → set (global/project) → list → describe → edit → mv → rm drives Execute with a mocked keychain. CLI commands share cli.go registration, so T1-T3 CLI files land in one commit. Follow-ups: key.enc not yet under internal/perm (Windows ACL); grants TODOs in rm/mv/relink for slice 1.6; doctor integration of perm.Check; POSIX perm tests compiled but not run here.
