# Feature: public launch and one-command install

Remove what is left of the old gentle-vault / Gentle AI framing, make the repository ready to go public, and add a one-command install (release binaries plus curl / irm scripts, and `go install`).
Branch `chore/public-launch`.

## Specs

- S1. User (verbatim): "si por favor limpia todo lo que tenga que ver con lo viejo gentle-vault y demas.. dejalo listo para compartir al repo en publico. tambien necesito que generes un comando para instalar oneshot o onecomand tipo con curl o directamente desde el repo de gitbub usando go, asi como tiene gentle-ai y engram.D . Quiero compartirlo para que lo empiecen a probar. obvio que el primero que va a probarlo voy a ser yo y mis compa;eros de trabajo"
- S2. User choice (verbatim): contract "Sí, a qbit-vault.secrets-broker/v1 (Recomendado)": the contract ID becomes `qbit-vault.secrets-broker/v1` and the "adoptable by Gentle AI" framing leaves PRD/ARCHITECTURE; mentions of Gentle Shell / Pi as an integrated host stay.
- S3. User choice (verbatim): installer "Releases + curl/irm + go install (Recomendado)".
- S4. User choice (verbatim): first version "v0.1.0-beta.1 (Recomendado)".
- S5. User choice (verbatim): development logs "Dejarlos (Recomendado)": `odd/tasks/` stays.
- S6. User (verbatim): "y como reacciona la instalacion cuando ya hay una version instalada? la reemplaza, la actualiza, borra la anterior y despues instala esta? se rompe? debes contemplar esto para no generar fricciones"

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| P1 | S1, S2 | inline | contract ID rename (code, schema, tests, docs), Gentle AI framing out of PRD/ARCHITECTURE/ROADMAP/TESTING, stale worktrees pruned, rename R3 closed | 867a706 | done |
| P2 | S3, S4 | inline | GoReleaser config, release workflow on `v*` tags (checksums, build provenance), version via ldflags and build info | 84c0c63 | done |
| P3 | S3, S6 | inline | `scripts/install.sh`, `scripts/install.ps1` with SHA-256 verification, in-place upgrade and re-sync; tests; README and INSTALL updated | f0671d9, 15509a0 | done |
| P4 | S1 | inline | full suite, PR, then the user's decisions: make the repo public, tag v0.1.0-beta.1 | | pending |

## Log

- L1. User request verbatim in S1.
- L2. `git worktree prune -v` removed three stale `Gentle-Vault/.git/gentle-ai/candidate-views/*` entries. gitleaks over all 146 commits: 8 findings, all test fixtures (`tok_0123…` prompt tokens, the jwt.io sample JWT, a bare RSA header). No real secret.
- L3. Checks: full `go vet` + `go test ./...` green on Windows (Go 1.27) after P1; `internal/cli` green with buildinfo; `goreleaser check` and `release --snapshot` (v2.12.0) produce the 10 archives and checksums.txt; install.ps1 installed the real snapshot zip and the binary answered `qbit-vault v0.0.0 (f0671d9, windows/amd64)`.
- L4. S6 decision: re-running the script upgrades the `qbit-vault` first on PATH in place when its directory is writable (keeps the registered absolute path), else installs to the default directory and warns about the shadowing copy; with `$QBIT_VAULT_HOME/state.json` present it runs `qbit-vault sync` (re-applies recorded registrations, reads no secret, asks nothing; not `init`), opt-out `QBIT_VAULT_NO_SYNC=1`. install_test.sh 31 checks green (Git Bash), install_test.ps1 green on PowerShell 7 and 5.1; the user's real PATH, ~/.local/bin and %LOCALAPPDATA%\Programs untouched. Verified on Windows: installing over a running `qbit-vault.exe mcp` succeeds (rc 0), the old file stays as `.old` until the next install.
