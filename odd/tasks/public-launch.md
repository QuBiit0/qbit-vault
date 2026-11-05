# Feature: public launch and one-command install

Remove what is left of the old gentle-vault / Gentle AI framing, make the repository ready to go public, and add a one-command install (release binaries plus curl / irm scripts, and `go install`).
Branch `chore/public-launch`.

## Specs

- S1. User (verbatim): "si por favor limpia todo lo que tenga que ver con lo viejo gentle-vault y demas.. dejalo listo para compartir al repo en publico. tambien necesito que generes un comando para instalar oneshot o onecomand tipo con curl o directamente desde el repo de gitbub usando go, asi como tiene gentle-ai y engram.D . Quiero compartirlo para que lo empiecen a probar. obvio que el primero que va a probarlo voy a ser yo y mis compa;eros de trabajo"
- S2. User choice (verbatim): contract "Sí, a qbit-vault.secrets-broker/v1 (Recomendado)": the contract ID becomes `qbit-vault.secrets-broker/v1` and the "adoptable by Gentle AI" framing leaves PRD/ARCHITECTURE; mentions of Gentle Shell / Pi as an integrated host stay.
- S3. User choice (verbatim): installer "Releases + curl/irm + go install (Recomendado)".
- S4. User choice (verbatim): first version "v0.1.0-beta.1 (Recomendado)".
- S5. User choice (verbatim): development logs "Dejarlos (Recomendado)": `odd/tasks/` stays.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| P1 | S1, S2 | inline | contract ID rename (code, schema, tests, docs), Gentle AI framing out of PRD/ARCHITECTURE/ROADMAP/TESTING, stale worktrees pruned, rename R3 closed | | pending |
| P2 | S3, S4 | inline | GoReleaser config, release workflow on `v*` tags (checksums, build provenance), version via ldflags | | pending |
| P3 | S3 | inline | `scripts/install.sh`, `scripts/install.ps1` with SHA-256 verification; tests; README and INSTALL updated | | pending |
| P4 | S1 | inline | full suite, PR, then the user's decisions: make the repo public, tag v0.1.0-beta.1 | | pending |

## Log

- L1. User request verbatim in S1.
- L2. `git worktree prune -v` removed three stale `Gentle-Vault/.git/gentle-ai/candidate-views/*` entries. gitleaks over all 146 commits: 8 findings, all test fixtures (`tok_0123…` prompt tokens, the jwt.io sample JWT, a bare RSA header). No real secret.
