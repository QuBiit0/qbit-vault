# Feature: repo polish, docs, visual identity, README, TUI design, full-flow control

Clean the repository, bring every doc in line with what is built, give QBit Vault a visual identity and a visual README, design a TUI, verify the whole flow end to end, and land everything on `main`.
Branch `feat/cli-skeleton` until T8. Spec authority: the code as built, docs/*, AGENTS.md.

## Specs

- S1. User (2026-11-05, verbatim): "limpia el repo, actualiza toda la doc, arma el readme completo bien lindo visual. controla el flujo completo. Dise;emos lo que haga falta"
- S2. User choices: branches "Borrarlas y llevar todo a main (Recomendado)" (delete the 23 old review branches locally and on GitHub, PR feat/cli-skeleton into main, merge, main becomes the default branch); design "La TUI de QBit Vault (Recomendado)", "Identidad visual QBit Vault", "README visual".
- S3. Brand: every personal tool carries the qbit brand (user preference); QBit Vault is independent and not affiliated with the hosts it integrates with.
- S4. Docs must describe what exists today: no `npx`/Homebrew/install script until the release (Phase 5), OpenCode out of scope (hosts.md S8), Pi through MCP (the native extension is Phase 4), `go install` is the install path.

- S5. User (2026-11-05, verbatim): "el tui debe ser como tiene engram y gentle-ai. interactivo y poder configurarse, actualizarse y demas". The TUI is an interactive app (bubbletea-style, like gentle-ai and engram): guided setup, configuration, self-update, management of secrets, grants, audit, hosts and sync. Self-update needs published releases (Phase 5) and uses the opt-out update check AGENTS.md invariant 8 allows.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1, S2 | inline | repo cleanup: .gitignore (.codegraph), move the proposal under docs/, CI on main, delete old review branches after proving each is contained in feat/cli-skeleton | f734b75 | done |
| T2 | S1, S4 | worker | docs audit: every doc and help text matches the code (ROADMAP status, INSTALL, CLI, ARCHITECTURE, PRD statuses) | (T2) | done |
| T3 | S2, S3 | design | visual identity: logo, banner, palette (gentle-design artboards), exported assets for README and TUI | | pending |
| T4 | S2 | design | TUI design: screens and flows as artboards; user picks a direction | | pending |
| T5 | S1, S2 | worker | README: visual, complete, accurate (banner, diagrams, quickstart, commands, security model, status) | | pending |
| T6 | S1 | worker | full-flow control: install-from-scratch e2e in a container (go install, init, set, agent MCP flow, uninstall) + every battery green | | pending |
| T7 | S2 | later | TUI spec + implementation, after the design is chosen and the dependency is approved | | pending |
| T8 | S2 | inline | PR feat/cli-skeleton -> main, merge, default branch main | | pending |

## Log

- L1. User request (S1) and choices (S2), 2026-11-05.
- L2. Every old review branch (`feat/gentle-vault`, `feat/gentle-vault-01..22-*`) and `main` are ancestors of `feat/cli-skeleton` (`git merge-base --is-ancestor`), so deleting the branches loses no commit.
- L3. T2 docs audit (gentle-ai-worker): ROADMAP and INSTALL rewritten to the real state, ~100 fixes across CLI, ARCHITECTURE, PRD (new implementation-status section), STORAGE, TESTING, THREAT_MODEL, AGENT_INTEGRATIONS, GENTLE_SHELL_EXTENSION, REMOTE_SYNC, AGENTS.md layout and CONTRACT.md; no claim was softened to hide a gap. Backlog of claims the code does not satisfy (now stated in the docs): (B1) `init` has no automatic passphrase fallback without a keychain; (B2) bindings.yaml/config.yaml are not loaded (budgets, TTLs are constants); (B3) pre-bash does not rewrite commands into `exec` nor deny grant_required/dump_command; (B4) Codex and Pi get no hook and no deny rule (only Claude Code does); (B5) no explicit Gentle AI deny-entry verification step (entries survive because only owned entries are touched); (B6) doctor lacks binary signature, Pi extension version, active-grant count, generation/anchor state; (B7) documented but missing commands `update`, `redact`, `set --fields`, `prompt --field/--confirm` (marked planned). vault-ops.md T4 status fixed (5d256a5).
