# Feature: repo polish, docs, visual identity, README, TUI design, full-flow control

Clean the repository, bring every doc in line with what is built, give QBit Vault a visual identity and a visual README, design a TUI, verify the whole flow end to end, and land everything on `main`.
Branch `feat/cli-skeleton` until T8. Spec authority: the code as built, docs/*, AGENTS.md.

## Specs

- S1. User (2026-11-05, verbatim): "limpia el repo, actualiza toda la doc, arma el readme completo bien lindo visual. controla el flujo completo. Dise;emos lo que haga falta"
- S2. User choices: branches "Borrarlas y llevar todo a main (Recomendado)" (delete the 23 old review branches locally and on GitHub, PR feat/cli-skeleton into main, merge, main becomes the default branch); design "La TUI de QBit Vault (Recomendado)", "Identidad visual QBit Vault", "README visual".
- S3. Brand: every personal tool carries the qbit brand (user preference); QBit Vault is independent and not affiliated with the hosts it integrates with.
- S4. Docs must describe what exists today: no `npx`/Homebrew/install script until the release (Phase 5), OpenCode out of scope (hosts.md S8), Pi through MCP (the native extension is Phase 4), `go install` is the install path.

- S5. User (2026-11-05, verbatim): "el tui debe ser como tiene engram y gentle-ai. interactivo y poder configurarse, actualizarse y demas". The TUI is an interactive app (bubbletea-style, like gentle-ai and engram): guided setup, configuration, self-update, management of secrets, grants, audit, hosts and sync. Self-update needs published releases (Phase 5) and uses the opt-out update check AGENTS.md invariant 8 allows.

- S6. User (2026-11-05, verbatim): "en realidad queria que sea verde negro y azul.. te voy a psar una imagen" ... "esta deveria ser mi marca" (two images: a qbitdev banner and an avatar). The brand is qbitdev: a Q outlined with a blue-to-green gradient inside atom orbits, a lowercase light wordmark `qbitdev`, near-black backgrounds, neon blue and green; a hexagon badge with the Q appears as a zipper pull. Colors measured from the banner's logo: background #000204, blue #4891B4 (glow #7FD0EC), green #4BB480 (glow #91ECC5), wordmark #C7D9DE. QBit Vault must read as part of the qbitdev family.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1, S2 | inline | repo cleanup: .gitignore (.codegraph), move the proposal under docs/, CI on main, delete old review branches after proving each is contained in feat/cli-skeleton | f734b75 | done |
| T2 | S1, S4 | worker | docs audit: every doc and help text matches the code (ROADMAP status, INSTALL, CLI, ARCHITECTURE, PRD statuses) | 8df3d3b | done |
| T3 | S2, S3, S6 | design | visual identity from the qbitdev brand: logo, banner, palette (gentle-design artboards), exported assets for README and TUI | (T3) | done |
| T4 | S2 | design | TUI design: screens and flows as artboards; user picks a direction | a456626 | done |
| T5 | S1, S2 | worker | README: visual, complete, accurate (banner, diagrams, quickstart, commands, security model, status) | (T5) | done |
| T6 | S1 | worker | full-flow control: install-from-scratch e2e in a container (go install, init, set, agent MCP flow, uninstall) + every battery green | | pending |
| T7 | S2 | later | TUI spec + implementation, after the design is chosen and the dependency is approved | | pending |
| T8 | S2 | inline | PR feat/cli-skeleton -> main, merge, default branch main | | pending |

## Log

- L1. User request (S1) and choices (S2), 2026-11-05.
- L2. Every old review branch (`feat/gentle-vault`, `feat/gentle-vault-01..22-*`) and `main` are ancestors of `feat/cli-skeleton` (`git merge-base --is-ancestor`), so deleting the branches loses no commit.
- L3. T2 docs audit (gentle-ai-worker): ROADMAP and INSTALL rewritten to the real state, ~100 fixes across CLI, ARCHITECTURE, PRD (new implementation-status section), STORAGE, TESTING, THREAT_MODEL, AGENT_INTEGRATIONS, GENTLE_SHELL_EXTENSION, REMOTE_SYNC, AGENTS.md layout and CONTRACT.md; no claim was softened to hide a gap. Backlog of claims the code does not satisfy (now stated in the docs): (B1) `init` has no automatic passphrase fallback without a keychain; (B2) bindings.yaml/config.yaml are not loaded (budgets, TTLs are constants); (B3) pre-bash does not rewrite commands into `exec` nor deny grant_required/dump_command; (B4) Codex and Pi get no hook and no deny rule (only Claude Code does); (B5) no explicit Gentle AI deny-entry verification step (entries survive because only owned entries are touched); (B6) doctor lacks binary signature, Pi extension version, active-grant count, generation/anchor state; (B7) documented but missing commands `update`, `redact`, `set --fields`, `prompt --field/--confirm` (marked planned). vault-ops.md T4 status fixed (5d256a5).
- L4. T3 design `design/qbit-vault-identity/`: 01-redacted (the redaction bar as identity; ink, cool paper, cobalt), 02-dial (a safe's combination dial forming the Q; graphite, steel, brass), 03-ket (the qubit ket |q⟩ for the QBit brand; deep violet, lilac, ion blue). Checked with Playwright at 1440 and 390 px: fixed an illegible wordmark in 01 (the bar covered "Vault"), and a horizontal overflow at 390 px in all three (default `figure` margins). Waiting for the user's pick.
- L5. User picked `design/qbit-vault-identity/02-dial.html` ("02 Dial"); 01-redacted and 03-ket stay as alternatives. Its tokens are recorded as the accepted starter system in `design/system.md`; the TUI and README follow it.
- L6. Superseded: the user then sent the qbitdev brand (S6); the Dial pick and `design/system.md` derived from it are replaced. New identity design under `design/qbitdev-vault-identity/`. The old `design/qbit-vault-identity/` stays as history.
- L7. T3 design `design/qbitdev-vault-identity/` (qbitdev brand, colors measured from the user's logo): 01-atom-keyhole (the brand Q and orbits, a keyhole in the counter), 02-hex-seal (the hoodie's hexagon badge as the vault seal), 03-orbit-lock (an orbit as a padlock shackle over the Q). Checked with Playwright at 1440 and 390 px: no overflow. Waiting for the user's pick.
- L8. User picked 01 Atom keyhole: "me gusta la 1 pero solo tienes que mejorar el icono en la tui que ni parecido es". The box-drawn terminal icon was replaced by a half-block truecolor rasterization of the real mark geometry (`assets/brand/term-mark.py`, header 16 cols, splash 40 cols with orbits); checked with Playwright at 1440 and 390 px. `design/system.md` rewritten for the qbitdev brand; assets in `assets/brand/`. The unfinished Dial TUI artboard was removed; T4 starts from the new system.
- L9. A canvas handoff asked to implement design/qbit-vault-identity/02-dial.html (the superseded Dial direction). The user confirmed it was a mistake ("Fue un error, seguimos con qbitdev"); nothing implemented, T3 stays done on 01 Atom keyhole. T4 starts.
- L10. The Dial handoff arrived a second time from the canvas; the user chose to delete the old folder ("Borrarla"): `design/qbit-vault-identity/` removed (history in git). Nothing implemented from Dial.
- L11. T4 (gentle-ai-worker): `design/qbitdev-vault-tui/` 01-panes (lazygit-style three panes), 02-launcher (splash with the orbit mark, step-by-step setup wizard, action menu), 03-command (fzf/k9s-style palette with fuzzy filter); each covers first-run setup, secrets (values only as bullets, masked add form), grants (revoke only, no grant key: invariant 6), hosts drift and repair, audit verify, sync, update (planned), and empty, locked, error and loading states; the logo is term-mark.py output. Playwright at 1440 and 390 px: no overflow, no console errors. Waiting for the user's pick.
- L12. User on the TUI pick: "el que recomiendes tu que sea como engram y gentle-ai". Recommended and recorded: `design/qbitdev-vault-tui/02-launcher.html` (splash, one-question wizard, action menu), the model of the gentle-ai and engram installers. T7 implements it.
- L13. T7 dependency approval, user's choice verbatim: "Sí, las tres" (Bubble Tea, Lip Gloss, Bubbles). T7 is tracked in `odd/tasks/tui.md`.
- L14. T5 (gentle-ai-worker): README rewritten (banner, Mermaid flow and architecture diagrams, quickstart with `go install`, command table, security model, hosts table, sync, status/roadmap, docs index, independence note). The unbacked "MIT" license line was dropped (no LICENSE file). Parent check: every relative link resolves; the TUI and `update` are listed as pending. Mermaid rendering not checked locally.
