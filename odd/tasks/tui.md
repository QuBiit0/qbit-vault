# Feature: interactive TUI (02 Launcher)

The interactive terminal app for QBit Vault, following `design/qbitdev-vault-tui/02-launcher.html` and `design/system.md`. Parent: `odd/tasks/polish.md` T7. Branch `feat/cli-skeleton`.

## Specs

- S1. User (polish L1, verbatim): the TUI must be "interactiva como gentle-ai o engram: setup, config, self-update, management". User pick (polish L12, verbatim): "el que recomiendes tu que sea como engram y gentle-ai" → direction `02-launcher` (splash, one-question-at-a-time setup wizard, then an action menu).
- S2. Dependencies approved by the user (verbatim choice): "Sí, las tres" — `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/lipgloss`, `github.com/charmbracelet/bubbles`. Record them in AGENTS.md § Conventions as allowed. No other new dependency.
- S3. Entry: `qbit-vault tui` opens the TUI. `qbit-vault` with no arguments opens it only when stdin and stdout are terminals and neither `--json` nor `QBIT_VAULT_NO_TUI=1` is set; otherwise it keeps today's behavior exactly (help text; `--json` → usage error "no command given"). `--home` is honored.
- S4. Security (AGENTS.md invariants): the TUI process never holds a secret value. It shows names, layers, descriptions, grant metadata and status only. Adding or editing a value suspends the TUI and runs the existing capture flow (native dialog or masked terminal prompt), then resumes. The TUI can list and revoke grants but has no way to create or approve one (invariant 6). Pairing codes and recovery keys are never rendered in the TUI. Every mutation goes through the same code paths as the CLI commands (snapshots, atomic writes, audit).
- S5. Visual (design/system.md): splash with the 40-column mark with orbits, 16-column mark in headers, rendered from the mark geometry with truecolor half blocks (Go port of `assets/brand/term-mark.py`); palette tokens from design/system.md; selected row in the blue→green gradient (or `#1C6E9E` background without truecolor); `--no-color` / `NO_COLOR` drop colors and the mark degrades to the plain wordmark.
- S6. Screens (from the artboard): Splash; Setup wizard (vault + key storage, hosts to register among claude-code/codex/pi, review, apply, done → offer "add a secret"); Main menu (Secrets, Grants, Hosts, Audit, Sync, Doctor, Update, Quit) with each item's hint stating consequences; Secrets list (names only) with add/describe/remove; Grants with revoke; Hosts with status, drift and repair (= `sync`); Audit with verify and recent entries; Sync status (linked or not, last round, conflicts count); Doctor report; Update screen marked planned (no network). States: empty vault, locked vault (offer unlock), and errors as screens with a next action (no stack traces). `esc` goes back one level, `q` quits from the menu, `ctrl+c` quits anywhere.
- S7. Tests: model-level tests through the public `tui` API (feed key messages, assert rendered view and backend calls) with a fake backend; a leak test asserts no `TESTSECRET_` fixture appears in any rendered frame across add/list flows; the S3 entry rules are tested through `cli.Execute` (non-TTY no-args still prints help).

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T1 | S2, S3, S5, S7 | worker | | pending |
| T2 | S4, S6, S7 | worker | | pending |
| T3 | S4, S6, S7 | worker | | pending |
| T4 | S1, S6 | inline | | pending |

- T1: dependencies + AGENTS.md; `internal/tui` shell (model, router, theme from tokens, Go mark rasterizer with tests), splash + main menu, `Backend` interface + fake, `qbit-vault tui` and the no-args TTY rule.
- T2: setup wizard and secrets/grants screens through a `cli`-side backend adapter over the existing command code (init, host registration, list, set via suspended capture, rm, describe, grants list, revoke).
- T3: hosts, audit, sync, doctor, update (planned) screens + empty/locked/error states + leak test.
- T4: docs (docs/CLI.md, README status, INSTALL) and close.

## Log

- L1. User (polish.md L1, verbatim request for the TUI): "interactiva como gentle-ai o engram: setup, config, self-update, management".
- L2. Direction picked (polish L12): 02 Launcher. Dependencies approved: "Sí, las tres" (Bubble Tea, Lip Gloss, Bubbles).
- L3. Decision: values never enter the TUI process; capture is delegated to the existing prompt backends by suspending the TUI (Bubble Tea strings cannot be wiped).
