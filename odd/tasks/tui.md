# Feature: interactive TUI (Panes + Launcher wizard)

The interactive terminal app for QBit Vault: first run follows the splash and setup wizard of `design/qbitdev-vault-tui/02-launcher.html`; daily use follows the three panes of `design/qbitdev-vault-tui/01-panes.html`; tokens from `design/system.md`. Parent: `odd/tasks/polish.md` T7. Branch `feat/cli-skeleton`.

## Specs

- S1. User (polish L1, verbatim): the TUI must be "interactiva como gentle-ai o engram: setup, config, self-update, management". User pick (polish L12, verbatim): "el que recomiendes tu que sea como engram y gentle-ai" → direction `02-launcher`. Revised by the user (verbatim): "creo que la primera panes esa esta mejor", then chose "Panes + wizard del Launcher": first run = splash + one-question-at-a-time setup wizard from 02-launcher; afterwards the daily home is the three-pane layout from 01-panes (sections / list / detail, key hints in the footer, `1`-`7` jump to sections, `tab` moves focus between panes).
- S2. Dependencies approved by the user (verbatim choice): "Sí, las tres" — `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/lipgloss`, `github.com/charmbracelet/bubbles`. Record them in AGENTS.md § Conventions as allowed. No other new dependency.
- S3. Entry: `qbit-vault tui` opens the TUI. `qbit-vault` with no arguments opens it only when stdin and stdout are terminals and neither `--json` nor `QBIT_VAULT_NO_TUI=1` is set; otherwise it keeps today's behavior exactly (help text; `--json` → usage error "no command given"). `--home` is honored.
- S4. Security (AGENTS.md invariants): the TUI process never holds a secret value. It shows names, layers, descriptions, grant metadata and status only. Adding or editing a value suspends the TUI and runs the existing capture flow (native dialog or masked terminal prompt), then resumes. The TUI can list and revoke grants but has no way to create or approve one (invariant 6). Pairing codes and recovery keys are never rendered in the TUI. Every mutation goes through the same code paths as the CLI commands (snapshots, atomic writes, audit).
- S5. Visual (design/system.md): splash with the 40-column mark with orbits, 16-column mark in headers, rendered from the mark geometry with truecolor half blocks (Go port of `assets/brand/term-mark.py`); palette tokens from design/system.md; selected row in the blue→green gradient (or `#1C6E9E` background without truecolor); `--no-color` / `NO_COLOR` drop colors and the mark degrades to the plain wordmark.
- S6. Screens (from the artboard): Splash; Setup wizard (vault + key storage, hosts to register among claude-code/codex/pi, review, apply, done → offer "add a secret"); Home = three panes (01-panes): sections pane (Secrets, Grants, Hosts, Audit, Sync, Doctor, Update), list pane, detail pane, footer with the keys of the focused pane and each destructive key's consequence; Secrets list (names only) with add/describe/remove; Grants with revoke; Hosts with status, drift and repair (= `sync`); Audit with verify and recent entries; Sync status (linked or not, last round, conflicts count); Doctor report; Update screen marked planned (no network). States: empty vault, locked vault (offer unlock), and errors as screens with a next action (no stack traces). `esc` goes back one level, `q` quits from the menu, `ctrl+c` quits anywhere.
- S7. Tests: model-level tests through the public `tui` API (feed key messages, assert rendered view and backend calls) with a fake backend; a leak test asserts no `TESTSECRET_` fixture appears in any rendered frame across add/list flows; the S3 entry rules are tested through `cli.Execute` (non-TTY no-args still prints help).

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T1 | S2, S3, S5, S7 | worker | (T1) | done |
| T2 | S4, S6, S7 | worker | | pending |
| T3 | S4, S6, S7 | worker | | pending |
| T4 | S1, S6 | inline | | pending |

- T1: dependencies + AGENTS.md; `internal/tui` shell (model, router, theme from tokens, Go mark rasterizer with tests), splash + three-pane home skeleton (sections pane, empty list/detail placeholders naming the task that fills them), `Backend` interface + fake, `qbit-vault tui` and the no-args TTY rule.
- T2: setup wizard and secrets/grants screens through a `cli`-side backend adapter over the existing command code (init, host registration, list, set via suspended capture, rm, describe, grants list, revoke).
- T3: hosts, audit, sync, doctor, update (planned) screens + empty/locked/error states + leak test.
- T4: docs (docs/CLI.md, README status, INSTALL) and close.

## Log

- L1. User (polish.md L1, verbatim request for the TUI): "interactiva como gentle-ai o engram: setup, config, self-update, management".
- L2. Direction picked (polish L12): 02 Launcher. Dependencies approved: "Sí, las tres" (Bubble Tea, Lip Gloss, Bubbles).
- L3. Decision: values never enter the TUI process; capture is delegated to the existing prompt backends by suspending the TUI (Bubble Tea strings cannot be wiped).
- L4. Direction revised by the user: "creo que la primera panes esa esta mejor" → chose "Panes + wizard del Launcher" (recommended when asked "cual es la que vos recomendas?"): guided first run from 02-launcher, daily three-pane home from 01-panes.
- L5. T1 (gentle-ai-worker): bubbletea v1.3.10, lipgloss v1.1.0, termenv v0.16.0 direct (color profile pinning); bubbles is allowed in AGENTS.md but enters go.mod with T2, its first import. internal/tui: Go port of term-mark (pinned pixels within ±2 of the Python reference), theme, splash, three-pane home skeleton, backend-error screen; `qbit-vault tui` and the no-args TTY rule (help = baseline + exactly the tui line; --json and QBIT_VAULT_NO_TUI unchanged). gofmt, go vet, go test internal/tui and internal/cli green (cli 473 s). Home-screen tests were written after the code (direction changed mid-task): no RED observed for them. Parent check: rendered real View() frames (splash, home, hosts focus, locked) to HTML and screenshotted: they match 01-panes/02-launcher.
