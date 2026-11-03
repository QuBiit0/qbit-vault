# Feature: roadmap slice 1.10, native prompt backends

Native out-of-band dialogs for capture and confirmation: PowerShell/WinForms on Windows,
`osascript` on macOS, `zenity`/`kdialog` on Linux desktops. They run outside the terminal the
agent controls, which closes the PTY residual (R9) wherever a desktop session exists. Branch
`feat/cli-skeleton`.

## Specs

- S1. ROADMAP 1.10: "`prompt`: osascript, powershell, zenity/kdialog backends" (R-CAP-01).
- S2. R-CAP-01: "otherwise a native dialog (macOS `osascript` with hidden answer, Windows PowerShell `Read-Host -AsSecureString` in a separate window, Linux `zenity --password` / `kdialog --password`), with a final fallback of reading from `/dev/tty` (or `CONIN$`) with echo disabled."
- S3. AGENT_INTEGRATIONS.md § Native capture dialog: "`gentle-vault prompt` picks a backend in order of availability, overridable with `GENTLE_VAULT_PROMPT`" (table: osascript, powershell, zenity/kdialog, tty). "The dialog always shows: secret name, the reason verbatim, the host and session id, the project label (or `global`), and whether the value is **new** or **already stored (grant only)** ... Values flow back to the broker over a pipe/fd, never through stdout."
- S4. THREAT_MODEL R4 (dialog spoofing) and R9 (PTY-owning agent answers the tty prompt).
- S5. AGENTS.md invariants 1, 2, 6.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1-S5 | worker | `internal/prompt` native backends, availability probing, selection order; CLI wiring; `prompt --value` on Windows; docs | feat(prompt) native | done |

## Log

- L1. User: "en español por favor.. continua? y cuanto falta?" (continue with slice 1.10).
- L2. Decision: selection order with `GENTLE_VAULT_PROMPT` unset: the platform's native backend when a desktop session is available (Windows interactive session; macOS GUI session; Linux with `DISPLAY` or `WAYLAND_DISPLAY` and zenity or kdialog on PATH), else tty. `GENTLE_VAULT_PROMPT=tty` forces the terminal (for users who prefer it); this re-opens the R9 residual for that user and is documented.
- L3. Decision: the value travels from the dialog helper to gentle-vault over the helper's own stdout pipe, which is a private anonymous pipe between the two processes and never reaches the agent; the AGENT_INTEGRATIONS wording "never through stdout" refers to gentle-vault's own stdout and is clarified. The helper script is passed on stdin or as an argument containing no secret; the value is never in argv or environment.
- L4. Decision: Windows uses a WinForms dialog driven by `powershell.exe -NoProfile -NonInteractive -STA` (masked TextBox with `UseSystemPasswordChar`, scope and layer choices, Cancel); the dialog is TopMost. macOS uses `osascript` `display dialog ... with hidden answer` and `choose from list`. Linux uses `zenity --password` / `--list` / `--question`, or `kdialog --password` / `--radiolist` / `--yesno`.
- L5. Decision: native backends cannot be exercised automatically in CI; each backend builds its helper command through a pure function that is unit-tested (exact argv/script, escaping of name and reason, no value anywhere), and the process runner is a seam. A manual smoke checklist goes into docs/TESTING.md.
- L6. Worker result: all checks green. Real PowerShell parser run over every script with 22 hostile strings; real WinForms dialogs opened and auto-clicked (value, choice, confirm, decline) - this caught a PowerShell `-Command -` quirk that drops multi-line statements, now guarded by a test. Deviations: zenity uses `--entry --hide-text` (`--password` cannot show the request text); PowerShell data travels as base64 decoded in the script; `prompt --value` stays POSIX-only (fd 3); a named backend that is missing never falls back to tty. osascript, zenity and kdialog were not run (no macOS/Linux desktop): unit-tested only, manual checklist in TESTING.md.
- L7. Independent verify: S1-S5 pass, no blockers (real PowerShell parser over 21 hostile scripts, real WinForms dialog read back via Win32 messages: text byte-identical, TopMost, ES_PASSWORD, value exact, timeout kills the helper). Fixed after it: kdialog renders rich text, so its texts are now HTML-escaped; powershell.exe and osascript are resolved by absolute system path, never PATH; R9 states that same-user UI automation drives the dialog trivially.
