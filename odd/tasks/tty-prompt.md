# Feature: roadmap slice 1.9, terminal prompt backend and interactive capture

`internal/prompt`: a backend interface with the terminal (`tty`) backend that reads from the
controlling terminal with echo disabled, plus the prompt token issued to the broker's own prompt.
Wires interactive capture into `set`, passphrase entry into `init`/unlock, and confirmations into
`grant`, `rm`, `mv`. Branch `feat/cli-skeleton`.

## Specs

- S1. ROADMAP 1.9: "`prompt`: tty backend + prompt token; `set` interactive" (R-CAP-01, R-CAP-04).
- S2. R-CAP-01: "... with a final fallback of reading from `/dev/tty` (or `CONIN$`) with echo disabled."
- S3. R-CAP-02: "The prompt MUST show the secret name and the agent-supplied reason". R-CAP-03: scope choices in the same interaction. R-CAP-03a: layer choice when `cwd` is inside a repository, default `suggested_layer` or `global`.
- S4. R-CAP-04: "Blank or whitespace-only input MUST fail the capture without writing anything. Surrounding whitespace MUST be trimmed. Cancel MUST leave the vault unchanged."
- S5. CLI.md `prompt --name NAME --reason R [--value] [--scopes ...] [--layers ...]`: "Opens the native capture dialog; prints `{token, scope, layer, value_on_fd:3}`"; `QBIT_VAULT_PROMPT` forces a backend.
- S6. STORAGE.md: "the broker issues a one-time random token to its own prompt backend, and `grant` must present it".
- S7. AGENTS.md invariants 1, 2, 6; DECISION L6 of odd/tasks/grants.md (R9).

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S2, S4, S7 | worker | `internal/prompt`: Backend interface, Request/Answer, tty backend (controlling terminal, echo off, masked), fake backend for tests | feat(prompt) | done |
| T2 | S1, S3-S7 | worker | CLI wiring: `set` interactive (value, layer, optional grant), passphrase prompts for `init --passphrase` and unlock, confirmations for `grant`, `rm`, `mv --yes` overwrite; `prompt` plumbing command with token; docs | feat(cli) prompt | done |

## Log

- L1. User: "si" (continue with slice 1.9).
- L2. Decision: dependency `golang.org/x/term` for echo-disabled reads (official Go sub-repository like x/crypto and x/sys; the standard library has no portable no-echo read). Justified in the commit body.
- L3. Decision: the tty backend reads from the controlling terminal (`/dev/tty`, `CONIN$`/`CONOUT$`), never from the process stdin, so a pipe the agent controls cannot answer it. When no controlling terminal can be opened, the backend is unavailable and the command fails with a typed error naming the missing terminal, never falls back to stdin.
- L4. Decision: confirmations (`grant`, `rm` without `--yes`, `mv` overwrite) move from stdin y/N to the tty backend; `--yes` stays for scripts on `rm` and `mv` (they only narrow or are user-run). `grant` keeps requiring a tty confirmation or a prompt token (R9 residual unchanged until slice 1.10).
- L5. Decision: `qbit-vault prompt` in this slice supports the tty backend only; it prints `{token, scope, layer}` as JSON on stdout and writes the value (when `--value`) to file descriptor 3 if open, else refuses (`--value` without fd 3 is a usage error). Native backends arrive in 1.10.
- L6. Decision: the unlock passphrase prompt is used when the vault is in passphrase mode and no cache entry exists, only when a controlling terminal is available; otherwise `vault_locked` as today.
- L7. Worker result: all checks green (cli suite ~200 s). The tty backend uses its own raw-mode loop (Ctrl-C cancels and restores instead of killing the process) and shows no mask, so the length is not revealed. The real console path (/dev/tty, CONIN$) could not run in this environment; only its line logic is tested. `prompt --value` is refused on Windows until slice 1.10. Follow-up: token issuance by `prompt` has no audit event of its own.
- L8. Independent verify: S1-S7 pass, no blockers (real PTY runs under WSL: echo off, terminal restored, stdin pipes never answer, ANSI/newline spoofing escaped, fd 3 value delivery). Fixed after it: a multi-line paste left the remaining lines in the tty queue for the shell to run and log (invariant 2) - now trailing input refuses the value and the input queue is flushed on every exit; prompt timeout (default 5 min, QBIT_VAULT_PROMPT_TIMEOUT); `prompt` audit event; capture records carry `reason: manual entry`. Residual: the `from: host` label comes from the caller's session (R4).
