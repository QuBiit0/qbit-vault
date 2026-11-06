# Changelog

All notable changes to QBit Vault. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions will follow [Semantic Versioning](https://semver.org/) from the first tagged release.

## [Unreleased]

### Changed

- Permission dialogs inside a repository: the session answer becomes `12 hours: in this project, even if the agent restarts`. A session ended whenever the agent restarted (a restarted MCP server is a new session), so the same question came back; the new answer is a project grant that ends after 12 h. Outside a repository the session answer stays. The `prompt` command and `set --grant` are unchanged.

### Added

- `qbit-vault-server`: `QBV_SERVER_BOOTSTRAP_INVITE` gives a server with no account its first invite through the environment, for hosted platforms where `invite` cannot be run inside the shell-less container. Hash only, single use, 24 h, never logged, ignored once an account exists.

## [0.1.0-beta.6] - 2026-11-06

### Added

- A global secret can be granted `Project: always in this project, until you revoke it`: the permission is bound to the repository it was approved in, survives agent restarts and new conversations there, and never reaches another repository (a nested one included). Before, global secrets offered only `once` and `session`, so a restarted agent asked again.

### Changed

- The session choice reads `Session: until the agent restarts (max 12h)`, which is what it does: a restarted agent is a new session.

## [0.1.0-beta.5] - 2026-11-06

### Added

- Before saving a typed value, qbit-vault points out pasted surrounding quotes or invisible characters (zero-width spaces, BOM, no-break space) and offers to drop them, the usual reason a service rejects a token that looks right. A clean value asks nothing more.

### Changed

- The capture and permission dialogs use plain words: who asks (the agent's name and a short session id), the secret, why, where it is saved, and that the value stays hidden from the agent. Permission choices read `Once: only the next command`, `Session: this agent session, for 12h`, `Project: always in this project, until you revoke it` and `Don't allow`.
- The agent skill says what to do when a service rejects a credential: check presence with `${#NAME}` only, tell the user what the service expects, propose one replace, and stop if that fails too.
- Replacing a value at the agent's request (`secret_manage replace`) is one decision that also sets its permission (`Replace, then Session: ...`), so the agent's next command needs no second permission dialog.

## [0.1.0-beta.4] - 2026-11-06

### Changed

- `init` on a machine without an OS keychain (WSL, a headless Linux box) asks for a passphrase instead of failing with `vault is locked`, and says why; with no terminal to ask it names `--passphrase --passphrase-stdin`.

### Fixed

- `prompt --value` refuses a terminal on file descriptor 3 (the value would show on screen); `/dev/null` still works. On Linux the Go runtime's epoll descriptor is recognized by asking the kernel.

## [0.1.0-beta.3] - 2026-11-05

### Added

- The `qbit-vault` agent skill: `init` and `sync` install it for Claude Code (`~/.claude/skills`) and, as one shared file, for Codex and Pi (`~/.agents/skills`); it is rewritten only when a release changes it, `doctor` reports a stale copy, and `uninstall` removes it. A user's own `SKILL.md` at that path wins: it is never replaced, checked or removed.

### Fixed

- Registering a host whose config already held the qbit-vault entry (for example after `state.json` was lost) no longer fails with `vault: invalid host record`.

## [0.1.0-beta.2] - 2026-11-05

First public release. The `v0.1.0-beta.1` tag exists but its release job failed before publishing anything; it is kept, not moved (published versions are never overridden).

### Added

- One-line install: `scripts/install.sh` (Linux, macOS) and `scripts/install.ps1` (Windows) download a release archive and verify its SHA-256 before installing. Re-running them upgrades an existing install in place (also a `go install` copy), atomically and with agents running, and runs `qbit-vault sync` when the vault is already set up; GoReleaser release archives for linux, darwin and windows on amd64 and arm64 with `checksums.txt` and GitHub build provenance.
- `qbit-vault version` reports the module version of a `go install` build and the commit of a checkout build.

- Encrypted local vault (XChaCha20-Poly1305) with the master key in the OS keychain or behind a passphrase; global and per-project layers; snapshots and restore.
- Grants (once, session with a 12-hour default, project), approved only by the user in a native dialog or the terminal; revocation.
- Per-command injection with streaming redaction of every active value and its common encodings, and a guard against commands that would print a value.
- Hash-chained audit log with verification.
- MCP server with four tools for coding agents: `secret_list`, `secret_request`, `secret_exec`, `secret_manage`.
- Host registration for Claude Code (MCP, hooks, deny rules), Codex and Gentle Shell/Pi (MCP), with config snapshots and byte-exact uninstall.
- Zero-knowledge self-hosted sync with `qbit-vault-server` (Docker image): device pairing, three-way merge, conflicts, history and restore, account rekey and device revocation.
- Interactive TUI (`qbit-vault tui`, or `qbit-vault` with no arguments in a terminal): first-run wizard and a three-pane home for secrets, grants, hosts, audit, sync and doctor. It never holds a secret value.
- `doctor` health report.

### Changed

- The broker contract is `qbit-vault.secrets-broker/v1` (was `gentle-ai.secrets-broker/v1` before any release).

### Fixed

- Redaction now also catches the Go 1.26 JSON encoding of a value that contains invalid UTF-8.
