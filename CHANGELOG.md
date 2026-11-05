# Changelog

All notable changes to QBit Vault. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions will follow [Semantic Versioning](https://semver.org/) from the first tagged release.

## [Unreleased]

First version, to be tagged `v0.1.0-beta.1`.

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
