# Changelog

All notable changes to QBit Vault. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions will follow [Semantic Versioning](https://semver.org/) from the first tagged release.

## [Unreleased]

First version, not yet tagged.

### Added

- Encrypted local vault (XChaCha20-Poly1305) with the master key in the OS keychain or behind a passphrase; global and per-project layers; snapshots and restore.
- Grants (once, session with a 12-hour default, project), approved only by the user in a native dialog or the terminal; revocation.
- Per-command injection with streaming redaction of every active value and its common encodings, and a guard against commands that would print a value.
- Hash-chained audit log with verification.
- MCP server with four tools for coding agents: `secret_list`, `secret_request`, `secret_exec`, `secret_manage`.
- Host registration for Claude Code (MCP, hooks, deny rules), Codex and Gentle Shell/Pi (MCP), with config snapshots and byte-exact uninstall.
- Zero-knowledge self-hosted sync with `qbit-vault-server` (Docker image): device pairing, three-way merge, conflicts, history and restore, account rekey and device revocation.
- Interactive TUI (`qbit-vault tui`, or `qbit-vault` with no arguments in a terminal): first-run wizard and a three-pane home for secrets, grants, hosts, audit, sync and doctor. It never holds a secret value.
- `doctor` health report.

### Fixed

- Redaction now also catches the Go 1.26 JSON encoding of a value that contains invalid UTF-8.
