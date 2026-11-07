# Changelog

All notable changes to QBit Vault. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Sync URLs are compared as origins: case, a default port (`:443`/`:80`), a path or a trailing slash no longer make a login fail. When a login is still refused because the server is configured for another URL, the message names both (`the server is configured as <origin>; you used <url>. Use the same URL ...`). `/v1/info` gains an optional `origin` field.
- `remote register`: the check of the recovery key's last four characters no longer ends after 5 wrong answers; it repeats until it is right or you cancel, and a cancel says `run 'qbit-vault remote recovery-key --rotate' to get a new recovery key`.
- Server: creating a pairing for a code that is already pending is refused (409) instead of overwriting it; a refused `POST /v1/rekey` leaves no stored version; `POST /v1/auth/token` validates the device id like `challenge`.
- A recovery key whose body starts with `QVR1` is recognized with and without the `QVR1-` prefix.

### Changed

- `remote approve` asks two things, the pairing code and the device name. The name dialog is the consent (it says the device will be able to read every secret; Cancel refuses) and Enter takes `device <n>`.

## [0.1.0-beta.14] - 2026-11-07

### Added

- The release publishes the sync server image `ghcr.io/qubiit0/qbit-vault-server` (linux/amd64 and linux/arm64, tagged with the release version and `latest`, version baked in). `deploy/compose.image.yaml` runs it with the same hardening as `deploy/compose.yaml`: copy one file, set `QBV_SERVER_PUBLIC_URL`, `docker compose up -d`. `deploy/README.md` and `docs/INSTALL.md` show that path first.
- The server answers `GET /` with a small status page with the QBit Vault branding, its version and API version (no account or device information, no script, no external request, strict security headers). Secrets are still never managed on the web.
- README "First 5 minutes" with a screenshot of the real permission dialog (`assets/screenshots/permission-dialog.png`) and one line on `Once` versus `Always: in this project`.

## [0.1.0-beta.13] - 2026-11-07

### Changed

- The one-line installers are release assets: every release carries `install.sh` and `install.ps1` (listed in `checksums.txt`), releases are regular releases, and the README and docs use `https://github.com/QuBiit0/qbit-vault/releases/latest/download/install.sh` / `install.ps1`. The copies in `scripts/` stay. The release notes link that version's `CHANGELOG.md` section instead of listing commits.
- The installers end with one next step, `next: run 'qbit-vault init'`, and `init` ends with `Restart your coding agents so they load QBit Vault.` when it registered or changed an agent.
- `qbit-vault sync` ends with `(to sync secrets between devices: qbit-vault remote sync)` when the vault syncs with a server; the README and `docs/CLI.md` explain the two `sync` commands.
- Every GitHub Action in CI and the release workflow is pinned to a full commit SHA, and Dependabot updates them weekly.
- Clearer errors: an existing master key and failed host registrations point to `qbit-vault doctor`, and a mistyped flag adds `see 'qbit-vault <command> --help'`. The TUI Update screen says `Re-run the install command to upgrade`.
- Docs: where the installers put the binary and how to remove the Windows `PATH` entry, a copy-pasteable `set` / `grant` / `exec` example, what to do when the sync server is lost or wiped, and a bold line saying sync is optional.
- Dialogs speak with one voice on Windows, macOS, Linux and the terminal. Every window is titled `QBit Vault` and its heading says what it is (`Secret request`, `Permission request`, `Confirm`, `Recovery key`, `Pairing code`, `Vault passphrase`, `Export passphrase`); the `qbit-vault:` title prefix is gone.
- The permission question names who asks and puts the reason on its own line: `Claude Code wants to use GITHUB_TOKEN (all projects).` / `Why: <reason>`. Replacing a value at an agent's request offers `Replace, allow once`, `Replace, always in this project`, `Replace, but ask me before each use` and `Don't replace`.
- Passphrase prompts say what they protect: `Vault passphrase`, `Export passphrase (protects this backup file)` (asked again as `Type the export passphrase again`) and `Passphrase of the export file`. `Who:` reads `you (qbit-vault)` for a command you run.
- Buttons say the action (`Save`, `Continue`, `Done`; `Confirm` / `Decline` is unchanged), the Windows confirmation highlights `Decline`, and the request lines are a two-column grid. The several-fields form has no `Value:` line; each box says whether it is hidden.
- Shorter, consistent copy: `Paste or type the value. The agent never sees it:`, `Value (hidden): `, `Type a number from 1 to N, or press Enter for the default.`, `No answer in time; nothing was saved.`, `Save it, don't allow yet`, a plainer quotes check, and `all projects` / `Only this project (<label>)` for layers everywhere. The TUI says `asked in a secure prompt` and `hidden`.

### Fixed

- `install.ps1` compares `PATH` entries ignoring a trailing `\` (no duplicate entry on a re-run) and turns a GitHub API failure into `could not reach the GitHub API (rate limit or network); set QBIT_VAULT_VERSION=vX.Y.Z and try again`.
- Ctrl-C at a terminal menu, y/N question or Press-Enter screen cancels (exit 1) instead of killing the process mid-write.
- Linux with only kdialog shows the recovery key and the pairing code in the terminal instead of failing; zenity dialogs are 480 px wide and their lists have no `Pick` / `Index` headers; the macOS icon is `note`, and `caution` only for a removal.

## [0.1.0-beta.12] - 2026-11-06

### Fixed

- Dump guard: it reads the script of a shell called with options before `-c` (`bash -o pipefail -c 'printenv'`, `sh --login -c …`, `bash -O extglob -c env`), which it used to let through.
- `pwsh`/`powershell` with an encoded command (`-e`, `-ec`, `-enc`, `-EncodedCommand`) is refused as `dump_command` while a secret is injected, and by the pre-bash hook.
- Redaction also matches the value in UTF-16LE and UTF-16BE (Windows PowerShell 5.1 `Out-File`), in command output and in files read by the post-read hook.
- `prompt --value` for a name that already exists issues a token bound to that record, so it cannot be redeemed against a record that replaced it.
- A panic in an MCP tool handler or a broker op answers the typed `internal` refusal and the server keeps serving; no panic text or stack is printed.
- The backup of the previous vault files is written with `fsync` like the live files.
- Linux: the unlock cache is used only when `XDG_RUNTIME_DIR` is on tmpfs; otherwise the passphrase is asked each time and nothing is written.
- A lock file stamped more than the stale age in the future (clock skew, a copied home) is treated as stale instead of "vault is busy" forever.

## [0.1.0-beta.11] - 2026-11-06

### Fixed

- Server hardening (`qbit-vault-server`; the client is unchanged):
  - `QBV_SERVER_TRUST_PROXY` is now the number of trusted proxies, and the client IP for rate limits is the Nth `X-Forwarded-For` entry from the right (it was the leftmost, which anyone could forge). `1` keeps its meaning of one proxy; use `2` behind Cloudflare and Traefik. Unset or `0` ignores the header; any other value exits 2.
  - Request bodies are capped at 64 KiB on every route except `PUT /v1/vault`, `POST /v1/rekey` and `POST /v1/accounts` (9 MiB): 413 `too_large`, nothing stored.
  - `QBV_SERVER_BOOTSTRAP_INVITE` must have at least 12 different characters (and 24 in total); a restart no longer extends its 24 h expiry; account creation is limited to 10 per hour per IP.
  - An invite is claimed atomically: two simultaneous account creations with one invite make one account.
  - Expired nonces, tokens and pairings (including their files) are swept; at most 1000 pairings are pending at once (then 429); the rate limiter evicts only expired entries instead of resetting every counter.
- Windows: the recovery key and pairing code dialogs always show the whole code (it sits alone in the selectable box, sized to its content; the explanation is above it).
- Linux: pressing Enter on a yes/no confirmation now declines, as on macOS and Windows (zenity `--default-cancel`; kdialog shows the confirmation as a list with Decline preselected, so Enter, Escape and closing the window all decline).
- `init` and `sync` no longer print an install command for the Pi extension (it is not published yet), and `--json` no longer has `install_command`.
- `SECURITY.md`: the latest release is the supported version.
- Sync client: it never follows a redirect (a 3xx answer is `remote_unreachable`), so sealed data only goes to the configured server.
- `remote approve`: once the server accepted the approval, the confirmation code is shown first; a later roster or sync failure is a warning, not an error.
- Installers: without `QBIT_VAULT_VERSION` they installed the first release the GitHub API lists, which orders by tag text, so `v0.1.0-beta.10` lost to `v0.1.0-beta.9`. They now take the release with the latest publish date. The installers are served from `main`, so the fix applies as soon as it merges.

## [0.1.0-beta.10] - 2026-11-06

### Fixed

- `export`: a vault whose only secrets are project layers not linked on this device says so instead of "the vault is empty"; an export too large to import back (over 64 MiB) is refused instead of written; `import --from-export` refuses a header asking Argon2id for more than 512 MiB (was 1 GiB).

## [0.1.0-beta.9] - 2026-11-06

### Added

- `qbit-vault export FILE`: an encrypted, portable backup of the whole vault (every layer and secret with its metadata, no grants or keys) sealed under a passphrase you choose at export time (at least 12 characters; Argon2id 128 MiB, XChaCha20-Poly1305). It needs no server, no sync and no account. `qbit-vault import --from-export FILE` restores it on any machine, including an empty vault just created by `init`: secrets return to their own layer, those with a name that already exists are replaced after a question (`--yes` skips it), every other secret and grant is untouched.
- Audit event `export` (a count only).

## [0.1.0-beta.8] - 2026-11-06

### Changed

- Windows dialogs follow the QBit Vault look (dark background, clear heading, Segoe UI, primary button on the right), and a recovery key or pairing code sits in a read-only box you can select and copy instead of typing it by hand.
- Permission questions from an agent offer three answers: `Once: only the next command` (preselected), `Always: in this project, until you revoke it` (inside a repository) and `Don't allow`. The session answer is gone (a restarted agent is a new session, so it kept asking), and so is the 12-hour answer of 0.1.0-beta.7. A global secret approved "always" is approved for that repository; another repository asks once. Outside a repository only once or no. `grant --scope session`, `set --grant session` and the `prompt` command's `--scopes` are unchanged.

## [0.1.0-beta.7] - 2026-11-06

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
