# Changelog

All notable changes to QBit Vault. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- A message blocked by the `user-prompt` hook now says what matched and what to do (#45). The reason names every stored secret whose value is in the message (name only, sorted, at most 5 then `and N more`; a `[REDACTED:X]` already in the text is not reported) or the kind of well-known shape (GitHub token, AWS access key, Slack token, JWT, ...), never the text, and ends with fixed advice: store it with `qbit-vault set NAME`, or, when a background job or another agent's report printed it, run the command through `secret_exec`. The block itself stays: the host cannot rewrite a prompt, and letting it through would hand the value to the model. The agent skill now tells the model to run background jobs, scripts and subagent commands that use a credential through `secret_exec`, so their output and completion notice are redacted.

### Added

- `packages/qbit-vault-pi`, the Pi / Gentle Shell extension (distributed as a git tag, not on npm): `/vault list|set|rm|revoke|audit|doctor` commands the user runs without the model, a vault status in the footer (`🔐 <n> grants`, `🔐 vault`, `🔒 locked`), paste interception that asks to store a secret-shaped message in the vault and sends `secret://NAME` instead (or nothing), and a revoke of the session's grants when Pi exits. It never opens the vault and never keeps a value: it runs the `qbit-vault` binary and passes values over stdin only. A new `pi-extension` CI job typechecks, builds and tests it, and a Go test keeps its `secret-patterns.yaml` equal to `defaults/secret-patterns.yaml`. Terminal capture, a bash override, read/write guards and a sidebar entry are not in v1 (`docs/GENTLE_SHELL_EXTENSION.md`).
- Pi extension distribution without npm: a manual workflow `pi-extension-release` builds and tests the package, assembles a tree with a `package.json` that has no `devDependencies` or `scripts` (`packages/qbit-vault-pi/scripts/assemble-dist.mjs`), `dist/`, `secret-patterns.yaml`, `README.md` and `LICENSE`, commits it (no parent the first time, then the previous `pi-extension` head, never forced) and pushes the immutable tag `pi-v<version>`; it refuses a tag that exists. Install with `gentle-shell -- install git:github.com/qbitdevz/qbit-vault@pi-v0.1.0` or `pi install git:github.com/qbitdevz/qbit-vault@pi-v0.1.0`. `init` and `sync` now print that command, for the Pi host only and as a suggestion, and never run it.

## [1.1.0] - 2026-11-10

Self-update, Windows dialogs from WSL, the passphrase asked on demand, a sturdier MCP server, and the fix for #42.

### Fixed

- `secret_list` showed a project grant that `secret_exec` then refused with `grant_required` (#42). The listing matched a grant by record only, while `exec` also requires a project grant of a global secret to be for the exact repository it was approved in, so a grant approved in one repository showed as active from another directory. The listing now uses the same check as `exec` (without spending a `once` grant) for the caller's repository root; a grant that exists but does not apply is `"grant":null` with a new optional `grant_note` (contract 1.0 stays valid: the field is additive), and the `grant_required` message says when the grant is for another directory or for an earlier value of the secret. The agent skill says what to do.
- A tool call that waits for a dialog is no longer lost when the client gives up. The MCP call's context now reaches the dialog: when the client cancels, the native helper is killed (or the terminal prompt stops) and nothing is stored, granted or audited as a capture or grant, even if the user answered at that instant; the call ends with a retryable `internal` refusal and starts no cooldown. While a call with a progress token waits, the server sends `notifications/progress` every 15 s so clients keep waiting.
- Two concurrent `secret_request` / `secret_manage` calls no longer open two dialogs at once: the server shows one at a time, and a waiting call that is cancelled never shows its dialog.
- The agent skill now says what to do for every refusal type (`rate_limited`, `invalid_name`, `no_project`, `not_model_callable`, `vault_corrupt`, `timeout`, `contract_mismatch`, `internal`); a test fails when a refusal type has no row. The `vault_locked` row no longer says the terminal is the only way to unlock.
- Under WSL the capture, permission and passphrase dialogs are the Windows ones (`powershell.exe` at its fixed `/mnt/c/Windows/…` path) instead of sending the user to a terminal: WSL is detected by `WSL_DISTRO_NAME` or the WSLInterop registration, the helper is chosen before `zenity` and `kdialog` whether or not `DISPLAY` is set, and `QBIT_VAULT_PROMPT` still forces a backend. `doctor` names the backend (`prompt: powershell (WSL)`); it says nothing when the backend is the terminal.

### Added

- An agent no longer sends you to a terminal to unlock the vault. In passphrase mode, when `secret_request` or `secret_manage` (and the host transport's `request`, `manage`, `grant`, `revoke`) find the vault locked, they ask the passphrase in a dialog headed `Vault passphrase` that names the requester and the secret (`Claude Code wants to use GITHUB_TOKEN. Unlock the vault to continue.`). A right passphrase unlocks with the same cache and time as `qbit-vault unlock`, then the call asks for its own permission as usual (unlocking never grants); a wrong one answers the retryable `vault_locked`; cancelling is `user_declined`; with no prompt backend nothing changes. The unlock is audited (`unlock`: requester and names, never the passphrase). `secret_exec` and `secret_list` still never open a dialog: their `vault_locked` message now tells the agent to call `secret_request`, and the skill says so. `QBIT_VAULT_NO_PROMPT_UNLOCK=1` turns the dialog off for agent calls; commands you run are not affected.
- `qbit-vault update` and `qbit-vault update --check`: bring the installed binary to the latest stable release. It confirms through the out-of-band prompt (user-only; `not_model_callable` without one), downloads the archive for your system and `checksums.txt` over HTTPS, verifies the SHA-256, and swaps the binary atomically (on Windows the running `.exe` is renamed to `.old-<id>` and cleaned on a later run). Any failure leaves the installed binary untouched. It then runs `sync` of the new binary when the vault is set up (`QBIT_VAULT_NO_SYNC=1` skips it). `--check` only reports; `--json` is supported for both. A build that is not a release refuses to update itself. The new binary is flushed to disk before the swap (and the directory after it on POSIX). The vault, grants, audit log and sync state are never opened or written. In the TUI, `c` (check now) keeps the last known result until the new one arrives, and a failed re-check keeps a known newer release.
- The TUI tells you about a new version: every time it opens it checks for a newer release in the background (5 s timeout; the first screen never waits, and no network only shows `could not check for updates` in the Update section). A newer release puts `update available <version>` in the header and the Update section shows the current and latest versions, the release notes link and `u update now`, which runs `qbit-vault update` with the TUI suspended for the confirmation. `QBIT_VAULT_NO_UPDATE_CHECK=1` turns the open-time check off (the section offers `c check now`); a build that is not a release makes no check and does not offer `u`. The TUI still holds no secret value and creates no grant.

## [1.0.0] - 2026-11-10

The first stable release. QBit Vault now lives at `github.com/qbitdevz/qbit-vault`. Everything below is on top of 0.1.0-beta.17.

### Fixed

- A device the account revoked can join again (`remote join`, pairing or `--recovery`): it takes a new device id and its project roots move to it, so project secrets still resolve; the old id stays revoked. A refused join changes nothing.
- The joiner's confirmation code is asked as its own question, headed `Confirmation code`, without the `Saved in` / `Value` lines of a secret request.
- `remote devices` shows `last seen` from the server and `last sync` only when known, instead of `last sync: never` for a device that only pulls (`--json` adds `last_seen`).
- A new passphrase that does not match its confirmation (vault, export) is asked again, up to 3 times, before it fails with `passphrases do not match`.
- `request` names the field that was stored meanwhile when several are asked.
- `restore` reports an unreadable `keys/retired.enc` instead of "backup cannot be opened"; vault temp files are created with `O_EXCL`; promoting a staged key (`rekey`) and `key.enc` writes retry the transient sharing errors of Windows; `init --passphrase` stops when the OS keychain cannot be read instead of assuming it holds no key.
- Windows: `doctor` and `perm.Check` no longer call a file with an empty ACL (nobody can open it) or an unrelated owner private, and `EnsureFile` repairs the ACL.
- A stale lock is broken under a `.break` guard that re-checks its age, so two processes cannot delete a lock another one just took.
- `audit --verify` and `doctor` report a missing `audit.head` next to two or more audit records as `head_mismatch` (it was valid, so deleting the head hid a truncation); a log of one record without a head is still fine.
- A declined or cancelled `request` also blocks the same name and layer for every session for 30 s, so a new session cannot re-prompt it at once.
- `request` no longer overwrites a value that `set` stored while the prompt was open: it answers `internal` (retryable) `<NAME> changed while it was being asked; ask again` and stores nothing.
- `import` refuses names that change how a child starts (`LD_PRELOAD`, `PATH`, …), with the same message as `set` and `exec`.
- The dump guard inspects the script of `pwsh -c`, `-co`, `-com`, … (any prefix of `-Command`).

### Changed

- Documented limit: `keys/retired.enc` has no rollback counter in `state.json` (THREAT_MODEL R8, STORAGE § Retired keys).
- The project moved to `github.com/qbitdevz/qbit-vault` (the Go module path, the installers, the release links and the server image `ghcr.io/qbitdevz/qbit-vault-server` follow). Old links redirect; images up to 0.1.0-beta.17 stay at `ghcr.io/qubiit0/qbit-vault-server`.
- The README is rewritten for the first stable release, with a terminal GIF, a TUI screenshot and a TUI tour (`assets/demo/`, recorded from the real binary on a throwaway demo vault; `bash assets/demo/make.sh` regenerates them). Every document was checked against the binary's `--help` and behavior: text that called finished things planned, pending or unpublished (the server image, the installers, build provenance) is gone, and what is still not built (npm package, Homebrew formula, Pi extension, Minisign signatures, `qbit-vault update`) is stated plainly in `docs/ROADMAP.md`.

## [0.1.0-beta.17] - 2026-11-07

This release also carries the build provenance attestation and the `ghcr.io/qubiit0/qbit-vault-server` image that 0.1.0-beta.16 lacks: its attestation step failed on a transient error of the Sigstore transparency log after the release was published, so its server-image job did not run. The beta.16 binaries and checksums are unaffected.

### Fixed

- Dump guard and pre-bash hook: `pwsh -EncodedCommand` is refused after any valued option (`-WorkingDirectory /f`, `-ep:Bypass`, quoted values), as `-e:VALUE`, and with typographic dashes; `bash --rcfile FILE -c …` no longer hides its script. The hook's command scanner keeps non-ASCII bytes intact.
- The dump guard's compiled-pattern cache is capped (64 name sets).
- `remote rekey` and `remote revoke-device` print the unknown-device notice and audit the revocations as soon as the server accepted the rotation, so a later local failure cannot skip them.
- `install.sh` picks the newest release from minified (one-line) JSON too.
- The dialog that shows the confirmation code on the approving device is headed `Confirmation code`, not `Pairing code`.

### Security

- Docs: the pre-bash hook is best effort (the boundary is the prompt plus redaction), the POSIX tree kill reaches the process group only, and a project is identified by its path (`THREAT_MODEL.md` R17-R19, `STORAGE.md`).
- `exec` refuses to inject a secret under an environment name that changes how the child starts (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `DYLD_*`, `BASH_ENV`, `ENV`, `PATH`, `PATHEXT`, `PYTHONSTARTUP`, `NODE_OPTIONS`, `PERL5OPT`, `RUBYOPT`, `COMSPEC`, `PROMPT_COMMAND`); `set` refuses such a name. Usage error naming the variable, never a value.

## [0.1.0-beta.16] - 2026-11-07

### Fixed

- A device that joins by pairing starts with the version floor of the device that approved it (`last_version` inside the key envelope), so a server that serves it an older version on its first round is refused as `remote_rollback`. An envelope from an older approver still joins. A device running 0.1.0-beta.15 or older cannot join through an approver on this version (it stops with `the pairing could not be confirmed` and nothing is kept): install the latest version on the new device first.
- `remote rekey` and `remote revoke-device` no longer fail when the server lists a device the roster does not know (left by an interrupted approve): it is revoked in the same call (`unknown device <id> was revoked`).
- Conflicts dropped for age (30 days) or count (100) are no longer silent: the round audits `<n> old conflict(s) discarded` and `remote sync` says so on stderr.

### Changed

- Known limitation, documented: a revoked device cannot rejoin with its id. Export what only it holds (`qbit-vault export FILE`), then join from a fresh vault home as a new device (REMOTE_SYNC § 4.5).

## [0.1.0-beta.15] - 2026-11-07

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
