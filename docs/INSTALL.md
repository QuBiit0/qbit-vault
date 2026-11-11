# Install: one command, then `qbit-vault init`

Each `v*` tag publishes a GitHub release with archives for Linux, macOS and Windows (amd64 and arm64), a `checksums.txt`, the two installer scripts and a build-provenance attestation (`.github/workflows/release.yml`, `.goreleaser.yaml`); 1.0.0 is the first stable one and the newest is listed in `CHANGELOG.md`. There is no npm package and no Homebrew formula (not built, `ROADMAP.md`).

## Quick path

1. Install the binary with one command (below).
2. Run `qbit-vault` (guided setup) or `qbit-vault init`, then `qbit-vault doctor`.
3. Restart your agent so it picks up the MCP server.

## One-line install

The two scripts are assets of every release, so `…/releases/latest/download/install.sh` and `…/install.ps1` always serve the newest reviewed version (they are listed in the release's `checksums.txt`). The same files live in `scripts/` in the repository.

```bash
# Linux / macOS
curl -fsSL https://github.com/qbitdevz/qbit-vault/releases/latest/download/install.sh | sh
```

```powershell
# Windows (PowerShell 5.1 or 7)
irm https://github.com/qbitdevz/qbit-vault/releases/latest/download/install.ps1 | iex
```

What the scripts do (`scripts/install.sh`, `scripts/install.ps1`; read them before piping them to a shell):

1. Pick the archive for your OS and architecture: `qbit-vault_<os>_<arch>.tar.gz` (`.zip` on Windows).
2. Resolve the version: `QBIT_VAULT_VERSION` if set, else the newest release **including pre-releases** (GitHub's `releases/latest` skips them): the one with the latest publish date among the last 100, because the releases API orders by tag text (`v1.0.10` sorts before `v1.0.9`).
3. Download the archive and `checksums.txt` over HTTPS and compare the SHA-256. On a mismatch, or an archive not listed, they stop with `checksum mismatch for <archive>: nothing was installed` (or `<archive> is not listed in checksums.txt`) and install nothing.
4. Choose the directory: `QBIT_VAULT_INSTALL_DIR` if set; else the directory of the `qbit-vault` already first on your `PATH`, when you can write to it (an upgrade in place, see below); else `~/.local/bin` (Linux, macOS) or `%LOCALAPPDATA%\Programs\qbit-vault` (Windows).
5. Replace the binary atomically: the new file is written beside the old one and renamed over it, so a failed download or a full disk never leaves a half-written `qbit-vault`. On Windows a running `qbit-vault.exe` (an agent's MCP server) is renamed aside to `qbit-vault.exe.old-<id>` first, which Windows allows, so the upgrade works with your agents open; if the copy fails the old binary is put back. The aside file stays while that process runs and the next install removes it. On Windows the directory is added to your **user** `PATH` (open a new terminal); on Linux and macOS the script tells you if the directory is not on `PATH`.
6. Finish: on a machine where the vault is already set up (`$QBIT_VAULT_HOME/state.json` exists, default `~/.qbit-vault`), run `qbit-vault sync` with the new binary so every registered agent points at it, and tell you to restart your agents; otherwise print the one next step, `next: run 'qbit-vault init'` (it checks the setup and ends by telling you to restart your agents). They never ask for, read or store a secret, never read your environment for values, and never run `init`; `sync` only re-applies the registrations you already made and reads no secret.

| Variable | Effect |
| --- | --- |
| `QBIT_VAULT_VERSION` | Tag to install, for example `v1.0.0` |
| `QBIT_VAULT_RELEASES_API` | Release list to choose the newest from (default: the GitHub releases API; the tests use a local file) |
| `QBIT_VAULT_INSTALL_DIR` | Target directory |
| `QBIT_VAULT_NO_PATH=1` | Windows only: leave the user `PATH` unchanged |
| `QBIT_VAULT_NO_SYNC=1` | Do not run `qbit-vault sync` after installing over a set-up vault |

Pass a variable to the piped script like this: `curl -fsSL …/install.sh | QBIT_VAULT_VERSION=v1.0.0 sh`, or in PowerShell `$env:QBIT_VAULT_VERSION='v1.0.0'; irm …/install.ps1 | iex`.

**Verifying more than the checksum.** The checksum proves the archive matches `checksums.txt` from the same release. To also prove that GitHub Actions built it from this repository, verify the provenance attestation with the GitHub CLI: `gh attestation verify qbit-vault_linux_amd64.tar.gz --repo qbitdevz/qbit-vault`. The binaries are not code-signed for macOS or Windows; a file downloaded by `curl` or PowerShell carries no quarantine flag, but if you download an archive with a browser, macOS Gatekeeper or Windows SmartScreen may warn. Minisign-signed checksums are not built; the SHA-256 `checksums.txt` and the provenance attestation are what exist.

## With Go

Requires Go 1.26 or newer (`go version`). No C compiler is needed.

```bash
go install github.com/qbitdevz/qbit-vault/cmd/qbit-vault@latest
```

`@latest` is the newest release tag (pre-release tags are used only while no stable tag exists); pin one with `@v1.0.0`. `qbit-vault version` reports the module version for a `go install` build and the commit for a checkout build.

From a checkout:

```bash
git clone https://github.com/qbitdevz/qbit-vault
cd qbit-vault
go install ./cmd/qbit-vault
```

## Prerequisites

| Need | Why |
| --- | --- |
| macOS, Linux (including WSL2) or Windows 10+, amd64 or arm64 | The unit suite, the install-script tests and the leak grep run on all three in CI; the Docker batteries (`e2e/`) run on Linux. |
| `curl` or `wget`, `tar` and `sha256sum` or `shasum` (Linux, macOS) | Used by `install.sh`; present on stock systems. |
| An OS keychain, or a passphrase | Without a keychain (WSL, a headless Linux box without Secret Service) `init` asks for a passphrase instead (below). Under WSL the dialogs (passphrase, secrets, permissions) are the Windows ones, through `powershell.exe` at its fixed `/mnt/c/Windows/…` path; no `zenity` or `kdialog` is needed, and `qbit-vault doctor` shows `prompt: powershell (WSL)`. |

## Where `go install` puts the binary

`go install` writes `qbit-vault` to `$GOBIN`, or `$(go env GOPATH)/bin` when `GOBIN` is unset. Check with `go env GOBIN GOPATH`.

| OS | Default location | File |
| --- | --- | --- |
| Linux | `~/go/bin` | `qbit-vault` |
| macOS | `~/go/bin` | `qbit-vault` |
| Windows | `%USERPROFILE%\go\bin` | `qbit-vault.exe` |

That directory must be on your `PATH`. Verify with `qbit-vault version`, and with `which -a qbit-vault` (`where qbit-vault` on Windows) that no older copy earlier on the `PATH` shadows the new one.

To build without installing: `go build -o qbit-vault ./cmd/qbit-vault` (`qbit-vault.exe` on Windows).

## First run

```bash
qbit-vault           # in a terminal: the guided setup (same as `qbit-vault tui`)
qbit-vault init      # or: the scripted path, no questions on a machine with a keychain
qbit-vault doctor    # read-only health report; exit 1 on any problem
```

- The TUI wizard runs `init` with the key storage and hosts you pick. `QBIT_VAULT_NO_TUI=1` makes bare `qbit-vault` print the help instead.
- `init` registers the hosts it detects: Claude Code (`~/.claude/` or a `claude` binary), Codex (`~/.codex/` or `codex`) and Pi / Gentle Shell (`~/.pi/` or a `pi` / `gentle-shell` binary). Choose them yourself with `init --agents claude-code,codex,pi` or skip them with `--agents none`.
- The registered MCP entry holds the **absolute path** of the binary that ran `init`. Moving or reinstalling to another directory means running `qbit-vault sync` (below).
- When `init` registered or changed any agent it ends with `Restart your coding agents so they load QBit Vault.`
- Store your first secret yourself: `qbit-vault set GITHUB_TOKEN --global` (hidden prompt). `init` never asks for a value and never reads your environment.

## Update

Re-run the one-line install. It is safe on a machine that already has QBit Vault:

| You have | What the script does |
| --- | --- |
| An install from the script, first on `PATH` | Upgrades it in place: `upgrading qbit-vault <old> -> <new>` (or `… is already installed; reinstalling it` for the same tag). Same path, so the agents' registrations stay valid. |
| A `go install` copy in `~/go/bin` (or any directory you can write) | Same: that copy is replaced in place by the release binary. |
| A copy in a directory you cannot write (`/usr/local/bin` owned by root) | Installs to the default directory and warns `another qbit-vault at <path> comes first on your PATH; remove it so your shell runs the new one`. |
| A vault already set up | Runs `qbit-vault sync` with the new binary, so every agent registration points at it, then `agent registrations are up to date; restart your agents to load the new version`. If `sync` finds a problem it says so and points at `qbit-vault doctor`; the binary is installed either way. |

Your vault, keys, grants, backups and audit log live in `$QBIT_VAULT_HOME` and are never touched by the install. Restart your agents afterwards: an agent that was open during the update keeps running the old MCP server until it restarts.

With Go, re-run `go install github.com/qbitdevz/qbit-vault/cmd/qbit-vault@latest` (or `git pull` then `go install ./cmd/qbit-vault`), then `qbit-vault sync` yourself; on Windows close your agents first, because `go install` cannot replace a running `.exe`. The simplest way is `qbit-vault update` (§ Self-update below).

## Uninstall

```bash
qbit-vault uninstall           # revert each host's config from its snapshot; keeps the vault
qbit-vault uninstall --purge   # also delete the vault and its keychain entry (you type `purge`)
```

`uninstall` does not delete the binary. Remove it from where the installer put it:

| System | Binary | Also remove |
| --- | --- | --- |
| Linux, macOS | `~/.local/bin/qbit-vault` (or the directory of the copy that was already first on your `PATH`, or `QBIT_VAULT_INSTALL_DIR`) | nothing: the script never edits your shell profile |
| Windows | `%LOCALAPPDATA%\Programs\qbit-vault\qbit-vault.exe` (or the existing location / `QBIT_VAULT_INSTALL_DIR`) | the entry the installer added to your **user** `PATH` |

Remove the Windows `PATH` entry in PowerShell (open a new terminal afterwards):

```powershell
[Environment]::SetEnvironmentVariable('Path', ((([Environment]::GetEnvironmentVariable('Path','User') -split ';') | Where-Object { $_.TrimEnd('\') -ne "$env:LOCALAPPDATA\Programs\qbit-vault" }) -join ';'), 'User')
```

Details of what `uninstall` restores, and the `--purge` refusal while the vault syncs, are in § `uninstall` below.

### Not built: npm and Homebrew

```bash
npx qbit-vault@latest init                                    # not built
brew install <tap>/qbit-vault && qbit-vault init             # not built
```

## npm launcher design (not built)

There is no `packages/` directory yet. The design is a tiny JS launcher with no `postinstall`:

```json
{
  "name": "qbit-vault",
  "bin": { "qbit-vault": "bin/qbit-vault.mjs" },
  "optionalDependencies": {
    "@qbit-vault/cli-darwin-arm64": "1.0.0",
    "@qbit-vault/cli-darwin-x64": "1.0.0",
    "@qbit-vault/cli-linux-x64": "1.0.0",
    "@qbit-vault/cli-linux-arm64": "1.0.0",
    "@qbit-vault/cli-win32-x64": "1.0.0"
  },
  "scripts": {}
}
```

- Each platform package contains the Go binary and its `checksums.txt` + Minisign signature. npm installs only the matching one.
- `bin/qbit-vault.mjs` resolves the platform package, verifies the binary's SHA-256 against the checksum **embedded in the launcher at release time**, then `execFileSync`s it with all arguments. No download at runtime, no `postinstall`, no network beyond npm itself.
- If the platform package is missing (unsupported platform or `--no-optional`), the launcher prints the `go install` alternative and exits 2.

The release archives are already produced by GoReleaser with `checksums.txt` and GitHub build provenance; Minisign signatures are not built.

## `init` step by step

Everything is idempotent; re-running repairs. Every file write goes through snapshot + atomic merge (`STORAGE.md`). Steps 4–7 run on **every** `init`, also when the vault already exists; `--agents <names>` selects hosts and `--agents none` skips steps 4–6 (the doctor still runs) (`CLI.md`). A step that fails stops its own host only: the file it was editing is untouched, the earlier steps stay in `state.json`, the other hosts still run and `init` exits 1. A second run with nothing to change writes no config file, takes no snapshot and leaves `state.json` as it was.

| # | Step | Details | Asks the user? |
| --- | --- | --- | --- |
| 1 | Create home | `$QBIT_VAULT_HOME` (default `~/.qbit-vault/`) with owner-only permissions and `state.json`. `config.yaml`, `bindings.yaml` and `dumpguard.yaml` are **not** created: the defaults are compiled in, and a `dumpguard.yaml` you add only extends the guard (no `config.yaml` loader exists yet) | no |
| 2 | Master key | Keychain mode (default): generate the key and store it in the OS keychain (`keychain: macos-keychain`, `windows-credential-manager` or `secret-service`). With `--passphrase`, wrap it with a passphrase (asked twice on the controlling terminal, or `--passphrase-stdin`) into `key.enc`. **Automatic fallback:** on a machine without a keychain (WSL, headless Linux without Secret Service) plain `init` asks for a passphrase twice instead of failing and prints `no OS keychain found (WSL or a headless Linux?): the master key is protected by the passphrase you just set; 'qbit-vault unlock' opens it`. With no terminal or dialog to ask it stops with `no OS keychain found and no terminal to ask for a passphrase; run 'qbit-vault init --passphrase --passphrase-stdin'` and writes nothing | with `--passphrase`, or when there is no keychain |
| 3 | Empty vault | Write `vault.enc` with an empty body. **Never** reads `process.env` or any `.env` | no |
| 4 | Detect hosts | `claude-code` (`~/.claude/` or a `claude` binary on `PATH`), `codex` (`~/.codex/` or `codex`), `pi` (the Pi agent directory, `~/.pi/`, or a `pi` or `gentle-shell` binary); `--agents` names hosts explicitly. There is no OpenCode adapter (dropped, `ROADMAP.md`) | no |
| 5 | Register hosts | Per `AGENT_INTEGRATIONS.md`, receipts to `state.json`. Claude Code: `mcpServers.qbit-vault` in `~/.claude.json`, six hooks and the `Read`/`Edit` deny rules for the vault home in `~/.claude/settings.json`. Codex: the `[mcp_servers.qbit-vault]` table in `~/.codex/config.toml` and two hooks (`PostToolUse` on `Bash`, `PreToolUse` on `apply_patch`) in `~/.codex/hooks.json`, next to the hooks of other tools; Codex runs them after you trust them in `/hooks`, and `init` prints that reminder. Pi / Gentle Shell: `mcpServers.qbit-vault` in `<Pi agent dir>/mcp.json` (`$PI_CODING_AGENT_DIR`, default `~/.pi/agent`). Every host also gets the `qbit-vault` agent skill: `~/.claude/skills/qbit-vault/SKILL.md` for Claude Code, one shared `~/.agents/skills/qbit-vault/SKILL.md` for Codex and Pi (`AGENT_INTEGRATIONS.md` § Agent skill) | no |
| 6 | Extension | Pi: `init` prints the install command of the `qbit-vault-pi` extension as a suggestion under the `host pi:` line and never runs it (installing needs the network, AGENTS.md invariant 8): `gentle-shell -- install git:github.com/qbitdevz/qbit-vault@pi-v0.2.0` (Gentle Shell) or `pi install git:github.com/qbitdevz/qbit-vault@pi-v0.2.0` (Pi). It is a git tag of this repository, not an npm package. Pi uses the MCP entry from step 5 either way | no |
| 7 | Doctor | Run `doctor` (read-only) and print the report. It is printed whenever a host was processed or a problem was found; a healthy vault-only run prints just the vault line. Exit 1 on any problem | no |

Total questions on a machine with a keychain: **zero**. Not built: verifying a binary signature, and a separate check that other tools' deny entries survived (they survive because only entries we own are touched; `AGENT_INTEGRATIONS.md`).

## Example output

Illustrative, on a Linux machine with all three hosts present:

```
vault initialized at /home/ana/.qbit-vault (keychain: secret-service)
host claude-code: registered (mcp, hooks, deny, skill)
host codex: registered (mcp, hooks, skill)
  Codex skips new hooks until you trust them: open /hooks in Codex and trust the qbit-vault hooks.
host pi: registered (mcp, skill)
  Pi extension (optional, run it yourself): gentle-shell -- install git:github.com/qbitdevz/qbit-vault@pi-v0.2.0
  with plain Pi: pi install git:github.com/qbitdevz/qbit-vault@pi-v0.2.0
ok    vault                    unlocked (keychain: secret-service)
ok    permissions              owner-only
ok    host.claude-code.mcp     registered
...
healthy
```

Restart your agent afterwards so it picks up the MCP server.

## `sync`

Re-applies the host registration steps from the receipts in `state.json` (run it after upgrading qbit-vault, after `gentle-ai sync` or any host rewrote its config, or after moving the binary). `doctor` tells you when it is needed. It is not the multi-machine sync: that is `qbit-vault remote sync` (below). When your vault syncs with a server, `sync` ends with `(to sync secrets between devices: qbit-vault remote sync)`.

## Backup without a server

A lost or broken machine takes the vault with it unless you keep a copy. The simplest copy needs no server, no account and no sync: one encrypted file.

```bash
qbit-vault export ~/vault-backup.qvx          # asks a new export passphrase twice (at least 12 characters)
```

Keep the file somewhere else (a USB stick, a cloud drive) and the passphrase in a different place, such as a password manager or paper: the file is a full copy, and anyone with both reads every secret. To restore on a new machine, install QBit Vault, then:

```bash
qbit-vault init                                       # an empty vault
qbit-vault import --from-export ~/vault-backup.qvx    # asks the export passphrase
```

Every secret returns to its own layer with its metadata; project secrets return to the project with the same folder path (`qbit-vault relink OLD_ROOT NEW_ROOT` if the repository lives elsewhere now). Grants are not in the file: approve them again as you use each secret. Export again after you add or change secrets; the file is a snapshot of the day you made it. Format and limits: [STORAGE.md](STORAGE.md#export-file-format), [THREAT_MODEL.md](THREAT_MODEL.md) (L35, R16). To keep several machines in step instead, see the next section.

## Several machines (optional)

`init` never contacts a server; sync is a separate, explicit step (`REMOTE_SYNC.md`).

**1. Run the server** (once, on your VPS or Dokploy). Every release publishes the image `ghcr.io/qbitdevz/qbit-vault-server` (linux/amd64 and linux/arm64, tagged with the release version and `latest`). Copy `deploy/compose.image.yaml` to the host, set `QBV_SERVER_PUBLIC_URL` to the `https://` origin your proxy serves (one volume `/data`, TLS at the proxy), start it and create an invite:

```bash
export QBV_SERVER_PUBLIC_URL=https://vault.example.com
docker compose -f compose.image.yaml up -d
docker compose -f compose.image.yaml exec server /qbit-vault-server invite --ttl 24h
```

Open the public URL in a browser to check it: the server answers a small status page ("This QBit Vault sync server is running") with its version. Prefer to build it yourself? `deploy/compose.yaml` builds the same server from the repository (`docker compose -f deploy/compose.yaml up -d --build`).

No shell on the host (a hosted Dokploy)? Set `QBV_SERVER_BOOTSTRAP_INVITE` to a code of your own of at least 24 characters in the service's environment and redeploy: while no account exists the server accepts that code once, as the invite of step 2 (it is never logged). Remove the variable after registering.

**2. First machine** (the one that already has your secrets):

```bash
qbit-vault remote register --server https://vault.example.com
```

A dialog asks for the invite, then shows your **recovery key** once. Write it down offline; with no device left it is the only way back in. The check of its last four characters repeats until you get it right; if you cancel, the account stays registered and `qbit-vault remote recovery-key --rotate` gives you a new key.

Use the **same URL** on every machine. Case, a default port (`:443`) and a trailing slash do not matter, but a different host name does; if a login is refused for that reason, the message names both URLs (`qbit-vault remote logout`, then register or join again with the right one).

**3. Every other machine:**

```bash
curl -fsSL https://github.com/qbitdevz/qbit-vault/releases/latest/download/install.sh | sh && qbit-vault init
qbit-vault remote join --server https://vault.example.com   # prints a pairing code
# on the first machine:
qbit-vault remote approve                                   # type the pairing code, name the device (Enter = "device 2"), read the confirmation code
# back on the new machine: type the confirmation code
```

**If the server is lost or wiped.** Your local vaults keep working; only the sync stops. Recovery keys of the old server no longer apply (they belong to its accounts). Keep an `export` (§ Backup without a server) so nothing depends on the server. To start again on a new or empty server: run `qbit-vault remote logout` on each device, then `qbit-vault remote register --server URL` on **one** device (it shows a new recovery key), then `qbit-vault remote join --server URL` on the others, approving each with `remote approve`.

From then on every change syncs by itself, and machines that were offline catch up on their next command. In a repository whose project secrets came from another machine, run `qbit-vault link <label>` once (`list` tells you when).

## `uninstall`

`uninstall` is a user command: it asks in the prompt backend and the agent's shell cannot run it.

1. For each host recorded in `state.json`, in reverse step order: if the file is still exactly what qbit-vault wrote, restore the snapshot taken at registration byte for byte (or delete a file qbit-vault created); if the user changed it since, remove only the entries qbit-vault added and keep everything else. The host is forgotten in `state.json` only when this succeeded; otherwise it stays, the command exits 1 and you can run it again.
2. The Pi extension, if you installed it, is yours to remove with Pi (`pi remove` with the same git source; in Gentle Shell, after `--`). `uninstall` only reverts the MCP entry and the skill. `uninstall` does not remove the binary: delete it from where it was installed (see Uninstall above; for a `go install` copy, your `go/bin` directory).
3. Leave `~/.qbit-vault/` intact. With `--purge` you type the literal word `purge` instead of confirming; after every host reverted it deletes the keychain item and the directory, and nothing else. `uninstall` never touches the sync server, so `--purge` refuses while this vault syncs: run `qbit-vault remote logout` (or revoke the device from another machine) first.

## Self-update

`qbit-vault update` brings an installed binary to the latest stable release; `qbit-vault update --check` only reports (`update available: v1.0.0 -> v1.1.0` or `qbit-vault v1.1.0 is up to date`). It is a user-only command: the confirmation `Update QBit Vault <current> to <latest>?` (default No) comes from the out-of-band prompt, so an agent cannot swap the binary (the pre-bash hook also denies it, and without a prompt backend it is `not_model_callable`).

What it does, in order:

1. Refuses a build that is not a release (`dev`, `+dirty`, a pseudo-version) with the one-line installer / `go install` hint; `--check` still reports.
2. Asks `https://api.github.com/repos/qbitdevz/qbit-vault/releases/latest` (or `QBIT_VAULT_RELEASES_API`, as the installers) and compares semantic versions. A draft or pre-release is never chosen.
3. Checks that the directory of the running binary is writable (`cannot replace <path>: re-run the install command` otherwise), then asks you.
4. Downloads `qbit-vault_<os>_<arch>.tar.gz` (`.zip` on Windows) and `checksums.txt` over HTTPS (redirects to GitHub's asset hosts are followed; size caps and timeouts apply), checks the archive's SHA-256 against `checksums.txt` and extracts the binary to a temp file beside the installed one. Any failure there leaves the installed binary byte-identical and removes the temp file.
5. Swaps it in atomically (the same rename the installers do; on Windows the running `qbit-vault.exe` is renamed to `qbit-vault.exe.old-<8 hex>` and a later `update` removes the old copies).
6. When the vault is set up, runs `sync` of the new binary (skip with `QBIT_VAULT_NO_SYNC=1`) and prints `updated qbit-vault <current> -> <latest>; restart your agents so they load the new version`.

The TUI does the same from its Update section: each time it opens it checks for a newer release in the background (5 s timeout; the screen never waits and a failure only shows `could not check for updates`), shows `update available <latest>` in the header, and `u` runs this update with the TUI suspended for the confirmation. `QBIT_VAULT_NO_UPDATE_CHECK=1` turns the open-time check off (the section then offers `c check now`).

It never opens the vault, grants, audit log or sync state, reads no secret, and contacts only the GitHub API and the release assets. The trust anchor is the same as the installers': a SHA-256 `checksums.txt` served over HTTPS from the repository's releases. Minisign-signed checksums are not built yet; when they are, the command verifies them without changing its interface (THREAT_MODEL L12).
