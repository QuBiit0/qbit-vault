# Install: one command, then `qbit-vault init`

QBit Vault is a pre-release (`v0.1.0-beta.2` is the first published release; the `v0.1.0-beta.1` tag has no release). Each `v*` tag publishes a GitHub release with archives for Linux, macOS and Windows (amd64 and arm64), a `checksums.txt` and a build-provenance attestation (`.github/workflows/release.yml`, `.goreleaser.yaml`). There is no npm package and no Homebrew formula yet (Phase 5, `ROADMAP.md`).

## Quick path

1. Install the binary with one command (below).
2. Run `qbit-vault` (guided setup) or `qbit-vault init`, then `qbit-vault doctor`.
3. Restart your agent so it picks up the MCP server.

## One-line install

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/QuBiit0/qbit-vault/main/scripts/install.sh | sh
```

```powershell
# Windows (PowerShell 5.1 or 7)
irm https://raw.githubusercontent.com/QuBiit0/qbit-vault/main/scripts/install.ps1 | iex
```

What the scripts do (`scripts/install.sh`, `scripts/install.ps1`; read them before piping them to a shell):

1. Pick the archive for your OS and architecture: `qbit-vault_<os>_<arch>.tar.gz` (`.zip` on Windows).
2. Resolve the version: `QBIT_VAULT_VERSION` if set, else the newest release **including pre-releases** (GitHub's `releases/latest` skips them).
3. Download the archive and `checksums.txt` over HTTPS and compare the SHA-256. On a mismatch, or an archive not listed, they stop with `checksum mismatch for <archive>: nothing was installed` (or `<archive> is not listed in checksums.txt`) and install nothing.
4. Choose the directory: `QBIT_VAULT_INSTALL_DIR` if set; else the directory of the `qbit-vault` already first on your `PATH`, when you can write to it (an upgrade in place, see below); else `~/.local/bin` (Linux, macOS) or `%LOCALAPPDATA%\Programs\qbit-vault` (Windows).
5. Replace the binary atomically: the new file is written beside the old one and renamed over it, so a failed download or a full disk never leaves a half-written `qbit-vault`. On Windows a running `qbit-vault.exe` (an agent's MCP server) is renamed aside to `qbit-vault.exe.old-<id>` first, which Windows allows, so the upgrade works with your agents open; if the copy fails the old binary is put back. The aside file stays while that process runs and the next install removes it. On Windows the directory is added to your **user** `PATH` (open a new terminal); on Linux and macOS the script tells you if the directory is not on `PATH`.
6. Finish: on a machine where the vault is already set up (`$QBIT_VAULT_HOME/state.json` exists, default `~/.qbit-vault`), run `qbit-vault sync` with the new binary so every registered agent points at it, and tell you to restart your agents; otherwise print the next step (`qbit-vault` or `qbit-vault init`). They never ask for, read or store a secret, never read your environment for values, and never run `init`; `sync` only re-applies the registrations you already made and reads no secret.

| Variable | Effect |
| --- | --- |
| `QBIT_VAULT_VERSION` | Tag to install, for example `v0.1.0-beta.2` |
| `QBIT_VAULT_INSTALL_DIR` | Target directory |
| `QBIT_VAULT_NO_PATH=1` | Windows only: leave the user `PATH` unchanged |
| `QBIT_VAULT_NO_SYNC=1` | Do not run `qbit-vault sync` after installing over a set-up vault |

Pass a variable to the piped script like this: `curl -fsSL …/install.sh | QBIT_VAULT_VERSION=v0.1.0-beta.2 sh`, or in PowerShell `$env:QBIT_VAULT_VERSION='v0.1.0-beta.2'; irm …/install.ps1 | iex`.

**Verifying more than the checksum.** The checksum proves the archive matches `checksums.txt` from the same release. To also prove that GitHub Actions built it from this repository, verify the provenance attestation with the GitHub CLI: `gh attestation verify qbit-vault_linux_amd64.tar.gz --repo QuBiit0/qbit-vault`. The binaries are not code-signed for macOS or Windows; a file downloaded by `curl` or PowerShell carries no quarantine flag, but if you download an archive with a browser, macOS Gatekeeper or Windows SmartScreen may warn. Minisign-signed checksums are still planned (Phase 5).

## With Go

Requires Go 1.26 or newer (`go version`). No C compiler is needed.

```bash
go install github.com/QuBiit0/qbit-vault/cmd/qbit-vault@latest
```

`@latest` is the newest release tag (pre-release tags are used only while no stable tag exists); pin one with `@v0.1.0-beta.2`. `qbit-vault version` reports the module version for a `go install` build and the commit for a checkout build.

From a checkout:

```bash
git clone https://github.com/QuBiit0/qbit-vault
cd qbit-vault
go install ./cmd/qbit-vault
```

## Prerequisites

| Need | Why |
| --- | --- |
| macOS, Linux (including WSL2) or Windows 10+, amd64 or arm64 | The unit suite, the install-script tests and the leak grep run on all three in CI; the Docker batteries (`e2e/`) run on Linux. |
| `curl` or `wget`, `tar` and `sha256sum` or `shasum` (Linux, macOS) | Used by `install.sh`; present on stock systems. |
| An OS keychain, or willingness to use `init --passphrase` | A headless Linux box or WSL without Secret Service has no keychain, and there is no automatic fallback. |

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
- Store your first secret yourself: `qbit-vault set GITHUB_TOKEN --global` (masked prompt). `init` never asks for a value and never reads your environment.

## Update

Re-run the one-line install. It is safe on a machine that already has QBit Vault:

| You have | What the script does |
| --- | --- |
| An install from the script, first on `PATH` | Upgrades it in place: `upgrading qbit-vault <old> -> <new>` (or `… is already installed; reinstalling it` for the same tag). Same path, so the agents' registrations stay valid. |
| A `go install` copy in `~/go/bin` (or any directory you can write) | Same: that copy is replaced in place by the release binary. |
| A copy in a directory you cannot write (`/usr/local/bin` owned by root) | Installs to the default directory and warns `another qbit-vault at <path> comes first on your PATH; remove it so your shell runs the new one`. |
| A vault already set up | Runs `qbit-vault sync` with the new binary, so every agent registration points at it, then `agent registrations are up to date; restart your agents to load the new version`. If `sync` finds a problem it says so and points at `qbit-vault doctor`; the binary is installed either way. |

Your vault, keys, grants, backups and audit log live in `$QBIT_VAULT_HOME` and are never touched by the install. Restart your agents afterwards: an agent that was open during the update keeps running the old MCP server until it restarts.

With Go, re-run `go install github.com/QuBiit0/qbit-vault/cmd/qbit-vault@latest` (or `git pull` then `go install ./cmd/qbit-vault`), then `qbit-vault sync` yourself; on Windows close your agents first, because `go install` cannot replace a running `.exe`. `qbit-vault update` does not exist yet (Phase 5).

## Uninstall

```bash
qbit-vault uninstall           # revert each host's config from its snapshot; keeps the vault
qbit-vault uninstall --purge   # also delete the vault and its keychain entry (you type `purge`)
```

`uninstall` does not delete the binary: remove `qbit-vault` (or `qbit-vault.exe`) from the directory above. Details of what it restores, and the `--purge` refusal while the vault syncs, are in § `uninstall` below.

### Planned for Phase 5 (not built)

```bash
npx qbit-vault@latest init                                    # planned
brew install <tap>/qbit-vault && qbit-vault init             # planned
```

## npm launcher design (planned, Phase 5)

There is no `packages/` directory yet. The design is a tiny JS launcher with no `postinstall`:

```json
{
  "name": "qbit-vault",
  "bin": { "qbit-vault": "bin/qbit-vault.mjs" },
  "optionalDependencies": {
    "@qbit-vault/cli-darwin-arm64": "0.1.0",
    "@qbit-vault/cli-darwin-x64": "0.1.0",
    "@qbit-vault/cli-linux-x64": "0.1.0",
    "@qbit-vault/cli-linux-arm64": "0.1.0",
    "@qbit-vault/cli-win32-x64": "0.1.0"
  },
  "scripts": {}
}
```

- Each platform package contains the Go binary and its `checksums.txt` + Minisign signature. npm installs only the matching one.
- `bin/qbit-vault.mjs` resolves the platform package, verifies the binary's SHA-256 against the checksum **embedded in the launcher at release time**, then `execFileSync`s it with all arguments. No download at runtime, no `postinstall`, no network beyond npm itself.
- If the platform package is missing (unsupported platform or `--no-optional`), the launcher prints the `go install` alternative and exits 2.

The release archives are already produced by GoReleaser with `checksums.txt` and GitHub build provenance; Minisign signatures are planned.

## `init` step by step

Everything is idempotent; re-running repairs. Every file write goes through snapshot + atomic merge (`STORAGE.md`). Steps 4–7 run on **every** `init`, also when the vault already exists; `--agents <names>` selects hosts and `--agents none` skips steps 4–6 (the doctor still runs) (`CLI.md`). A step that fails stops its own host only: the file it was editing is untouched, the earlier steps stay in `state.json`, the other hosts still run and `init` exits 1. A second run with nothing to change writes no config file, takes no snapshot and leaves `state.json` as it was.

| # | Step | Details | Asks the user? |
| --- | --- | --- | --- |
| 1 | Create home | `$QBIT_VAULT_HOME` (default `~/.qbit-vault/`) with owner-only permissions and `state.json`. `config.yaml`, `bindings.yaml` and `dumpguard.yaml` are **not** created: the defaults are compiled in, and a `dumpguard.yaml` you add only extends the guard (no `config.yaml` loader exists yet) | no |
| 2 | Master key | Keychain mode (default): generate the key and store it in the OS keychain (`keychain: macos-keychain`, `windows-credential-manager` or `secret-service`). With `--passphrase`, wrap it with a passphrase (asked twice on the controlling terminal, or `--passphrase-stdin`) into `key.enc`. **There is no automatic fallback:** on a machine without a keychain (headless Linux, WSL without Secret Service) plain `init` fails and you run `init --passphrase` | only with `--passphrase` |
| 3 | Empty vault | Write `vault.enc` with an empty body. **Never** reads `process.env` or any `.env` | no |
| 4 | Detect hosts | `claude-code` (`~/.claude/` or a `claude` binary on `PATH`), `codex` (`~/.codex/` or `codex`), `pi` (the Pi agent directory, `~/.pi/`, or a `pi` or `gentle-shell` binary); `--agents` names hosts explicitly. There is no OpenCode adapter (dropped, `ROADMAP.md`) | no |
| 5 | Register hosts | Per `AGENT_INTEGRATIONS.md`, receipts to `state.json`. Claude Code: `mcpServers.qbit-vault` in `~/.claude.json`, four hooks and the `Read`/`Edit` deny rules for the vault home in `~/.claude/settings.json`. Codex: the `[mcp_servers.qbit-vault]` table in `~/.codex/config.toml`. Pi / Gentle Shell: `mcpServers.qbit-vault` in `<Pi agent dir>/mcp.json` (`$PI_CODING_AGENT_DIR`, default `~/.pi/agent`). Every host also gets the `qbit-vault` agent skill: `~/.claude/skills/qbit-vault/SKILL.md` for Claude Code, one shared `~/.agents/skills/qbit-vault/SKILL.md` for Codex and Pi (`AGENT_INTEGRATIONS.md` § Agent skill) | no |
| 6 | Extension | Pi: `init` **prints** `host pi: to add the extension, run: pi install npm:qbit-vault-pi` for you to run and never runs it, because installing needs the network (AGENTS.md invariant 8). The extension itself does not exist yet (Phase 4); until it does, Pi uses the MCP entry from step 5 | no |
| 7 | Doctor | Run `doctor` (read-only) and print the report. It is printed whenever a host was processed or a problem was found; a healthy vault-only run prints just the vault line. Exit 1 on any problem | no |

Total questions on a machine with a keychain: **zero**. Not built: verifying a binary signature, a separate check that other tools' deny entries survived (they survive because only entries we own are touched; `AGENT_INTEGRATIONS.md`), and a "restart your agent" next-steps message.

## Example output

Illustrative, on a Linux machine with all three hosts present:

```
vault initialized at /home/ana/.qbit-vault (keychain: secret-service)
host claude-code: registered (mcp, hooks, deny, skill)
host codex: registered (mcp, skill)
host pi: registered (mcp)
host pi: to add the extension, run: pi install npm:qbit-vault-pi
ok    vault                    unlocked (keychain: secret-service)
ok    permissions              owner-only
ok    host.claude-code.mcp     registered
...
healthy
```

Restart your agent afterwards so it picks up the MCP server.

## `sync`

Re-applies the host registration steps from the receipts in `state.json` (run it after upgrading qbit-vault, after `gentle-ai sync` or any host rewrote its config, or after moving the binary). `doctor` tells you when it is needed. It is not the multi-machine sync: that is `remote` (below).

## Several machines (optional)

`init` never contacts a server; sync is a separate, explicit step (`REMOTE_SYNC.md`).

**1. Run the server** (once, on your VPS or Dokploy). No image is published yet (Phase 5): `deploy/compose.yaml` builds it from the repository (`deploy/Dockerfile`, build context the repository root). Deploy it with one volume `/data` and `QBV_SERVER_PUBLIC_URL=https://vault.example.com` behind the proxy's TLS, then create an invite:

```bash
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml exec server /qbit-vault-server invite --ttl 24h
```

**2. First machine** (the one that already has your secrets):

```bash
qbit-vault remote register --server https://vault.example.com
```

A dialog asks for the invite, then shows your **recovery key** once. Write it down offline; with no device left it is the only way back in.

**3. Every other machine:**

```bash
curl -fsSL https://raw.githubusercontent.com/QuBiit0/qbit-vault/main/scripts/install.sh | sh && qbit-vault init
qbit-vault remote join --server https://vault.example.com   # prints a pairing code
# on the first machine:
qbit-vault remote approve                                   # type the pairing code, read the confirmation code
# back on the new machine: type the confirmation code
```

From then on every change syncs by itself, and machines that were offline catch up on their next command. In a repository whose project secrets came from another machine, run `qbit-vault link <label>` once (`list` tells you when).

## `uninstall`

`uninstall` is a user command: it asks in the prompt backend and the agent's shell cannot run it.

1. For each host recorded in `state.json`, in reverse step order: if the file is still exactly what qbit-vault wrote, restore the snapshot taken at registration byte for byte (or delete a file qbit-vault created); if the user changed it since, remove only the entries qbit-vault added and keep everything else. The host is forgotten in `state.json` only when this succeeded; otherwise it stays, the command exits 1 and you can run it again.
2. The Pi extension (Phase 4, not built yet) would be installed by you (`pi install npm:qbit-vault-pi`), so you would remove it the same way (`pi remove`); `uninstall` only reverts the MCP entry. `uninstall` does not remove the binary: delete it from your `go/bin` directory.
3. Leave `~/.qbit-vault/` intact. With `--purge` you type the literal word `purge` instead of confirming; after every host reverted it deletes the keychain item and the directory, and nothing else. `uninstall` never touches the sync server, so `--purge` refuses while this vault syncs: run `qbit-vault remote logout` (or revoke the device from another machine) first.

## Self-update (planned)

Not built (Phase 5): `qbit-vault update` downloads the release, verifies Minisign + checksums and swaps the binary atomically. A background check at most once per 24 h would print a one-line notice and be opt-out (`QBIT_VAULT_NO_UPDATE_CHECK=1`); it is the optional update check AGENTS.md invariant 8 allows.
