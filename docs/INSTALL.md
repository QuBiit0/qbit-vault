# Install: `go install` and `qbit-vault init`

While the repository is private, the install is a Go build from source. There is no release, no npm package, no Homebrew formula and no install script yet (Phase 5, `ROADMAP.md`).

## Quick path

1. Check the prerequisites below.
2. Install the binary (option A or B).
3. Run `qbit-vault` (guided setup) or `qbit-vault init`, then `qbit-vault doctor`.
4. Restart your agent so it picks up the MCP server.

## Prerequisites

| Need | Why |
| --- | --- |
| Go 1.26 or newer (`go version`; `go.mod` names `go 1.26.0`) | The only build tool. No C compiler is needed. |
| `git` with read access to `github.com/QuBiit0/qbit-vault` | The repository is private. |
| macOS, Linux (including WSL2) or Windows 10+ | The unit suite and the leak grep run on all three in CI; the Docker batteries (`e2e/`) run on Linux. |
| An OS keychain, or willingness to use `init --passphrase` | A headless Linux box or WSL without Secret Service has no keychain, and there is no automatic fallback. |

## Option A: from a checkout (recommended while private)

```bash
git clone https://github.com/QuBiit0/qbit-vault
cd qbit-vault
go install ./cmd/qbit-vault
```

`git clone` uses whatever GitHub login you already have (credential manager, `gh auth login`, an SSH key with `git@github.com:QuBiit0/qbit-vault.git`). Building from a checkout never touches the Go module proxy.

## Option B: `go install` by module path

```bash
# bash / zsh
export GOPRIVATE=github.com/QuBiit0/*
go install github.com/QuBiit0/qbit-vault/cmd/qbit-vault@latest
```

```powershell
# PowerShell
go env -w GOPRIVATE=github.com/QuBiit0/*
go install github.com/QuBiit0/qbit-vault/cmd/qbit-vault@latest
```

`GOPRIVATE` stops Go from asking the public proxy and checksum database about a private module; Go then fetches it with `git`, so your git credentials must work non-interactively. If `git` reaches GitHub over HTTPS and prompts, either store a credential (`gh auth setup-git`, or a credential manager) or route the path over SSH: `git config --global url."git@github.com:".insteadOf "https://github.com/"`. Without access the command fails with a "repository not found" style error from `git`. Without a release tag, `@latest` is the newest commit of the default branch.

## Where the binary goes

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

Re-run the same install command (`git pull` then `go install ./cmd/qbit-vault`, or the `@latest` form), then:

```bash
qbit-vault version     # confirm the new build is the one on PATH
qbit-vault sync        # re-apply host registrations (needed if the binary path changed)
qbit-vault doctor
```

Close your agents first: a running `qbit-vault mcp` keeps the old executable open, and on Windows the replacement can fail while it runs. An agent that was open during the update still runs the old MCP server until you restart it. `qbit-vault update` does not exist yet (Phase 5).

## Uninstall

```bash
qbit-vault uninstall           # revert each host's config from its snapshot; keeps the vault
qbit-vault uninstall --purge   # also delete the vault and its keychain entry (you type `purge`)
```

`uninstall` does not delete the binary: remove `qbit-vault` (or `qbit-vault.exe`) from the directory above. Details of what it restores, and the `--purge` refusal while the vault syncs, are in § `uninstall` below.

### Planned for Phase 5 (not built)

These were the original install paths. They are kept as the design target and do not work today:

```bash
npx qbit-vault@latest init                                    # planned
brew install <tap>/qbit-vault && qbit-vault init             # planned
curl -fsSL https://raw.githubusercontent.com/QuBiit0/qbit-vault/main/scripts/install.sh | bash   # planned; scripts/ does not exist yet
irm https://raw.githubusercontent.com/QuBiit0/qbit-vault/main/scripts/install.ps1 | iex          # planned
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

The Go releases would be produced by goreleaser with Minisign-signed `checksums.txt` and GitHub provenance.

## `init` step by step

Everything is idempotent; re-running repairs. Every file write goes through snapshot + atomic merge (`STORAGE.md`). Steps 4–7 run on **every** `init`, also when the vault already exists; `--agents <names>` selects hosts and `--agents none` skips steps 4–6 (the doctor still runs) (`CLI.md`). A step that fails stops its own host only: the file it was editing is untouched, the earlier steps stay in `state.json`, the other hosts still run and `init` exits 1. A second run with nothing to change writes no config file, takes no snapshot and leaves `state.json` as it was.

| # | Step | Details | Asks the user? |
| --- | --- | --- | --- |
| 1 | Create home | `$QBIT_VAULT_HOME` (default `~/.qbit-vault/`) with owner-only permissions and `state.json`. `config.yaml`, `bindings.yaml` and `dumpguard.yaml` are **not** created: the defaults are compiled in, and a `dumpguard.yaml` you add only extends the guard (no `config.yaml` loader exists yet) | no |
| 2 | Master key | Keychain mode (default): generate the key and store it in the OS keychain (`keychain: macos-keychain`, `windows-credential-manager` or `secret-service`). With `--passphrase`, wrap it with a passphrase (asked twice on the controlling terminal, or `--passphrase-stdin`) into `key.enc`. **There is no automatic fallback:** on a machine without a keychain (headless Linux, WSL without Secret Service) plain `init` fails and you run `init --passphrase` | only with `--passphrase` |
| 3 | Empty vault | Write `vault.enc` with an empty body. **Never** reads `process.env` or any `.env` | no |
| 4 | Detect hosts | `claude-code` (`~/.claude/` or a `claude` binary on `PATH`), `codex` (`~/.codex/` or `codex`), `pi` (the Pi agent directory, `~/.pi/`, or a `pi` or `gentle-shell` binary); `--agents` names hosts explicitly. There is no OpenCode adapter (dropped, `ROADMAP.md`) | no |
| 5 | Register hosts | Per `AGENT_INTEGRATIONS.md`, receipts to `state.json`. Claude Code: `mcpServers.qbit-vault` in `~/.claude.json`, four hooks and the `Read`/`Edit` deny rules for the vault home in `~/.claude/settings.json`. Codex: the `[mcp_servers.qbit-vault]` table in `~/.codex/config.toml`. Pi / Gentle Shell: `mcpServers.qbit-vault` in `<Pi agent dir>/mcp.json` (`$PI_CODING_AGENT_DIR`, default `~/.pi/agent`) | no |
| 6 | Extension | Pi: `init` **prints** `host pi: to add the extension, run: pi install npm:qbit-vault-pi` for you to run and never runs it, because installing needs the network (AGENTS.md invariant 8). The extension itself does not exist yet (Phase 4); until it does, Pi uses the MCP entry from step 5 | no |
| 7 | Doctor | Run `doctor` (read-only) and print the report. It is printed whenever a host was processed or a problem was found; a healthy vault-only run prints just the vault line. Exit 1 on any problem | no |

Total questions on a machine with a keychain: **zero**. Not built: verifying a binary signature, a separate check that Gentle AI deny entries survived (they survive because only entries we own are touched; `AGENT_INTEGRATIONS.md`), and a "restart your agent" next-steps message.

## Example output

Illustrative, on a Linux machine with all three hosts present:

```
vault initialized at /home/ana/.qbit-vault (keychain: secret-service)
host claude-code: registered (mcp, hooks, deny)
host codex: registered (mcp)
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
go install github.com/QuBiit0/qbit-vault/cmd/qbit-vault@latest && qbit-vault init
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
