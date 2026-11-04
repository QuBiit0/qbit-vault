# Install: what `npx qbit-vault@latest init` does

## The one command

```bash
npx qbit-vault@latest init
```

Windows (PowerShell), macOS and Linux. Requires Node ≥ 20 (already present for Pi users). Alternatives that end in the same `init`:

```bash
brew install <tap>/qbit-vault && qbit-vault init
curl -fsSL https://raw.githubusercontent.com/<owner>/qbit-vault/main/scripts/install.sh | bash
irm https://raw.githubusercontent.com/<owner>/qbit-vault/main/scripts/install.ps1 | iex
go install github.com/<owner>/qbit-vault/cmd/qbit-vault@latest && qbit-vault init
```

## npm launcher design (no postinstall)

`qbit-vault` on npm is a tiny JS launcher:

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
- If the platform package is missing (unsupported platform or `--no-optional`), the launcher prints the `curl`/`go install` alternatives and exits 2.

The Go releases themselves are produced by goreleaser with Minisign-signed `checksums.txt` and GitHub provenance, mirroring Gentle AI's release pipeline.

## `init` step by step

Everything is idempotent; re-running repairs. Every file write goes through snapshot + atomic merge (`STORAGE.md`). Steps 5–7 and 9 run on **every** `init`, also when the vault already exists; `--agents <names>` selects hosts and `--agents none` skips steps 5–8 (`CLI.md`). A step that fails stops its own host only: the file it was editing is untouched, the earlier steps stay in `state.json`, the other hosts still run and `init` exits 1. A second run with nothing to change writes no config file, takes no snapshot and leaves `state.json` as it was.

| # | Step | Details | Asks the user? |
| --- | --- | --- | --- |
| 1 | Preflight | Verify binary signature, OS, Node for extension install, write access to `$QBIT_VAULT_HOME` | no |
| 2 | Create home | `~/.qbit-vault/` 0700, `config.yaml`, `bindings.yaml`, `dumpguard.yaml` from embedded defaults, `state.json` | no |
| 3 | Master key | Try keychain. On success: generate key, store, `keychain: <backend>`. On failure (headless Linux, WSL without Secret Service): **passphrase prompt** (masked, twice) → `key.enc` | only without keychain |
| 4 | Empty vault | Write `vault.enc` with `{secrets:{}}`. **Never** reads `process.env` or any `.env` | no |
| 5 | Detect hosts | Presence of `~/.claude/`, `~/.codex/`, OpenCode config dir, `~/.pi/agent/`, `~/.gentle-shell/agent/`; honor `--agents` | no |
| 6 | Register hosts | Per `AGENT_INTEGRATIONS.md`: MCP entries, hooks, plugin, deny-list; receipts to `state.json`. Claude Code (implemented): `mcpServers.qbit-vault` in `~/.claude.json`, four hooks and the `//<vault home>/**` Read/Edit deny rules in `~/.claude/settings.json` | no |
| 7 | Deny-list check | Confirm Gentle AI entries survived (R-INS-05); abort + restore on failure | no |
| 8 | Extension | `gentle-shell install npm:qbit-vault-pi@<pinned>` and/or `pi install npm:qbit-vault-pi@<pinned>` (pinned version, `--ignore-scripts`) | no |
| 9 | Doctor | Run `doctor` (read-only) and print the report. It is printed whenever a host was processed or a problem was found; a healthy vault-only run prints just the vault line. Exit 1 on any problem | no |
| 10 | Next steps | Print: "Restart your agent. In the chat, ask it to do something that needs a credential; you'll get a masked prompt here." | no |

Total questions on a machine with a keychain: **zero**.

## Example output

```
qbit-vault 0.1.0  ✔ signature verified
Home        ~/.qbit-vault  (created)
Keychain    macos-keychain   (master key stored)
Vault       empty            (0 secrets)
Hosts
  gentle-shell   ~/.gentle-shell/agent   extension qbit-vault-pi@0.1.0 ✔  mcp ✔
  claude-code    ~/.claude               mcp ✔  hooks ✔ (4)  deny-list ✔ (Gentle AI entries preserved: 11)
  codex          ~/.codex                mcp ✔
  opencode       not found               skipped
Backups     ~/.qbit-vault/backups/20261016T081500Z (4 files)
Audit       chain ok (1 event)

Restart your agent and ask it for something that needs a credential.
Docs: https://github.com/<owner>/qbit-vault#use-it-from-the-agent
```

## `sync`

Re-applies steps 6–8 from receipts. Run after upgrading qbit-vault, Gentle Shell, Gentle AI (`gentle-ai sync` may rewrite host configs) or any host. `doctor` tells you when it is needed.

## Several machines (optional)

`init` never contacts a server; sync is a separate, explicit step (`REMOTE_SYNC.md`).

**1. Run the server** (once, on your VPS or Dokploy). Deploy `deploy/compose.yaml` (image `ghcr.io/<owner>/qbit-vault-server`, one volume `/data`, `QBV_SERVER_PUBLIC_URL=https://vault.example.com`) behind the proxy's TLS, then create an invite:

```bash
docker compose -f deploy/compose.yaml exec server /qbit-vault-server invite --ttl 24h
```

**2. First machine** (the one that already has your secrets):

```bash
qbit-vault remote register --server https://vault.example.com
```

A dialog asks for the invite, then shows your **recovery key** once. Write it down offline; with no device left it is the only way back in.

**3. Every other machine:**

```bash
npx qbit-vault@latest init
qbit-vault remote join --server https://vault.example.com   # prints a pairing code
# on the first machine:
qbit-vault remote approve                                   # type the pairing code, read the confirmation code
# back on the new machine: type the confirmation code
```

From then on every change syncs by itself, and machines that were offline catch up on their next command. In a repository whose project secrets came from another machine, run `qbit-vault link <label>` once (`list` tells you when).

## `uninstall`

1. For each receipt in `state.json`, restore the snapshot taken at registration (or remove only the keys qbit-vault added if the file changed since, using a 3-way merge; conflicts are reported and left to the user).
2. Remove the extension from each Pi home.
3. Leave `~/.qbit-vault/` intact. With `--purge` and the literal confirmation `purge`: delete the keychain item and the directory. `uninstall` never touches the sync server; run `qbit-vault remote logout` (or revoke the device from another machine) first if this machine synced.

## Updates

`qbit-vault update` downloads the release matching the launcher's pinned version range, verifies Minisign + checksums, swaps the binary atomically. A background check at most once per 24 h prints a one-line notice; `config.update_check: false` or `QBIT_VAULT_NO_UPDATE_CHECK=1` disables it.
