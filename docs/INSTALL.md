# Install: what `npx gentle-vault@latest init` does

## The one command

```bash
npx gentle-vault@latest init
```

Windows (PowerShell), macOS and Linux. Requires Node ≥ 20 (already present for Pi users). Alternatives that end in the same `init`:

```bash
brew install <tap>/gentle-vault && gentle-vault init
curl -fsSL https://raw.githubusercontent.com/<owner>/gentle-vault/main/scripts/install.sh | bash
irm https://raw.githubusercontent.com/<owner>/gentle-vault/main/scripts/install.ps1 | iex
go install github.com/<owner>/gentle-vault/cmd/gentle-vault@latest && gentle-vault init
```

## npm launcher design (no postinstall)

`gentle-vault` on npm is a tiny JS launcher:

```json
{
  "name": "gentle-vault",
  "bin": { "gentle-vault": "bin/gentle-vault.mjs" },
  "optionalDependencies": {
    "@gentle-vault/cli-darwin-arm64": "0.1.0",
    "@gentle-vault/cli-darwin-x64": "0.1.0",
    "@gentle-vault/cli-linux-x64": "0.1.0",
    "@gentle-vault/cli-linux-arm64": "0.1.0",
    "@gentle-vault/cli-win32-x64": "0.1.0"
  },
  "scripts": {}
}
```

- Each platform package contains the Go binary and its `checksums.txt` + Minisign signature. npm installs only the matching one.
- `bin/gentle-vault.mjs` resolves the platform package, verifies the binary's SHA-256 against the checksum **embedded in the launcher at release time**, then `execFileSync`s it with all arguments. No download at runtime, no `postinstall`, no network beyond npm itself.
- If the platform package is missing (unsupported platform or `--no-optional`), the launcher prints the `curl`/`go install` alternatives and exits 2.

The Go releases themselves are produced by goreleaser with Minisign-signed `checksums.txt` and GitHub provenance, mirroring Gentle AI's release pipeline.

## `init` step by step

Everything is idempotent; re-running repairs. Every file write goes through snapshot + atomic merge (`STORAGE.md`).

| # | Step | Details | Asks the user? |
| --- | --- | --- | --- |
| 1 | Preflight | Verify binary signature, OS, Node for extension install, write access to `$GENTLE_VAULT_HOME` | no |
| 2 | Create home | `~/.gentle-vault/` 0700, `config.yaml`, `bindings.yaml`, `dumpguard.yaml` from embedded defaults, `state.json` | no |
| 3 | Master key | Try keychain. On success: generate key, store, `keychain: <backend>`. On failure (headless Linux, WSL without Secret Service): **passphrase prompt** (masked, twice) → `key.enc` | only without keychain |
| 4 | Empty vault | Write `vault.enc` with `{secrets:{}}`. **Never** reads `process.env` or any `.env` | no |
| 5 | Detect hosts | Presence of `~/.claude/`, `~/.codex/`, OpenCode config dir, `~/.pi/agent/`, `~/.gentle-shell/agent/`; honor `--agents` | no |
| 6 | Register hosts | Per `AGENT_INTEGRATIONS.md`: MCP entries, hooks, plugin, deny-list; receipts to `state.json` | no |
| 7 | Deny-list check | Confirm Gentle AI entries survived (R-INS-05); abort + restore on failure | no |
| 8 | Extension | `gentle-shell install npm:gentle-vault-pi@<pinned>` and/or `pi install npm:gentle-vault-pi@<pinned>` (pinned version, `--ignore-scripts`) | no |
| 9 | Doctor | Run and print the report | no |
| 10 | Next steps | Print: "Restart your agent. In the chat, ask it to do something that needs a credential; you'll get a masked prompt here." | no |

Total questions on a machine with a keychain: **zero**.

## Example output

```
gentle-vault 0.1.0  ✔ signature verified
Home        ~/.gentle-vault  (created)
Keychain    macos-keychain   (master key stored)
Vault       empty            (0 secrets)
Hosts
  gentle-shell   ~/.gentle-shell/agent   extension gentle-vault-pi@0.1.0 ✔  mcp ✔
  claude-code    ~/.claude               mcp ✔  hooks ✔ (3)  deny-list ✔ (Gentle AI entries preserved: 11)
  codex          ~/.codex                mcp ✔  prompt=tty (sandbox detected)
  opencode       not found               skipped
Backups     ~/.gentle-vault/backups/20261016T081500Z (4 files)
Audit       chain ok (1 event)

Restart your agent and ask it for something that needs a credential.
Docs: https://github.com/<owner>/gentle-vault#use-it-from-the-agent
```

## `sync`

Re-applies steps 6–8 from receipts. Run after upgrading gentle-vault, Gentle Shell, Gentle AI (`gentle-ai sync` may rewrite host configs) or any host. `doctor` tells you when it is needed.

## Several machines (optional)

`init` never contacts a server; sync is a separate, explicit step (`REMOTE_SYNC.md`).

**1. Run the server** (once, on your VPS or Dokploy). Deploy `deploy/compose.yaml` (image `ghcr.io/<owner>/gentle-vault-server`, one volume `/data`, `GV_SERVER_PUBLIC_URL=https://vault.example.com`) behind the proxy's TLS, then create an invite:

```bash
docker exec <container> gentle-vault-server invite --ttl 24h
```

**2. First machine** (the one that already has your secrets):

```bash
gentle-vault remote register --server https://vault.example.com
```

A dialog asks for the invite, then shows your **recovery key** once. Write it down offline; with no device left it is the only way back in.

**3. Every other machine:**

```bash
npx gentle-vault@latest init
gentle-vault remote join --server https://vault.example.com   # prints a pairing code
# on the first machine:
gentle-vault remote approve                                   # type the pairing code, read the confirmation code
# back on the new machine: type the confirmation code
```

From then on every change syncs by itself, and machines that were offline catch up on their next command. In a repository whose project secrets came from another machine, run `gentle-vault link <label>` once (`list` tells you when).

## `uninstall`

1. For each receipt in `state.json`, restore the snapshot taken at registration (or remove only the keys gentle-vault added if the file changed since, using a 3-way merge; conflicts are reported and left to the user).
2. Remove the extension from each Pi home.
3. Leave `~/.gentle-vault/` intact. With `--purge` and the literal confirmation `purge`: delete the keychain item and the directory. `uninstall` never touches the sync server; run `gentle-vault remote logout` (or revoke the device from another machine) first if this machine synced.

## Updates

`gentle-vault update` downloads the release matching the launcher's pinned version range, verifies Minisign + checksums, swaps the binary atomically. A background check at most once per 24 h prints a one-line notice; `config.update_check: false` or `GENTLE_VAULT_NO_UPDATE_CHECK=1` disables it.
