# Architecture

## Components

```
                         ┌──────────────────────────────────────────┐
                         │  packages/qbit-vault  (npm launcher)   │
                         │  resolves platform binary, runs `init`   │
                         └───────────────┬──────────────────────────┘
                                         │ spawns
┌────────────────────────────────────────▼──────────────────────────────────────┐
│  qbit-vault  (Go binary)                                                    │
│                                                                               │
│  cmd/qbit-vault ── cobra CLI ──┬── init / sync / doctor / uninstall         │
│                                  ├── set / rm / mv / list / import / audit    │
│                                  ├── grant / revoke                           │
│                                  ├── exec                                     │
│                                  ├── prompt   (native capture, internal use)  │
│                                  ├── remote / link (opt-in multi-device sync) │
│                                  └── mcp      (stdio MCP server)              │
│                                                                               │
│  internal/broker      contract v1 handlers; the only module hosts talk to     │
│  internal/vault       envelope, layers (global/project), resolve, atomic write│
│  internal/keychain    go-keyring backend + passphrase/Argon2id fallback       │
│  internal/grants      grants.enc, TTL, scope + layer match                    │
│  internal/runner      child runner: env build/scrub, shell, tree kill, caps   │
│  internal/dumpguard   dump-command guard (data file), wrapper/segment parser  │
│  internal/redact      streaming multi-encoding replacer                       │
│  internal/prompt      tty / osascript / powershell / zenity capture           │
│  internal/audit       hash-chained JSONL                                      │
│  internal/hosts       Adapter interface, step runner, receipts (fake: tests)  │
│  internal/adapters    claude / codex / pi adapters (implement hosts.Adapter)  │
│  internal/filemerge   snapshot + atomic JSON/TOML merge                       │
│  internal/doctor      read-only report                                        │
│  internal/merge       pure three-way per-record merge (hlc, tombstones)       │
│  internal/remote      sync client: keys, pairing, envelopes, rounds, anchors  │
└───────────────────────────────────────────────────────────────────────────────┘
          ▲ CLI (--json)                      ▲ MCP stdio
          │                                   │
┌─────────┴───────────────┐      ┌────────────┴────────────────────────────────┐
│ packages/qbit-vault-pi│      │ Claude Code / Codex / OpenCode / Pi (MCP)   │
│ Pi / Gentle Shell ext.  │      │ tools: secret_request, secret_list,         │
│ masked UI, bash override│      │        secret_exec, secret_manage           │
│ redaction, paste guard  │      │ hooks (where the host has them)             │
└─────────────────────────┘      └─────────────────────────────────────────────┘
```

With sync enabled, `internal/remote` talks HTTPS to **`qbit-vault-server`** (`cmd/qbit-vault-server`, `internal/server`): a self-hosted, zero-knowledge store of sealed vault versions, key envelopes, device public keys and audit anchors (`REMOTE_SYNC.md`). It is a separate deployment; the client stays daemon-free.

Two rules shape everything:

1. **The broker is the only entry point for hosts.** Extension, MCP server and hooks all call `internal/broker`, which implements `contracts/secrets-broker/v1`. Nothing else is reachable from an agent.
2. **Values live in exactly three places**: the encrypted file, process memory of `qbit-vault` for the duration of one operation, and the environment of one `exec` child. The `Secret` type makes accidental printing impossible by construction (`String()` returns `[REDACTED]`). With sync, the server holds a further copy, but only as ciphertext sealed on the device; it never holds a plaintext value or a key that opens one.

## Process model

- No daemon. Every host operation is a fresh `qbit-vault` process (CLI) or a long-lived stdio MCP server **started and owned by the host** (one per host session). Both are stateless apart from the files in `$QBIT_VAULT_HOME`.
- Session identity: the host passes `--session <id>` (Pi session id, Claude Code `session_id` from hook input, MCP server gets it at startup from the host's env or generates one and reports it in `doctor`). Grants are keyed by it.
- Keychain unlock happens per process; the OS caches it. In passphrase mode the unlocked key is cached with a TTL only in a `0600` file under `$XDG_RUNTIME_DIR` (tmpfs on Linux), so the user is not asked on every exec; where no such memory-backed directory exists there is no cache and the passphrase is asked on each unlock.

## Data flows

### Flow A — first request from Pi / Gentle Shell

```
model ──secret_request(GITHUB_TOKEN, "gh release create")──▶ extension
extension ──ctx.ui.custom(masked input + scope)──▶ user types value, picks "session"
extension ──spawn: qbit-vault set GITHUB_TOKEN --stdin --session S --grant session --reason "..."
            (value on stdin, never argv)
qbit-vault: keychain.unlock → vault.put → grants.add(S, GITHUB_TOKEN, session, +30m) → audit
            ◀── {"ok":true,"ref":"secret://GITHUB_TOKEN","grant":{...}}
extension ──tool result──▶ model   (same JSON, no value)
```

### Flow B — exec through the Pi bash override

```
model ──bash("gh release create v1 --notes x")──▶ extension (bash override)
extension: references? scans for $NAME/{{secret:NAME}} AND for known names used by
           the binary (gh → GITHUB_TOKEN via the implicit-binding table, see below)
extension ──spawn: qbit-vault exec --session S --secret GITHUB_TOKEN -- gh release create v1 --notes x
qbit-vault: grants.check(S, GITHUB_TOKEN) → ok
              dumpguard.check(cmd) → ok
              env = scrub(parent env) + {GITHUB_TOKEN: value}
              child = run(cmd, env, pgroup, timeout)
              stdout/stderr → redact → host
              audit(exec)
extension ──tool result (redacted)──▶ model
```

If `grants.check` fails: qbit-vault exits with refusal `grant_required` (JSON). The extension then opens the grant prompt (Flow A without the value step), and retries once.

### Flow C — Claude Code

```
model ──Bash(cmd)──▶ Claude Code ──PreToolUse hook──▶ qbit-vault hook pre-bash --json
hook: same reference scan + dumpguard; returns updatedInput with
      command = "qbit-vault exec --session <session_id> --secret ... -- <cmd>"
      or {decision:"block", reason:"grant_required: GITHUB_TOKEN"} which makes the model
      call secret_request (MCP) → native dialog → grant → model retries Bash.
Claude Code ──PostToolUse hook──▶ qbit-vault hook post --json  (redacts tool_response)
```

### Flow E — agent proposes a management action

```
model ──secret_list()──▶ broker ──▶ {project, secrets (with layer), policy}
model ──secret_manage(move, DATABASE_URL, layer: global, to: project, reason)──▶ host
host ──confirmation prompt (Pi ctx.ui.custom or `qbit-vault prompt --confirm`)──▶ user
        "Move DATABASE_URL from global to shop-api?  reason: …  [Confirm] [Decline]"
user confirms → prompt token → broker: vault.move → grants.drop(DATABASE_URL, global) → audit(manage)
            ◀── {"ok":true,"applied":true,"action":"move","name":"DATABASE_URL","layer":"project"}
user declines → refusal user_declined + cooldown
```

Like grants, applying a `manage` action requires a prompt token that only the broker's own prompt backend issues, so a `manage` arriving without one (for example replayed over MCP) cannot apply anything.

### Flow F — user enters a secret manually

```
user ──qbit-vault set DATABASE_URL (or /vault set in Pi)──▶ masked prompt: value + layer
qbit-vault: keychain.unlock → vault.put(layer) → audit(capture, by: user)
```

No model, no tool call, no grant; the next agent use asks only for a grant.

### Flow G — several fields in one request

```
model ──secret_request(fields: [DB_HOST:text, DB_USER:text, DB_PASSWORD:secret], reason)──▶ host
host ──one prompt (Pi form / PowerShell form / zenity --forms / consecutive boxes)──▶ user
        three boxes (two visible, one masked), layer once, scope once
host ──spawn: qbit-vault set --stdin --fields DB_HOST,DB_USER,DB_PASSWORD --kinds text,text,secret
            --grant session --from-prompt-token T   (JSON of values on stdin)
qbit-vault: one locked write of all three → one grant per record → audit(capture)
            ◀── {"ok":true,"refs":[…three…],"grant":{…}}
```

All-or-nothing: a blank box or a cancel stores and grants nothing.

### Flow H — a change on one machine reaches another

```
laptop: qbit-vault set NPM_TOKEN  → local save → seal body (RVK) → PUT /v1/vault base=41 → version 42
desktop (later): agent calls secret_list → broker pulls (If-None-Match 41) → version 42
         verify AAD + AEAD → merge(base 41, local, remote 42) under vault.lock → local save
         → secret_list shows NPM_TOKEN; first exec asks for a grant on the desktop
```

`exec` never waits on the network; offline machines catch up on their next pull.

### Flow D — Codex / OpenCode (MCP only)

The model calls `secret_exec(command, secrets)` directly. Behavior identical to Flow B inside qbit-vault. OpenCode additionally gets a plugin for bash rewrite when the plugin API is available.

## Implicit binding table

To keep usage natural ("run gh" instead of "run gh with GITHUB_TOKEN"), the extension and hooks consult a data file `bindings.yaml` mapping well-known binaries to the env vars they read:

```yaml
gh:        [GITHUB_TOKEN, GH_TOKEN]
git:       [GITHUB_TOKEN]        # only when remote is github.com and credential helper is qbit-vault
aws:       [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN]
gcloud:    [CLOUDSDK_AUTH_ACCESS_TOKEN]
vercel:    [VERCEL_TOKEN]
npm:       [NPM_TOKEN]
docker:    [DOCKER_PASSWORD]
psql:      [PGPASSWORD, DATABASE_URL]
prisma:    [DATABASE_URL]
openai:    [OPENAI_API_KEY]
anthropic: [ANTHROPIC_API_KEY]
```

A binding only *proposes* names: if the vault has one of them and the session has a grant, it is injected; if the vault has it but no grant, the grant prompt opens; if the vault does not have it, nothing happens (the command runs without it and fails naturally, which is the right signal for the agent to call `secret_request`). The user can edit the file; `doctor` validates it.

## Host registration (`internal/hosts`) and `doctor` (`internal/doctor`)

A host adapter implements `hosts.Adapter`: `Name()` (stable, `[a-z0-9-]`), `Detect(env)` (does the host look installed; read-only) and `Steps(env)`, an ordered list of `hosts.Step`. A step is one reversible edit of one config file with three functions: `Apply(env, prev)` (a `filemerge` merge returning its receipt; it writes nothing when the file already holds our entry), `Revert(env, receipt)` (the `filemerge` 3-way revert) and `Check(env, receipt)` (read-only; `hosts.CheckJSON` and `hosts.CheckTOML` re-run the merge in memory and report `ErrDrift` when it would change the file). `hosts.Env` carries the vault home and the user's home directory.

`hosts.Apply(env, adapters)` is the step runner behind `init` (and later `sync`): per host it applies the steps in order, saving the host's receipts to `state.json` after each step that changed one. A failing step stops that host (its file is left as it was, because `filemerge` refuses before writing) and the next host still runs; the earlier steps stay recorded and the next run applies only what is missing. A run that changes nothing writes neither a config file, a snapshot nor `state.json`. `hosts.Verify` compares the receipts with the files for `doctor`, and `hosts.RevertHost` undoes a host for `uninstall` (steps in reverse order, reporting each step's `filemerge` outcome; the host is forgotten only when every step succeeded; `hosts.Revert` is the same without the report). `sync` is `Apply` over the hosts recorded in `state.json`, plus any named by `--agents`. The release registry is filled by the Claude Code, Codex and Pi adapters (empty until they land); `internal/hosts/fake` is a test-only adapter.

`internal/doctor` builds the report from `state.json`, `internal/perm` and the host configs and writes nothing. The vault is opened the way `remote status` opens it (`openSessionQuiet`): the OS keychain or an unexpired unlock cache, never a passphrase prompt and never a rekey completion; a vault that cannot be opened that way is reported as `locked`, which is not a problem. The sync line comes from `state.json.remote` and its last-round summary; doctor never contacts the server.

## Config file editing (`internal/filemerge`)

Every host adapter edits the user's own files (`~/.claude/settings.json`, `~/.codex/config.toml`, `~/.pi/agent/mcp.json`) only through `internal/filemerge`, which enforces AGENTS.md invariant 7 and PRD R-INS-04/R-INS-09:

- **Snapshot first.** Before any write, the current file is copied to `$QBIT_VAULT_HOME/backups/<UTC timestamp>/<encoded absolute path>` (owner-only; same timestamp layout and `-NNN` suffix as vault snapshots, `STORAGE.md` § Atomic writes and backups). The encoding mirrors the path as a relative tree: `C:\Users\Ana\.claude\settings.json` becomes `C/Users/Ana/.claude/settings.json`, a UNC share becomes `UNC/srv/share/…`, a POSIX path loses its leading slash; `%`, `:`, `\` and the characters Windows forbids in names are percent-escaped. A file that did not exist is recorded as absent and copies nothing.
- **Atomic write.** Temp file in the same directory, `fsync`, rename, directory `fsync`; the original is never opened for writing, so a failure leaves it intact. An existing file keeps its permission bits; a new file is 0600 and its missing parent directories 0700.
- **Symlink policy.** A target that is a symlink (or a Windows reparse point) is **refused** with `ErrSymlink`: it is neither replaced by a regular file nor followed to a place outside the intended path. Only the final path component is checked; a symlinked parent directory (a dotfiles layout of `~/.claude`) is fine. A user who keeps the config file itself in a dotfiles repo registers that host by hand; following links on request is a possible later option.
- **JSON merge** (`MergeJSON`, `UnmergeJSON`): a position-aware editor that splices text, so every key we do not own, the key order, the user's formatting (indent unit, CRLF, colon spacing, one-line objects) survive. We own either an object member addressed by key path (`mcpServers` → `qbit-vault`) or the elements of an array that contain a **marker** string (the `hooks.PreToolUse` elements containing `qbit-vault hook`; a string element such as a `permissions.deny` entry matches on its decoded text). An owned element is replaced as a whole and user elements are never touched. Applying the same edits twice gives the same bytes. Invalid JSON (a BOM and comments included), a duplicate key on the path or a path through a non-object is refused with a typed error and no write.
- **TOML editor** (`MergeTOML`, `UnmergeTOML`, no dependency): adds, replaces or removes only `[mcp_servers.qbit-vault]` and its subtables as text; every other byte, comments included, is untouched, and CRLF files and files without a trailing newline are handled. It tracks multi-line strings and arrays so a `[` inside them is not taken for a header. A table defined twice, an array of tables or an inline/dotted definition (`qbit-vault = {…}`, `mcp_servers = {…}`) is `ErrAmbiguous`.
- **Receipts and 3-way revert.** A merge returns a `Receipt` (absolute path, snapshot handle, SHA-256 of what we wrote, `created`, `exact`) that `state.json` stores (`STORAGE.md` § `state.json`). `Revert` compares the file now with what we wrote: (1) still equal and the receipt `exact` (ours was the only change): restore the snapshot byte for byte, or delete the file if it did not exist before; (2) the user edited it since: remove only our keys or table and keep their edits; (3) when we created the file and nothing but our content remains, delete it. A pruned snapshot falls back to (2). The file as it is at revert time is snapshotted first.

## Key decisions (ADR summary)

| # | Decision | Alternatives rejected | Why |
| --- | --- | --- | --- |
| D1 | Go core | TypeScript core | Same stack as gentle-ai (upstream path), single static binary, no runtime for Codex/OpenCode users, easy keychain bindings |
| D2 | No daemon in v1 | Unix-socket broker daemon | Simpler threat surface, no lifecycle to manage on Windows; grants file gives the same cross-session behavior |
| D3 | Values via stdin / masked prompt, never argv | `set NAME VALUE` | Shell history and `ps` exposure |
| D4 | Per-child env injection | Writing a temp `.env`, exporting to the shell | Temp files leak; exports outlive the command |
| D5 | Grants are user-UI-only | Model-callable `secret_grant` | Prompt injection would grant itself |
| D6 | Existence not disclosed to the model before consent | `secret_request` returning `exists: true` | Avoids enumeration by injected content |
| D7 | XChaCha20-Poly1305 + Argon2id | AES-GCM, scrypt | Misuse-resistant nonces, memory-hard KDF, both in `x/crypto` |
| D8 | Contract-first (`secrets-broker/v1`) | Ad-hoc tool schemas per host | gentle-ai adoption requires it; identical behavior across hosts |
| D9 | Four tools only (`request`, `list`, `exec`, `manage`) | Separate `secret_grant`, `secret_get`, `secret_policy`, one tool per management action | Smallest surface the model can misuse; `get` and `grant` must not exist; policy rides on `list` so the agent learns its rules in the call it makes anyway |
| D11 | Two layers, `global` and `project`, in one encrypted file | Per-project vault files; `.vault` file inside the repo; a per-secret `projects` allowlist | One file keeps project paths encrypted and writes atomic; nothing in the repo means nothing to commit by accident; overrides cover the real case (same name, different value per repo) that an allowlist cannot |
| D12 | Agent management is propose-and-confirm | Agent mutates directly; agent read-only | Keeps invariant 6 (every change is an explicit user action) while letting the agent organize the vault |
| D13 | Grants bind to (name, layer) | Grants bind to name only | Adding a project override must not silently inherit the global grant |
| D10 | Native OS dialogs for non-Pi hosts | Local web page | Zero network listener, zero extra code paths, works today |
| D14 | Own zero-knowledge sync server | S3-compatible storage; a synced folder or git repo; Vaultwarden/Bitwarden | One product with no scripts (the user's request); the client controls conflict handling, pairing and revocation; the server can be self-hosted on Dokploy and holds nothing that decrypts |
| D15 | Pairing with two typed codes plus a recovery key | Password-derived account key (Bitwarden style); trust the server's key directory | No weak password for the server to brute-force; the fingerprint code stops key substitution and the confirmation code stops a planted master key, so the server needs no trust at all |
| D16 | Revocation rotates the master and recovery keys | Revoke the device's server access only | A revoked device knows the key; without rotation it could read every later version with the server's help |
| D17 | Three-way per-record merge with hybrid clocks and kept conflicts | Last writer wins per file; prompt the user on every conflict | Offline edits on two machines must both survive without blocking a non-interactive sync |
| D18 | Project layers by id with per-device roots, linked by the user | Key layers by git remote URL | Paths differ per machine; a URL match alone would hand a project's secrets to any clone of it |
| D19 | Grants and the audit log stay local; only an encrypted audit-head anchor syncs | Sync grants; sync the log | A grant is a decision about one machine and session; the log must stay verifiable offline, and the anchor gives tamper evidence without uploading its content |

## Directory `$QBIT_VAULT_HOME` (default `~/.qbit-vault/`)

```
vault.enc        AEAD envelope (see STORAGE.md)
key.enc          only in passphrase mode
grants.enc       grant metadata, AEAD-encrypted with the master key
audit.jsonl      hash-chained
bindings.yaml    implicit bindings (user-editable)
dumpguard.yaml   refused command patterns (user-extendable)
config.yaml      ttl defaults, prompt backend override, update check opt-out
backups/<ts>/    encrypted vault snapshots and agent-config snapshots
state.json       installed hosts, versions, registration receipts (for sync/uninstall), device id, remote state
remote/          device.enc, base.enc (only when the vault syncs)
keys/retired.enc master keys replaced by rekey, revocation or join (keeps old backups restorable)
```

The whole directory is added to every host's read deny list by `init`.
