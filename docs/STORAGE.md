# Storage, cryptography, keychain, grants and audit

## Vault file: `vault.enc`

A JSON envelope with a cleartext header and one AEAD-encrypted body. The header is authenticated as additional data, so it cannot be altered without detection.

```json
{
  "format": "gentle-vault/1",
  "cipher": "xchacha20poly1305",
  "kdf": null,
  "nonce": "<24 bytes, base64>",
  "aad": { "format": "gentle-vault/1", "created_at": "…", "writes": 42 },
  "ct": "<ciphertext+tag, base64>"
}
```

- `kdf` is `null` in keychain mode. In passphrase mode it is `{ "alg": "argon2id", "salt": "<16B>", "t": 3, "m_kib": 65536, "p": 4 }` and describes how `key.enc` was wrapped, not how the vault body is encrypted (the body is always encrypted with the 32-byte master key).
- A fresh 24-byte nonce is generated for every write. XChaCha20's 192-bit nonce makes random nonces safe without a counter.
- `aad.writes` is a monotonically increasing counter, also stored in `state.json`; a vault file with a lower counter than `state.json` is treated as a rollback and `vault_corrupt` is raised until the user runs `restore`.

### Plaintext body

```json
{
  "global": {
    "GITHUB_TOKEN": {
      "value": "…",
      "description": "GitHub PAT, repo scope",
      "sensitive": false,
      "binaries": ["gh", "git"],
      "hosts": ["api.github.com"],
      "created_at": "…", "updated_at": "…"
    },
    "DATABASE_URL": { "value": "…", "description": "local dev db", "…": "…" }
  },
  "projects": {
    "/home/me/shop-api": {
      "label": "shop-api",
      "secrets": {
        "DATABASE_URL": { "value": "…", "description": "shop-api staging", "…": "…" },
        "STRIPE_SECRET_KEY": { "value": "…", "sensitive": true, "…": "…" }
      }
    }
  }
}
```

### Layers

- `global` holds secrets usable from any directory. `projects` maps a canonical repository root to that project's own secrets. `label` is the root's base name, shown in prompts and `list`.
- **Resolution** of `NAME` for a `cwd`: find the repository root of `cwd` (`git rev-parse --show-toplevel`, else the nearest ancestor containing `.git`); if `projects[root].secrets[NAME]` exists use it, else `global[NAME]`, else `unknown_secret`. A project secret therefore overrides a global one with the same name only inside that repository (PRD R-LAYER-02).
- **Project root rule (v1):** the root is the nearest ancestor of `cwd` that contains a `.git` entry, either a directory or the file of a linked worktree. gentle-vault never spawns `git`; for normal checkouts and linked worktrees this equals `git rev-parse --show-toplevel`. Outside such an ancestor there is no project and only the global layer applies.
- Project roots are canonicalized (absolute, symlinks resolved, case-folded on Windows and macOS) before lookup. Linked Git worktrees resolve to their own top level, so each worktree is its own project unless the user runs `gentle-vault relink` to point it at an existing layer.
- Both layers live in this one encrypted body. Project paths, names and descriptions are as protected as the values. Nothing is ever written inside the repository.

The body is only ever materialized inside `internal/vault` for the duration of one operation, then zeroed (`crypto/subtle`-style wipe of the byte slices; Go cannot guarantee it against GC copies, which is accepted).

## Master key

- 32 bytes from `crypto/rand`.
- **Keychain mode** (default): stored via `go-keyring` under service `gentle-vault`, account `master:<vault-id>`, where `vault-id` is a random UUID written to `state.json`, so multiple vault homes on one machine do not collide.
  - macOS: login Keychain item; user may be asked to allow `gentle-vault` on first access.
  - Windows: Credential Manager generic credential; DPAPI-protected to the user.
  - Linux: Secret Service (GNOME Keyring, KWallet via bridge). If D-Bus/Secret Service is not reachable, fall back to passphrase mode and say so in `doctor`.
- **Passphrase mode**: `key.enc` = `{ kdf, nonce, ct }` where `ct` = XChaCha20-Poly1305(derived_key, master_key). `derived_key` = Argon2id(passphrase, salt, t=3, m=64 MiB, p=4, 32 bytes). Unlock caches the master key in a runtime file (`$XDG_RUNTIME_DIR/gentle-vault/<vault-id>.key`, 0600, or `%LOCALAPPDATA%\gentle-vault\run\` with owner-only ACL) for `config.unlock_ttl` (default 8 h); `gentle-vault lock` deletes it.
- `gentle-vault rekey` rotates the master key: decrypt, generate new key, encrypt, swap, and update keychain/key.enc atomically with a backup of the old envelope.

## Atomic writes and backups

Every mutation of `vault.enc`, `grants.enc`, `state.json`:

1. Copy current file to `backups/<UTC timestamp>/<filename>`, where the directory name is the UTC time formatted with the Go layout `20060102T150405.000000000Z` (for example `20261103T141500.123456789Z`; fixed width, so names sort chronologically) (the vault copy is already encrypted; no extra handling).
2. Write new content to `<filename>.tmp.<pid>` in the same directory, `fsync`.
3. `rename` over the target (atomic on POSIX; `MoveFileEx` with `REPLACE_EXISTING|WRITE_THROUGH` on Windows).
4. `fsync` the directory on POSIX.

A save of `vault.enc` also rewrites `state.json`; step 1 then copies **both** current files into the **same** `backups/<timestamp>/` directory before either is written, so every snapshot is a consistent (`vault.enc`, `state.json`) pair. The first save of a fresh vault has nothing to copy and creates no snapshot. Writes of a single file outside a vault save get their own snapshot directory.

Backups are pruned to the last 20 snapshots by default (`config.backups_keep`), which for vault saves means the last 20 saves. `gentle-vault restore --from <ts>` swaps a backup back in (with its own backup of the current state first).

## File permissions

| File | POSIX | Windows |
| --- | --- | --- |
| `$GENTLE_VAULT_HOME/` | 0700 | owner-only ACL, inheritance disabled |
| `vault.enc`, `key.enc`, `grants.enc`, `audit.jsonl`, `state.json` | 0600 | owner-only ACL |
| `backups/**` | 0600 | owner-only ACL |
| `bindings.yaml`, `dumpguard.yaml`, `config.yaml` | 0600 | owner-only ACL |

`doctor` reports any file whose mode is wider than this.

## Grants: `grants.enc`

Metadata only; losing it loses permissions, never secrets. Stored in the same AEAD envelope as `vault.enc` (own nonce, `format: "gentle-vault-grants/1"` in the header), encrypted with the same master key, so a leaked copy does not reveal which secrets exist, which sessions used them or which repositories they belong to. Decrypted plaintext:

```json
{
  "grants": [
    { "id": "g_01J…", "name": "GITHUB_TOKEN", "layer": "global", "session": "pi:2f1c…", "scope": "session",
      "created_at": "…", "expires_at": "…", "consumed": false,
      "prompt_token_hash": "sha256:…" },
    { "id": "g_01K…", "name": "DATABASE_URL", "layer": "project:/home/me/shop-api", "session": null, "scope": "project",
      "project_root": "/home/me/shop-api", "created_at": "…", "expires_at": null }
  ]
}
```

`layer` is `global` or `project:<root>` and records **which record** the user granted. Evaluation for `exec(name, session, cwd)`:

1. Expired grants are purged on load.
2. Resolve `name` for `cwd` (§ Layers) to a record and its layer. Unknown → `unknown_secret`.
3. Only grants whose `name` **and** `layer` match the resolved record are considered. A grant on the global `DATABASE_URL` never injects the project `DATABASE_URL`, and the reverse.
4. `once`: matching `session`, not consumed → allow and mark consumed.
5. `session`: matching `session` → allow.
6. `project`: `cwd` inside `project_root` → allow.
7. Otherwise `grant_required`.

`mv`, `rm` and `relink` rewrite or drop the grants of the affected record in the same atomic write sequence (vault first, then grants; a crash between the two leaves grants pointing at a missing record, which evaluation treats as `grant_required`).

`prompt_token_hash` records which prompt created the grant (the broker issues a one-time random token to its own prompt backend, and `grant` must present it; the hash is stored for audit). This is the mechanism behind "grants are user-UI-only".

## Audit log: `audit.jsonl`

One JSON object per line. Every record:

```json
{ "ts": "…", "seq": 1042, "prev": "sha256:<hash of previous line>", "event": "exec",
  "session": "pi:2f1c…", "host": {"name":"gentle-shell","version":"3.7.0"},
  "names": ["GITHUB_TOKEN"], "cwd": "/home/me/repo",
  "command": "gh release create v1.2.0 --notes-file CHANGELOG.md",   // redacted
  "exit_code": 0, "duration_ms": 1830, "redactions": 2,
  "hash": "sha256:<hash of this line without the hash field>" }
```

Events: `init`, `capture`, `grant`, `exec`, `refusal`, `revoke`, `rm`, `rekey`, `restore`, `uninstall`, `warning`.

`gentle-vault audit --verify` walks the chain and reports the first broken link. `gentle-vault audit --tail 50`, `--since 24h`, `--name X`, `--json` for the Gentle Shell widget.

The command text is passed through the redactor before being logged (a command that embeds a literal value, which should not happen, still never reaches the log).

## What a leaked directory reveals

If someone copies the whole `$GENTLE_VAULT_HOME` (a stolen backup, a synced folder, a misconfigured share) but not the master key:

| File | Readable without the key | Contents an attacker learns |
| --- | --- | --- |
| `vault.enc`, `backups/**/vault.enc` | no (AEAD) | format, creation time, write counter |
| `grants.enc` | no (AEAD) | format, write counter |
| `key.enc` (passphrase mode) | only by brute-forcing the passphrase through Argon2id (64 MiB per guess) | the master key, if the passphrase is weak |
| `audit.jsonl` | yes | secret **names**, layers, sessions, redacted commands, timestamps. Never values. |
| `state.json`, `config.yaml`, `bindings.yaml`, `dumpguard.yaml` | yes | installed hosts, versions, settings. No names, no values. |

In keychain mode the key never sits in the directory; it lives in the OS keychain, unlocked only by the user's login session. The audit log stays cleartext on purpose: it is append-only and must be verifiable (`audit --verify`) even when the vault is locked or corrupt. Hiding names in the audit log too (keyed hashes) is a v2 candidate, see `ROADMAP.md`.

## `state.json`

```json
{
  "format": "gentle-vault-state/1",
  "vault_id": "uuid", "writes": 42, "keychain": "secret-service",
  "version": "0.1.0",
  "hosts": {
    "claude-code": { "registered_at": "…", "receipts": ["~/.claude/settings.json#hooks", "~/.claude/settings.json#mcpServers.gentle-vault", "~/.claude/settings.json#permissions.deny"], "snapshot": "backups/20261016T081500Z/" },
    "gentle-shell": { "extension": "gentle-vault-pi@0.1.0", "home": "~/.gentle-shell/agent" }
  }
}
```

Receipts are what `sync` re-applies and `uninstall` reverts.
