# Storage, cryptography, keychain, grants and audit

## Vault file: `vault.enc`

A JSON envelope with a cleartext header and one AEAD-encrypted body. The header is authenticated as additional data, so it cannot be altered without detection.

```json
{
  "format": "gentle-vault/1",
  "cipher": "xchacha20poly1305",
  "nonce": "<24 bytes, base64>",
  "aad": { "format": "gentle-vault/1", "cipher": "xchacha20poly1305", "created_at": "…", "writes": 42 },
  "ct": "<ciphertext+tag, base64>"
}
```

- There is no `kdf` field: the body is always encrypted with the 32-byte master key, and `key.enc` (§ Master key) is the only place that describes how a key was wrapped. The top-level `format` and `cipher` repeat the values inside `aad`, which is the authenticated copy: the two must match, any other mismatch, an edited header field or an unknown top-level field is `vault_corrupt`.
- A fresh 24-byte nonce is generated for every write. XChaCha20's 192-bit nonce makes random nonces safe without a counter.
- `aad.writes` is a monotonically increasing counter, also stored in `state.json`; a vault file with a lower counter than `state.json` is treated as a rollback and `vault_corrupt` is raised until the user runs `restore`.

### Plaintext body

```json
{
  "global": {
    "GITHUB_TOKEN": {
      "id": "9f2c…",
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

**Record id.** Every record carries a random `id` (16 bytes from `crypto/rand`, hex) inside the encrypted body. It is created when the record is created and **regenerated whenever its value is replaced**; metadata edits (`edit`), `mv` and `relink` keep it (they keep the value). Grants bind to it (see § Grants). The id is internal: no command prints it.

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
- **Passphrase mode**: `key.enc` = `{ format, kdf, nonce, ct }` with `format` = `gentle-vault-key/1` and `kdf` = `{ alg: "argon2id", salt: <16 B, base64>, t: 3, m_kib: 65536, p: 4 }`. `ct` = XChaCha20-Poly1305(derived_key, master_key) with a 24-byte random nonce. `derived_key` = Argon2id(passphrase, salt, t=3, m=64 MiB, p=4, 32 bytes). The AAD is the canonical JSON of `{ format, kdf }`, so the KDF parameters and salt are authenticated: altering them makes decryption fail. Before running Argon2, parameters outside `t` 1..10, `m_kib` 65536..1048576, `p` 1..16, or a salt that is not 16 bytes, are refused as corrupt, so a doctored file cannot make the process allocate gigabytes. A wrong passphrase and a tampered file are indistinguishable by design (`ErrBadPassphrase`, fixed message, never echoing input). A blank or whitespace-only passphrase is refused. `key.enc` is written atomically (temp file, `fsync`, rename; 0600 on POSIX).
- **Mode is implied by the files**: `key.enc` present means passphrase mode; otherwise the OS keychain. There is no mode field in `state.json`.
- **Unlock cache**: the unlocked key is cached only in a memory-backed runtime directory: `$XDG_RUNTIME_DIR/gentle-vault/<vault-id>.key` (0600 file in a 0700 directory, tmpfs on Linux), content `{ expires_at, key }`, for `config.unlock_ttl` (default 8 h). It is used only on Linux, and only when `$XDG_RUNTIME_DIR` is set to an absolute path naming an existing directory; the directory and file are made owner-only through `internal/perm`. Everywhere else (Windows, macOS, Linux without `XDG_RUNTIME_DIR`) there is no cache and the passphrase is asked on every unlock: those platforms ship an OS keychain, so passphrase mode is rare there, and a disk-backed cache would put the key on disk unencrypted. An expired entry is deleted and ignored; `gentle-vault lock` deletes the file.
- `gentle-vault rekey` rotates the master key: decrypt, generate new key, encrypt, swap, and update keychain/key.enc atomically with a backup of the old envelope.

## Atomic writes and backups

Every mutation of `vault.enc`, `grants.enc`, `state.json` runs under the vault lock (below), then:

1. Copy current file to `backups/<UTC timestamp>/<filename>`, where the directory name is the UTC time formatted with the Go layout `20060102T150405.000000000Z` (for example `20261103T141500.123456789Z`; fixed width, so names sort chronologically) (the vault copy is already encrypted; no extra handling). If that directory already exists (two saves on the same clock tick, which coarse Windows clocks allow), a fixed-width `-001`, `-002`, … suffix is appended, so snapshots never share a directory.
2. Remove leftover `<filename>.tmp.*` files from a crashed save (safe: the lock is held), then write new content to `<filename>.tmp.<pid>.<8 random hex>` in the same directory, `fsync`. The random suffix keeps two handles in one process from colliding.
3. `rename` over the target (atomic on POSIX; on Windows Go's `os.Rename` calls `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING`, with no `WRITE_THROUGH`: durability comes from the temp file's `fsync` before the rename). On Windows a rename can fail while another process (antivirus, indexer) briefly has the target open (access denied, sharing or lock violation); those errors are retried with backoff (1 ms doubling to 100 ms) for up to 2 s in total, after which the save fails with the file name only and the vault untouched.
4. `fsync` the directory on POSIX.

If a save fails before it replaced anything, the snapshot it created is removed, so failed saves do not consume backup slots. If it fails after `vault.enc` was replaced but before `state.json` was, the snapshot is kept: it is the only copy of the previous consistent pair.

The repair of `state.json` on load (vault file ahead of the counter after a crash between the two writes) rewrites `state.json` atomically with no snapshot: it restates a counter the vault file already proves and is not a user mutation.

**Vault lock.** Every operation that reads or writes the vault, including load and repair, first creates `$GENTLE_VAULT_HOME/vault.lock` with `O_CREATE|O_EXCL` (0600); the file holds the pid and an RFC3339 timestamp. Acquisition retries every few milliseconds for up to 5 s, then fails with the typed `ErrLocked` ("vault is busy"). A lock file older than 30 s is presumed left by a crashed process: it is removed once and acquisition retried. Two processes that both judge the same lock stale can race on that removal; the window is a few file operations and a live holder that exceeds 30 s loses its lock, which is accepted. The lock is released on return, error or panic, and only if the file is still the one this handle wrote. Reads re-load from disk under the same lock, so they see other processes' writes.

A save of `vault.enc` also rewrites `state.json`; step 1 then copies **both** current files into the **same** `backups/<timestamp>/` directory before either is written, so every snapshot is a consistent (`vault.enc`, `state.json`) pair. The first save of a fresh vault has nothing to copy and creates no snapshot. Writes of a single file outside a vault save get their own snapshot directory.

Backups are pruned to the last 20 snapshots by default (`config.backups_keep`), which for vault saves means the last 20 saves. `gentle-vault restore --from <ts>` swaps a backup back in (with its own backup of the current state first).

## File permissions

| File | POSIX | Windows |
| --- | --- | --- |
| `$GENTLE_VAULT_HOME/` | 0700 | owner-only ACL, inheritance disabled |
| `vault.enc`, `key.enc`, `grants.enc`, `audit.jsonl`, `audit.head`, `state.json` | 0600 | owner-only ACL |
| `backups/**` | 0600 | owner-only ACL |
| `bindings.yaml`, `dumpguard.yaml`, `config.yaml` | 0600 | owner-only ACL |

`doctor` reports any file whose mode is wider than this.

**Enforcement.** `internal/perm` (`EnsureDir`, `EnsureFile`, `Check`) applies the table. `internal/vault` calls it as it creates things, before secret-bearing bytes are written or a temp file replaces a live one: the home directory on every locked operation that may create it, the lock files (`vault.lock`, `audit.lock`) right after they are created, each temp file before the rename over `vault.enc` or `state.json`, and the `backups/` directory, every snapshot directory and every snapshot file. On POSIX a path wider than 0700/0600 is tightened with `chmod`; stricter modes are left alone. On Windows the path gets a protected DACL (inheritance disabled) with a single allow entry for the current user's SID, set through `golang.org/x/sys/windows`; the home directory's entry is inheritable, so files created inside start out private. `Check` reports a Windows path as private when no access-allowed entry names another SID and the DACL is not null. `internal/keychain` applies the same rule to `key.enc` (and its temp file, before any key bytes are written) and to the unlock cache.

## Grants: `grants.enc`

Metadata only; losing it loses permissions, never secrets. Stored in the same AEAD envelope as `vault.enc` (own nonce, `format: "gentle-vault-grants/1"` in the header), encrypted with the same master key, so a leaked copy does not reveal which secrets exist, which sessions used them or which repositories they belong to. Decrypted plaintext:

```json
{
  "grants": [
    { "id": "g_01J…", "name": "GITHUB_TOKEN", "layer": "global", "record_id": "9f2c…", "session": "pi:2f1c…", "scope": "session",
      "created_at": "…", "expires_at": "…", "consumed": false,
      "prompt_token_hash": "sha256:…" },
    { "id": "g_01K…", "name": "DATABASE_URL", "layer": "project:/home/me/shop-api", "record_id": "41ab…", "session": "", "scope": "project",
      "project_root": "/home/me/shop-api", "created_at": "…", "expires_at": null, "consumed": false }
  ],
  "tokens": [
    { "hash": "sha256:…", "name": "GITHUB_TOKEN", "layer": "global", "scope": "session", "session": "pi:2f1c…", "expires_at": "…" }
  ]
}
```

`session` is empty and `expires_at` null for `project` scope. Timestamps are RFC 3339 UTC.

**File.** `grants.enc` is managed by `internal/vault` under the same `vault.lock` as `vault.enc`; the vault never interprets the body (`internal/grants` does). The envelope is the one of `vault.enc` (`internal/envelope`) with `format: "gentle-vault-grants/1"` in the header and in the AAD, so a `vault.enc` can never be opened as grants or the reverse. It has its own write counter, `grants_writes`, in `state.json` (unknown keys of `state.json` are preserved). A grants write seals the next body with `writes` = counter + 1, replaces `grants.enc` atomically (temp file, `fsync`, rename, owner-only like the other files), then records the counter in `state.json`. There are **no snapshots** of `grants.enc`: losing it loses permissions, never secrets, and restoring an old copy would revive revoked grants.

**Fail closed (L3).** A `grants.enc` that is missing is an empty store. One that cannot be trusted (malformed, altered, wrong key or wrong format) or whose `writes` is **behind** `grants_writes` (a rollback that would revive revoked grants) is also treated as an empty store, and the operation reports a `reset` to the CLI, which prints `warning: grants were reset (store unreadable or rolled back)` on stderr and appends an audit `warning` record with `detail: "grants reset"`. The next grants write replaces the bad file (`grants` and `describe` do it on first read). One that is **ahead** of the counter (a crash between the two writes, or a counter missing from `state.json`) is accepted and the counter repaired. The counter is not authenticated (THREAT_MODEL R8).

**Tokens.** `tokens` holds the pending prompt tokens (see below): only the SHA-256 of a random 32-byte value, never the value. They expire after 2 minutes, are removed when redeemed (also when presented for the wrong request) and purged with expired grants.

`layer` is `global` or `project:<root>` and records **which record** the user granted. Evaluation for `exec(name, session, cwd)`:

1. Expired grants are purged on load.
2. Resolve `name` for `cwd` (§ Layers) to a record and its layer. Unknown → `unknown_secret`.
3. Only grants whose `name`, `layer` **and `record_id`** match the resolved record are considered. A grant on the global `DATABASE_URL` never injects the project `DATABASE_URL`, and the reverse.
4. `once`: matching `session`, not consumed → allow and mark consumed.
5. `session`: matching `session` → allow.
6. `project`: `cwd` inside `project_root` → allow.
7. Otherwise `grant_required`.

`mv`, `rm`, a value replacement (`set` over an existing record) and `relink` rewrite or drop the grants of the affected record inside the same locked operation (vault first, then grants). `rm`, `mv` and replace drop the grants of that `(name, layer)`; `mv` drops those of both layers (an overwritten target's grants belonged to a value that is gone); `relink` rewrites layer `project:<old>` to `project:<new>` and `project_root` with it. Metadata edits (`edit`) keep their grants. A crash or failure between the vault write and the grants write can leave grants for a record that is gone. They are inert: a grant stores the `record_id` of the record it was granted for, and a re-created or value-replaced secret with the same name and layer has a new id, so the stale grant never matches it (evaluation says `grant_required`). The drop is cleanup, not what keeps the stale grant from authorizing the new record. A grant with no `record_id`, or a check with an empty id, matches nothing.

**Scope rules** (`internal/grants`). `once` and `session` need a host session; `project` needs a project record, stores `project_root` and no session, and never expires. A `sensitive` record accepts `once` only. `session` lives 30 minutes by default (`--ttl` 1 minute to 24 hours); an unused `once` grant expires after 10 minutes and is consumed by the first matching check. Adding a grant replaces an identical `(name, layer, session, scope)` grant. A `project` grant also requires `cwd` to be inside `project_root`, on path boundaries (`/work/shop` does not cover `/work/shop-old`).

`prompt_token_hash` records which prompt created the grant (the broker issues a one-time random token to its own prompt backend, and `grant` must present it; the hash is stored for audit). This is the mechanism behind "grants are user-UI-only". A token is 32 random bytes in base64url, bound to one `(name, layer, scope, session)`, valid for 2 minutes and for one use; an unknown, expired, reused or mismatched token is refused as `not_model_callable`. Until the prompt backend exists (slices 1.9 and 1.10) the CLI confirms a grant either with such a token (`--from-prompt-token`) or with a y/N answer when stdin and stdout are both terminals.

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

Events: `init`, `capture`, `grant`, `exec`, `manage`, `refusal`, `revoke`, `rm`, `mv`, `edit`, `relink`, `rekey`, `restore`, `uninstall`, `warning`. An unknown event is refused when appending.

**Fields.** In this order: `ts` (RFC 3339, nanoseconds, UTC), `seq` (1-based), `prev`, `event`, `session`, then the optional `host` (`{name, version}`), `names`, `layer` (`global` or `project:<root>`), `by`, `reason`, `cwd`, `refusal` (the refusal type), `scope`, `expires_at`, `command`, `exit_code`, `duration_ms`, `redactions`, `outcome`, `detail`, and finally `hash`. Optional fields are omitted when empty. The API takes secret **names** only; a name that does not match the secret-name rule is dropped (never written raw) and the record gets `detail: "invalid name"`.

**Chain.** `prev` is `sha256:` plus the hex SHA-256 of the previous line's raw bytes, without the newline; the first record's `prev` is `sha256:` plus 64 zeros. `hash` is `sha256:` plus the hex SHA-256 of the record's canonical JSON (fields in the order above) encoded with `"hash":""`, that is, with the hash value empty, not with the field removed. Editing a line breaks its own `hash`; deleting, inserting or reordering lines breaks the next `prev`.

**Anchor.** After each append, `audit.head` (`{"seq":N,"hash":"sha256:…","line":"sha256:…"}`) is replaced atomically (temp file, fsync, rename). `hash` is the `hash` field of record N; `line` is the SHA-256 of record N's raw line, which is exactly the `prev` the next record needs. Without the anchor, deleting the tail of the log would leave a chain that still verifies. If the log is missing or empty while the anchor has `seq` > 0, the next append does **not** restart at genesis: it continues with `seq` = anchor `seq` + 1 and `prev` = the anchor's `line`, so a deleted log stays visible. The same applies when the log is shorter than the anchor (its tail was removed): the next append continues from the anchor, not from the surviving last line, and the gap shows up as `bad_prev`. `--verify` reports `truncated` at line 1 for a missing or empty log with such an anchor, and for a log whose first record has `seq` ≠ 1 (the log starts after genesis). It also reports `truncated` when the log ends before the anchor and `head_mismatch` when the anchor does not match the record it names (`hash` and `line`), or is missing a field or unreadable; an anchor one record behind the log (a crash between the two writes) is fine, and a missing `audit.head` next to an existing log is valid. The anchor catches accidental truncation and naive deletion, not an attacker who rewrites both files (THREAT_MODEL R8).

**Appending.** Appends from any process serialize on `audit.lock` (the same lock-file mechanism as `vault.lock`, bounded wait, stale break). The writer reads the last line from the end of the file (a 64 KiB window), writes one line with `O_APPEND`, fsyncs, then writes the anchor. If the last line is malformed (partial, not JSON, longer than the window) the writer does not guess from it: it ends the partial line with a newline, sets `prev` to the hash of those raw bytes and `seq` to the anchor's `seq` plus one (without a readable anchor, the number of lines plus one), so `--verify` still reports the damage.

**Verify.** `gentle-vault audit --verify` walks every line and reports the first problem as `{line, seq, reason}`, with `reason` one of `bad_json`, `bad_hash` (the line is not exactly the canonical encoding of its fields, or its `hash` is wrong), `bad_prev`, `bad_seq`, `partial_line` (the last line lacks its newline), `truncated`, `head_mismatch`. A missing log and a missing anchor are valid with 0 records.

**Who writes.** The CLI writes `init` (`detail` = keychain mode, only when a vault is created), `capture` (`set`: names, layer, `detail: "replaced"` when replacing a value), `rm`, `edit`, `mv` (layer = destination, `detail: "global->project"` or `"project->global"`), `relink` (`cwd`) and one `refusal` record (type, and the secret name when it is valid) for every typed refusal a command returns. `session` is `--session` or `cli`; `by` is `user`. A record never holds a value, a description, a binary list or command arguments. `grant` (names, layer, `scope`, `expires_at` when the grant expires, `detail` `terminal` or `prompt token`, `session` = the host session) and `revoke` (names when revoking by name, `layer` when a layer was named, `detail` `name|all|session revoked=N`) are written by `grant`, `set --grant` and `revoke`; a `warning` with `detail: "grants reset"` is written when `grants.enc` is reset. `exec` and `manage` records arrive with their slices.

**Best effort (CLI).** The vault change is already committed when its record is written, so a failed append prints `warning: audit log write failed` to stderr and leaves the exit code and stdout alone. A home directory that does not exist has no audit log and is skipped silently. `revoke` is best effort too (it only narrows access). **`grant` is fail-closed (L4):** its `grant` record is appended before the grant is persisted, and if the append fails the grant is not created (refusal `internal`). Exec (slice 1.8) will decide separately.

`gentle-vault audit --tail 50`, `--since 24h`, `--name X`, `--event E`, `--json` for the Gentle Shell widget; the log is read under `audit.lock`, so a reader never sees a half-written line, and it works without unlocking the vault.

The command text is passed through the redactor before being logged (a command that embeds a literal value, which should not happen, still never reaches the log).

## What a leaked directory reveals

If someone copies the whole `$GENTLE_VAULT_HOME` (a stolen backup, a synced folder, a misconfigured share) but not the master key:

| File | Readable without the key | Contents an attacker learns |
| --- | --- | --- |
| `vault.enc`, `backups/**/vault.enc` | no (AEAD) | format, creation time, write counter |
| `grants.enc` | no (AEAD) | format, write counter |
| `key.enc` (passphrase mode) | only by brute-forcing the passphrase through Argon2id (64 MiB per guess) | the master key, if the passphrase is weak |
| `audit.jsonl` | yes | secret **names**, layers, sessions, redacted commands, timestamps. Never values. |
| `audit.head` | yes | the sequence number and hash of the newest audit record. No names, no values. |
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
