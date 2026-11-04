# Storage, cryptography, keychain, grants and audit

## Vault file: `vault.enc`

A JSON envelope with a cleartext header and one AEAD-encrypted body. The header is authenticated as additional data, so it cannot be altered without detection.

```json
{
  "format": "qbit-vault/1",
  "cipher": "xchacha20poly1305",
  "nonce": "<24 bytes, base64>",
  "aad": { "format": "qbit-vault/1", "cipher": "xchacha20poly1305", "created_at": "…", "writes": 42 },
  "ct": "<ciphertext+tag, base64>"
}
```

- There is no `kdf` field: the body is always encrypted with the 32-byte master key, and `key.enc` (§ Master key) is the only place that describes how a key was wrapped. The top-level `format` and `cipher` repeat the values inside `aad`, which is the authenticated copy: the two must match, any other mismatch, an edited header field or an unknown top-level field is `vault_corrupt`.
- A fresh 24-byte nonce is generated for every write. XChaCha20's 192-bit nonce makes random nonces safe without a counter.
- `aad.writes` is a monotonically increasing counter, also stored in `state.json`; a vault file with a lower counter than `state.json` is treated as a rollback and `vault_corrupt` is raised until the user runs `restore`.

### Plaintext body

```json
{
  "schema": 2,
  "global": {
    "GITHUB_TOKEN": {
      "id": "9f2c…",
      "value": "…",
      "kind": "secret",
      "description": "GitHub PAT, repo scope",
      "sensitive": false,
      "binaries": ["gh", "git"],
      "hosts": ["api.github.com"],
      "created_at": "…", "updated_at": "…",
      "hlc": "1793782800123.0@3fa1…"
    },
    "DATABASE_URL": { "value": "…", "description": "local dev db", "…": "…" }
  },
  "projects": {
    "7c41…": {
      "label": "shop-api",
      "origin": "github.com/acme/shop-api",
      "roots": { "3fa1…": "/home/me/shop-api", "b20e…": "C:/Users/me/code/shop-api" },
      "hlc": "…",
      "secrets": {
        "DATABASE_URL": { "value": "…", "description": "shop-api staging", "…": "…" },
        "DB_HOST": { "value": "…", "kind": "text", "…": "…" },
        "STRIPE_SECRET_KEY": { "value": "…", "sensitive": true, "…": "…" }
      }
    }
  },
  "tombstones": [ { "key": "global/OLD_TOKEN", "hlc": "…", "deleted_by": "3fa1…" } ],
  "conflicts": [],
  "devices": {
    "3fa1…": { "label": "laptop", "sign_pub": "…", "box_pub": "…", "added_at": "…", "added_by": "register",
                "revoked_at": null, "last_sync": { "version": 41, "at": "…" } }
  }
}
```

**Schema 2.** `schema` is absent in schema 1 bodies (the format before sync). Schema 2 adds, per record, `kind` (`secret` or `text`, default `secret`; R-VAULT-06) and `hlc` (the hybrid logical clock of its last change, `REMOTE_SYNC.md` § 7.3); keys `projects` by a random 16-byte hex **project id** with `label`, an optional normalized `origin` URL read from `.git/config` when the layer is created, and `roots` (device id → canonical root); and adds `tombstones`, `conflicts` and `devices` (the roster, empty until sync is enabled). A vault without sync uses the same schema; its `roots` hold only its own device. **Migration** happens on the first save after an upgrade, under the vault lock and with the usual snapshot: every schema-1 project layer gets a new id, `roots: {<this device>: <old key>}` and `origin` when the root still has one; every record gets `kind: "secret"` and an `hlc` from the current time; `schema` becomes 2. A schema-1 binary refuses a schema-2 body as `vault_corrupt` with the message `vault was written by a newer qbit-vault; upgrade`, and a body with a `schema` higher than it knows is refused the same way.

**Stamping.** No command writes an `hlc` or a tombstone itself: every save compares the body with the one it loaded, and a record (or project label/origin) that is new, changed or still without an `hlc` gets `<unix_ms>.<counter>@<device_id>`, never lower than the highest one in the body; a record that disappeared leaves `{key, hlc, deleted_by}` with the key `global/<NAME>` or `project/<id>/<NAME>`, removed again when the key comes back and purged after 180 days. A project layer whose root for this device is taken by another layer, or missing, is kept aside as unlinked and written back unchanged.

**Device id.** `state.json.device_id` is 16 random bytes (hex) created by `init` or by the migration. A vault from before device ids gets one on its first load (saved with the counter repair). It names this machine in `roots` and the roster whether or not sync is enabled.

**Record id.** Every record carries a random `id` (16 bytes from `crypto/rand`, hex) inside the encrypted body. It is created when the record is created and **regenerated whenever its value is replaced**; metadata edits (`edit`), `mv` and `relink` keep it (they keep the value). Grants bind to it (see § Grants). The id is internal: no command prints it.

### Layers

- `global` holds secrets usable from any directory. `projects` maps a canonical repository root to that project's own secrets. `label` is the root's base name, shown in prompts and `list`.
- **Resolution** of `NAME` for a `cwd`: find the repository root of `cwd` (`git rev-parse --show-toplevel`, else the nearest ancestor containing `.git`); find the project whose `roots[<this device>]` equals that root; if its `secrets[NAME]` exists use it, else `global[NAME]`, else `unknown_secret`. A project layer with no root for this device (it came from another machine through sync) is invisible until the user runs `qbit-vault link` (`REMOTE_SYNC.md` § 7.5). A project secret therefore overrides a global one with the same name only inside that repository (PRD R-LAYER-02).
- **Project root rule (v1):** the root is the nearest ancestor of `cwd` that contains a `.git` entry, either a directory or the file of a linked worktree. qbit-vault never spawns `git`; for normal checkouts and linked worktrees this equals `git rev-parse --show-toplevel`. Outside such an ancestor there is no project and only the global layer applies.
- Project roots are canonicalized (absolute, symlinks resolved, case-folded on Windows and macOS) before lookup. Linked Git worktrees resolve to their own top level, so each worktree is its own project unless the user runs `qbit-vault relink` to point it at an existing layer.
- Both layers live in this one encrypted body. Project paths, names and descriptions are as protected as the values. Nothing is ever written inside the repository.

The body is only ever materialized inside `internal/vault` for the duration of one operation, then zeroed (`crypto/subtle`-style wipe of the byte slices; Go cannot guarantee it against GC copies, which is accepted).

## Master key

- 32 bytes from `crypto/rand`.
- **Keychain mode** (default): stored via `go-keyring` under service `qbit-vault`, account `master:<vault-id>`, where `vault-id` is a random UUID written to `state.json`, so multiple vault homes on one machine do not collide.
  - macOS: login Keychain item; user may be asked to allow `qbit-vault` on first access.
  - Windows: Credential Manager generic credential; DPAPI-protected to the user.
  - Linux: Secret Service (GNOME Keyring, KWallet via bridge). If D-Bus/Secret Service is not reachable, fall back to passphrase mode and say so in `doctor`.
- **Passphrase mode**: `key.enc` = `{ format, kdf, nonce, ct }` with `format` = `qbit-vault-key/1` and `kdf` = `{ alg: "argon2id", salt: <16 B, base64>, t: 3, m_kib: 65536, p: 4 }`. `ct` = XChaCha20-Poly1305(derived_key, master_key) with a 24-byte random nonce. `derived_key` = Argon2id(passphrase, salt, t=3, m=64 MiB, p=4, 32 bytes). The AAD is the canonical JSON of `{ format, kdf }`, so the KDF parameters and salt are authenticated: altering them makes decryption fail. Before running Argon2, parameters outside `t` 1..10, `m_kib` 65536..1048576, `p` 1..16, or a salt that is not 16 bytes, are refused as corrupt, so a doctored file cannot make the process allocate gigabytes. A wrong passphrase and a tampered file are indistinguishable by design (`ErrBadPassphrase`, fixed message, never echoing input). A blank or whitespace-only passphrase is refused. `key.enc` is written atomically (temp file, `fsync`, rename; 0600 on POSIX).
- **Mode is implied by the files**: `key.enc` present means passphrase mode; otherwise the OS keychain. There is no mode field in `state.json`.
- **Unlock cache**: the unlocked key is cached only in a memory-backed runtime directory: `$XDG_RUNTIME_DIR/qbit-vault/<vault-id>.key` (0600 file in a 0700 directory, tmpfs on Linux), content `{ expires_at, key }`, for `config.unlock_ttl` (default 8 h). It is used only on Linux, and only when `$XDG_RUNTIME_DIR` is set to an absolute path naming an existing directory; the directory and file are made owner-only through `internal/perm`. Everywhere else (Windows, macOS, Linux without `XDG_RUNTIME_DIR`) there is no cache and the passphrase is asked on every unlock: those platforms ship an OS keychain, so passphrase mode is rare there, and a disk-backed cache would put the key on disk unencrypted. An expired entry is deleted and ignored; `qbit-vault lock` deletes the file.
- **Passphrase prompt**: `init --passphrase` (without `--passphrase-stdin`) asks the passphrase twice and every command that needs the key in passphrase mode with no cache entry asks it once, both through the prompt backend (slice 1.9: the controlling terminal, echo off, never stdin). The unlock prompt is used only when a controlling terminal exists; otherwise the vault stays locked (`vault_locked`) as before. Ctrl-C or end of input is `cancelled` (exit 1) and a wrong passphrase is `vault_locked`; a successful unlock refreshes the cache where one is available.
- `qbit-vault rekey` rotates the master key: decrypt, generate new key, encrypt, swap, and update keychain/key.enc atomically with a backup of the old envelope, and add the old key to `keys/retired.enc` (§ Retired keys). There is no moment in which a crash leaves the vault sealed with a key that is not stored: (1) **stage** the new key durably (keychain account `master:next:<vault-id>`, or `key.next.enc` wrapped with the same passphrase, which is asked and must unwrap `key.enc` to the current key); (2) **re-seal**, under the vault lock and resumable: `vault.enc` (as a normal save, so the old envelope becomes a snapshot), then `grants.enc`, then `keys/retired.enc`, each opened with the new key first and the old one only when that fails; (3) **promote**: the staged key overwrites the main entry (`key.next.enc` is renamed over `key.enc`), the unlock cache is refreshed, the staged entry is deleted. A rekey refused before step 2 changed anything (a rolled-back vault) deletes the staged key. When the main key cannot open the vault and a staged key exists, the next command finishes steps 2 and 3 and warns `an interrupted rekey was finished`. A staged key left by a crash **before** step 2 protects nothing and is overwritten by the next rekey. With sync enabled it is the rekey of `REMOTE_SYNC.md` § 4.5: other devices receive the new key through the server, sealed to their device keys.

## Atomic writes and backups

Every mutation of `vault.enc`, `grants.enc`, `state.json` runs under the vault lock (below), then:

1. Copy current file to `backups/<UTC timestamp>/<filename>`, where the directory name is the UTC time formatted with the Go layout `20060102T150405.000000000Z` (for example `20261103T141500.123456789Z`; fixed width, so names sort chronologically) (the vault copy is already encrypted; no extra handling). If that directory already exists (two saves on the same clock tick, which coarse Windows clocks allow), a fixed-width `-001`, `-002`, … suffix is appended, so snapshots never share a directory.
2. Remove leftover `<filename>.tmp.*` files from a crashed save (safe: the lock is held), then write new content to `<filename>.tmp.<pid>.<8 random hex>` in the same directory, `fsync`. The random suffix keeps two handles in one process from colliding.
3. `rename` over the target (atomic on POSIX; on Windows Go's `os.Rename` calls `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING`, with no `WRITE_THROUGH`: durability comes from the temp file's `fsync` before the rename). On Windows a rename can fail while another process (antivirus, indexer) briefly has the target open (access denied, sharing or lock violation); those errors are retried with backoff (1 ms doubling to 100 ms) for up to 2 s in total, after which the save fails with the file name only and the vault untouched.
4. `fsync` the directory on POSIX.

If a save fails before it replaced anything, the snapshot it created is removed, so failed saves do not consume backup slots. If it fails after `vault.enc` was replaced but before `state.json` was, the snapshot is kept: it is the only copy of the previous consistent pair.

The repair of `state.json` on load (vault file ahead of the counter after a crash between the two writes) rewrites `state.json` atomically with no snapshot: it restates a counter the vault file already proves and is not a user mutation.

**Vault lock.** Every operation that reads or writes the vault, including load and repair, first creates `$QBIT_VAULT_HOME/vault.lock` with `O_CREATE|O_EXCL` (0600); the file holds the pid and an RFC3339 timestamp. Acquisition retries every few milliseconds for up to 5 s, then fails with the typed `ErrLocked` ("vault is busy"). A lock file older than 30 s is presumed left by a crashed process: it is removed once and acquisition retried. Two processes that both judge the same lock stale can race on that removal; the window is a few file operations and a live holder that exceeds 30 s loses its lock, which is accepted. The lock is released on return, error or panic, and only if the file is still the one this handle wrote. Reads re-load from disk under the same lock, so they see other processes' writes.

A save of `vault.enc` also rewrites `state.json`; step 1 then copies **both** current files into the **same** `backups/<timestamp>/` directory before either is written, so every snapshot is a consistent (`vault.enc`, `state.json`) pair. The first save of a fresh vault has nothing to copy and creates no snapshot. Writes of a single file outside a vault save get their own snapshot directory.

**Agent config snapshots.** `internal/filemerge` (`ARCHITECTURE.md` § Config file editing) snapshots every host config file it is about to change (and the file as it is before a revert) into its own `backups/<timestamp>/<encoded absolute path>/` tree: `C:\Users\Ana\.claude\settings.json` is stored as `backups/<ts>/C/Users/Ana/.claude/settings.json`, a POSIX path without its leading slash, a UNC share under `UNC/`. Files are owner-only like the rest of `backups/`. A merge that changes nothing takes no snapshot. These directories share the vault's pruning: a receipt whose snapshot was pruned still reverts, by removing only our entries instead of restoring the copy.

Backups are pruned to the last 20 snapshots by default (`config.backups_keep`), which for vault saves means the last 20 saves. `qbit-vault restore --from <ts>` swaps a backup back in (with its own backup of the current state first): it opens the snapshot's `vault.enc` with the current key or a retired one and saves that body as the **next** write under the current key, so the rollback counter moves forward instead of tripping `vault_corrupt`. It works over a corrupt or rolled-back live vault and takes the snapshot's `state.json` when the live one is unreadable. `grants.enc` is not part of a snapshot and is left alone.

## File permissions

| File | POSIX | Windows |
| --- | --- | --- |
| `$QBIT_VAULT_HOME/` | 0700 | owner-only ACL, inheritance disabled |
| `vault.enc`, `key.enc`, `grants.enc`, `audit.jsonl`, `audit.head`, `state.json` | 0600 | owner-only ACL |
| `backups/**` | 0600 | owner-only ACL |
| `remote/`, `keys/` | 0700 | owner-only ACL |
| `remote/*.enc`, `keys/retired.enc` | 0600 | owner-only ACL |
| `bindings.yaml`, `dumpguard.yaml`, `config.yaml` | 0600 | owner-only ACL |

`doctor` reports any file whose mode is wider than this.

**Enforcement.** `internal/perm` (`EnsureDir`, `EnsureFile`, `Check`) applies the table. `internal/vault` calls it as it creates things, before secret-bearing bytes are written or a temp file replaces a live one: the home directory on every locked operation that may create it, the lock files (`vault.lock`, `audit.lock`) right after they are created, each temp file before the rename over `vault.enc` or `state.json`, and the `backups/` directory, every snapshot directory and every snapshot file. On POSIX a path wider than 0700/0600 is tightened with `chmod`; stricter modes are left alone. On Windows the path gets a protected DACL (inheritance disabled) with a single allow entry for the current user's SID, set through `golang.org/x/sys/windows`; the home directory's entry is inheritable, so files created inside start out private. `Check` reports a Windows path as private when no access-allowed entry names another SID and the DACL is not null. `internal/keychain` applies the same rule to `key.enc` (and its temp file, before any key bytes are written) and to the unlock cache.

## Grants: `grants.enc`

Metadata only; losing it loses permissions, never secrets. Stored in the same AEAD envelope as `vault.enc` (own nonce, `format: "qbit-vault-grants/1"` in the header), encrypted with the same master key, so a leaked copy does not reveal which secrets exist, which sessions used them or which repositories they belong to. Decrypted plaintext:

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
  ],
  "cooldowns": [
    { "name": "AWS_SECRET_ACCESS_KEY", "session": "pi:2f1c…", "until": "…" }
  ]
}
```

`session` is empty and `expires_at` null for `project` scope. Timestamps are RFC 3339 UTC.

**File.** `grants.enc` is managed by `internal/vault` under the same `vault.lock` as `vault.enc`; the vault never interprets the body (`internal/grants` does). The envelope is the one of `vault.enc` (`internal/envelope`) with `format: "qbit-vault-grants/1"` in the header and in the AAD, so a `vault.enc` can never be opened as grants or the reverse. It has its own write counter, `grants_writes`, in `state.json` (unknown keys of `state.json` are preserved). A grants write seals the next body with `writes` = counter + 1, replaces `grants.enc` atomically (temp file, `fsync`, rename, owner-only like the other files), then records the counter in `state.json`. There are **no snapshots** of `grants.enc`: losing it loses permissions, never secrets, and restoring an old copy would revive revoked grants.

**Fail closed (L3).** A `grants.enc` that is missing is an empty store. One that cannot be trusted (malformed, altered, wrong key or wrong format) or whose `writes` is **behind** `grants_writes` (a rollback that would revive revoked grants) is also treated as an empty store, and the operation reports a `reset` to the CLI, which prints `warning: grants were reset (store unreadable or rolled back)` on stderr and appends an audit `warning` record with `detail: "grants reset"`. The next grants write replaces the bad file (`grants` and `describe` do it on first read). One that is **ahead** of the counter (a crash between the two writes, or a counter missing from `state.json`) is accepted and the counter repaired. The counter is not authenticated (THREAT_MODEL R8).

**Cooldowns.** `cooldowns` holds the names a session may not request again yet: a `request` the user denied, cancelled or let time out starts a 60 s cooldown for that `(name, session)` (R-CAP-05), purged when it ends. They live here because a broker call is a fresh process; like grants, losing them only lifts a restriction early.

**Tokens.** `tokens` holds the pending prompt tokens (see below): only the SHA-256 of a random 32-byte value, never the value. They expire after 2 minutes, are removed when redeemed (also when presented for the wrong request) and purged with expired grants.

`layer` is `global` or `project:<root>` and records **which record** the user granted. Evaluation for `exec(name, session, cwd)`:

1. Expired grants are purged on load.
2. Resolve `name` for `cwd` (§ Layers) to a record and its layer. Unknown → `unknown_secret`.
3. Only grants whose `name`, `layer` **and `record_id`** match the resolved record are considered. A grant on the global `DATABASE_URL` never injects the project `DATABASE_URL`, and the reverse.
4. `once`: matching `session`, not consumed → allow and mark consumed.
5. `session`: matching `session` → allow.
6. `project`: `cwd` inside `project_root` → allow.
7. Otherwise `grant_required`.

Drop rules, all inside the same locked operation as the vault change (vault first, then grants): `rm`, `mv` and a value replacement (`set` over an existing record) drop the grants of that `(name, layer)`; `mv` drops those of both layers (an overwritten target's grants belonged to a value that is gone); **`relink` drops every grant of the old project layer and carries none to the new root** (the user grants again; relink can only narrow access); **`edit --sensitive` drops the record's `session` and `project` grants and keeps its `once` grants**. Other metadata edits keep their grants. A crash or failure between the vault write and the grants write can leave grants for a record that is gone. They are inert: a grant stores the `record_id` of the record it was granted for, and a re-created or value-replaced secret with the same name and layer has a new id, so the stale grant never matches it (evaluation says `grant_required`). The drop is cleanup, not what keeps the stale grant from authorizing the new record. A grant with no `record_id`, or a check with an empty id, matches nothing. As defence in depth, evaluation is also told whether the record is `sensitive` and then matches `once` grants only.

**Scope rules** (`internal/grants`). `once` and `session` need a host session; `project` needs a project record, stores `project_root` and no session, and never expires. A `sensitive` record accepts `once` only; `project` scope on a global record is refused with the message `project scope needs a project secret` (still `scope_not_allowed`). `session` lives 30 minutes by default (`--ttl` 1 minute to 24 hours); an unused `once` grant expires after 10 minutes and is consumed by the first matching check. Adding a grant replaces an identical `(name, layer, session, scope)` grant. A `project` grant also requires `cwd` to be inside `project_root`, on path boundaries (`/work/shop` does not cover `/work/shop-old`).

`prompt_token_hash` records which prompt created the grant (the broker issues a one-time random token to its own prompt backend, and `grant` must present it; the hash is stored for audit). This is the mechanism behind "grants are user-UI-only". A token is 32 random bytes in base64url, bound to one `(names, layer, scope, session, ttl)`, where `names` is the sorted list of the fields of one prompt (one name for a single-field request; a multi-field token is redeemed for all its names at once by `set --stdin --fields`, all-or-nothing, and creates one grant per record), and, when issued for an existing record, to its `record_id` (a token issued for a value that does not exist yet, as with `set --grant`, binds name, layer, scope, session and ttl only), where an omitted ttl is the scope's default (30 minutes for `session`) so it is part of the binding, valid for 2 minutes and for one use; an unknown, expired, reused or mismatched token (a token presented for a different request, TTL included, is burnt) is refused as `not_model_callable`. `qbit-vault prompt` is the issuer (slice 1.9, terminal backend; native dialogs in 1.10); `set --grant` interactive issues and redeems one in a single step, so its grant is audited as `prompt token` too. The CLI confirms a grant either with such a token (`--from-prompt-token`) or with a y/N answer on the **controlling terminal** (`/dev/tty`, `CONIN$`; never stdin).

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

Events: `init`, `capture`, `grant`, `exec`, `manage`, `refusal`, `revoke`, `rm`, `mv`, `edit`, `relink`, `link`, `rekey`, `restore`, `uninstall`, `warning`, `prompt`, `remote`. An unknown event is refused when appending. `remote` records carry `detail` `registered`, `joined (pairing)`, `joined (recovery)`, `approved <device>`, `revoked <device>`, `recovery key rotated`, `conflict resolved`, `restored version N` or `logged out`, and never a code, a key or a server token; a sync round itself is not audited (it is not a user decision), except an applied conflict, which adds a `warning` (`detail: "sync conflict"`, names, layer).

**Fields.** In this order: `ts` (RFC 3339, nanoseconds, UTC), `seq` (1-based), `prev`, `event`, `session`, then the optional `host` (`{name, version}`), `names`, `layer` (`global` or `project:<root>`), `by`, `reason`, `cwd`, `refusal` (the refusal type), `scope`, `expires_at`, `command`, `exit_code`, `duration_ms`, `redactions`, `outcome`, `detail`, and finally `hash`. Optional fields are omitted when empty. The API takes secret **names** only; a name that does not match the secret-name rule is dropped (never written raw) and the record gets `detail: "invalid name"`.

**Chain.** `prev` is `sha256:` plus the hex SHA-256 of the previous line's raw bytes, without the newline; the first record's `prev` is `sha256:` plus 64 zeros. `hash` is `sha256:` plus the hex SHA-256 of the record's canonical JSON (fields in the order above) encoded with `"hash":""`, that is, with the hash value empty, not with the field removed. Editing a line breaks its own `hash`; deleting, inserting or reordering lines breaks the next `prev`.

**Anchor.** After each append, `audit.head` (`{"seq":N,"hash":"sha256:…","line":"sha256:…"}`) is replaced atomically (temp file, fsync, rename). `hash` is the `hash` field of record N; `line` is the SHA-256 of record N's raw line, which is exactly the `prev` the next record needs. Without the anchor, deleting the tail of the log would leave a chain that still verifies. If the log is missing or empty while the anchor has `seq` > 0, the next append does **not** restart at genesis: it continues with `seq` = anchor `seq` + 1 and `prev` = the anchor's `line`, so a deleted log stays visible. The same applies when the log is shorter than the anchor (its tail was removed): the next append continues from the anchor, not from the surviving last line, and the gap shows up as `bad_prev`. `--verify` reports `truncated` at line 1 for a missing or empty log with such an anchor, and for a log whose first record has `seq` ≠ 1 (the log starts after genesis). It also reports `truncated` when the log ends before the anchor and `head_mismatch` when the anchor does not match the record it names (`hash` and `line`), or is missing a field or unreadable; an anchor one record behind the log (a crash between the two writes) is fine, and a missing `audit.head` next to an existing log is valid. The anchor catches accidental truncation and naive deletion, not an attacker who rewrites both files (THREAT_MODEL R8).

**Appending.** Appends from any process serialize on `audit.lock` (the same lock-file mechanism as `vault.lock`, bounded wait, stale break). The writer reads the last line from the end of the file (a 64 KiB window), writes one line with `O_APPEND`, fsyncs, then writes the anchor. If the last line is malformed (partial, not JSON, longer than the window) the writer does not guess from it: it ends the partial line with a newline, sets `prev` to the hash of those raw bytes and `seq` to the anchor's `seq` plus one (without a readable anchor, the number of lines plus one), so `--verify` still reports the damage.

**Verify.** `qbit-vault audit --verify` walks every line and reports the first problem as `{line, seq, reason}`, with `reason` one of `bad_json`, `bad_hash` (the line is not exactly the canonical encoding of its fields, or its `hash` is wrong), `bad_prev`, `bad_seq`, `partial_line` (the last line lacks its newline), `truncated`, `head_mismatch`. A missing log and a missing anchor are valid with 0 records.

**Who writes.** The CLI writes `init` (`detail` = keychain mode, only when a vault is created), `capture` (`set`: names, layer, `detail: "replaced"` when replacing a value, `reason: "manual entry"` for an interactive capture), `prompt` (`qbit-vault prompt`: names, `layer`, `scope` when a token was issued, `outcome` `issued`, `denied` or `cancelled` including a timeout; best effort; never the value, the token or the requester's reason), `rm`, `edit`, `mv` (layer = destination, `detail: "global->project"` or `"project->global"`), `relink` (`cwd`) and one `refusal` record (type, and the secret name when it is valid) for every typed refusal a command returns. `session` is `--session` or `cli`; `by` is `user`. A record never holds a value, a description, a binary list or command arguments. `grant` (names, layer, `scope`, `expires_at` when the grant expires, `detail` `terminal` or `prompt token`, `session` = the host session) and `revoke` (names when revoking by name, `layer` when a layer was named, `detail` `name|all|session revoked=N`) are written by `grant`, `set --grant` and `revoke`; a `warning` with `detail: "grants reset"` is written when `grants.enc` is reset. **`exec` (fail-closed, two phases).** `exec` appends a record with `outcome: "started"` (names, `layer` when every secret shares one, `cwd`, `command` redacted and cut to 2048 bytes, `detail: "hosts warning"` when a host advisory fired) before the child starts, inside the grants lock that consumes `once` grants; if the append fails nothing runs and nothing is consumed (refusal `internal`). After the child ends it appends `outcome: "finished"` with `exit_code`, `duration_ms`, `redactions` and `detail` `timeout` or `interrupted` when applicable (`outcome: "error"` when the runner failed); this one is best effort (stderr warning on failure). Exec records carry no `by`. Values shorter than 8 bytes add a `warning` record per name (`detail: "short value"`). `manage` records arrive with their slice.

**Best effort (CLI).** The vault change is already committed when its record is written, so a failed append prints `warning: audit log write failed` to stderr and leaves the exit code and stdout alone. A home directory that does not exist has no audit log and is skipped silently. `revoke` is best effort too (it only narrows access). **`grant` is fail-closed (L4):** its `grant` record is appended before the grant is persisted, and if the append fails the grant is not created (refusal `internal`). **`exec` is fail-closed for its `started` record** and best effort for its `finished` one (L2).

`qbit-vault audit --tail 50`, `--since 24h`, `--name X`, `--event E`, `--json` for the Gentle Shell widget; the log is read under `audit.lock`, so a reader never sees a half-written line, and it works without unlocking the vault.

The command text is passed through the redactor before being logged (a command that embeds a literal value, which should not happen, still never reaches the log).

## What a leaked directory reveals

If someone copies the whole `$QBIT_VAULT_HOME` (a stolen backup, a synced folder, a misconfigured share) but not the master key:

| File | Readable without the key | Contents an attacker learns |
| --- | --- | --- |
| `vault.enc`, `backups/**/vault.enc` | no (AEAD) | format, creation time, write counter |
| `grants.enc` | no (AEAD) | format, write counter |
| `key.enc` (passphrase mode) | only by brute-forcing the passphrase through Argon2id (64 MiB per guess) | the master key, if the passphrase is weak |
| `audit.jsonl` | yes | secret **names**, layers, sessions, redacted commands, timestamps. Never values. |
| `audit.head` | yes | the sequence number and hash of the newest audit record. No names, no values. |
| `state.json`, `config.yaml`, `bindings.yaml`, `dumpguard.yaml` | yes | installed hosts, versions, settings, device id and, with sync, server URL, account id, generation and version. No names, no values. |
| `remote/device.enc`, `remote/base.enc`, `keys/retired.enc` | no (AEAD) | format, write counter |

In keychain mode the key never sits in the directory; it lives in the OS keychain, unlocked only by the user's login session. The audit log stays cleartext on purpose: it is append-only and must be verifiable (`audit --verify`) even when the vault is locked or corrupt. Hiding names in the audit log too (keyed hashes) is a v2 candidate, see `ROADMAP.md`.

## `state.json`

```json
{
  "format": "qbit-vault-state/1",
  "vault_id": "uuid", "writes": 42, "keychain": "secret-service",
  "version": "0.1.0",
  "hosts": {
    "claude-code": {
      "registered_at": "2026-10-16T08:15:00Z",
      "registered": ["mcp", "hooks"],
      "receipts": {
        "mcp": { "path": "/home/ana/.claude/settings.json", "snapshot": { "path": "/home/ana/.claude/settings.json", "existed": true, "backup": "/home/ana/.qbit-vault/backups/20261016T081500.000000000Z/home/ana/.claude/settings.json" }, "sha256": "…", "created": false, "exact": true },
        "hooks": { "path": "/home/ana/.claude/settings.json", "snapshot": { "…": "…" }, "sha256": "…", "created": false, "exact": false }
      }
    },
    "gentle-shell": { "extension": "qbit-vault-pi@0.1.0", "home": "~/.gentle-shell/agent" }
  }
}
```

**`hosts`** maps a host name (`[a-z0-9-]`, at most 32 characters) to its record: `registered_at` (first registration), `registered` (the step names that have a receipt, in adapter order) and `receipts`, one per **step** of the host adapter, keyed by the stable step name (`mcp`, `hooks`, `deny-list`, …; `internal/hosts`). `init` saves a host's record after every step that changed a receipt, so a failing step leaves the earlier steps recorded; a run that changes nothing does not write `state.json` at all. The section is read and written by `internal/vault` (`ReadHosts`, `WriteHost`) under the vault lock, like `remote`, and every other key of `state.json` is carried through untouched. A record holding a relative path is refused before anything is written; a `hosts` value that is not an object of records is `vault_corrupt`. Per-host extras such as the Pi extension version arrive with their adapter.

Receipts are what `sync` re-applies, `doctor` compares and `uninstall` reverts; `uninstall` deletes a host's record only after its revert succeeded, and `uninstall --purge` removes the whole vault home, including this file, and the key's keychain entry. A receipt is the `internal/filemerge` `Receipt` of one edited file: absolute paths only (no `~`, Windows-portable), the snapshot handle taken before the change, the SHA-256 of the bytes written, `created` (the file did not exist before) and `exact` (the snapshot is the state immediately before our only change); `original` (the snapshot handle of the file before our first change, unchanged by re-applies; absent in receipts written before it existed, which then revert without pruning containers we emptied); `ARCHITECTURE.md` § Config file editing gives the revert rule. With remote sync, `state.json` also holds `device_id` and `remote` (`REMOTE_SYNC.md` § 11); `remote` is absent when the vault does not sync.

## Remote files

Only present once the vault syncs. Both use the `vault.enc` envelope with their own `format` and write counter in `state.json`, sealed with the master key, written under `vault.lock` with the atomic-write steps above, owner-only like the other files, and never snapshotted (they are rebuilt from the server).

| File | `format` | Content |
| --- | --- | --- |
| `remote/device.enc` | `qbit-vault-device/1` | this device's 32-byte secret `DK` (`REMOTE_SYNC.md` § 2) |
| `remote/base.enc` | `qbit-vault-base/1` | the body of the last remote version this device agreed with, the base of the three-way merge |

A missing or unreadable `base.enc` makes the next round merge with an empty base: nothing is lost, and keys changed on both sides become conflicts. A missing `device.enc` turns sync off with `remote_auth` until `remote join` runs again.

## Retired keys

`keys/retired.enc` (`format: "qbit-vault-retired/1"`, sealed with the current master key, written atomically like the other files) lists the master keys this vault used before, newest first: `{"keys":[{"generation":"local"|"<n>","key":"<base64>","retired_at":"…"}]}`, at most 20 entries (the oldest is dropped; backups are pruned to 20 saves by default, so an older key rarely opens anything). A file that cannot be opened is treated as empty: it only means no older key to try. `rekey`, a revocation and joining an account with a non-empty local vault add the key they replace, so `restore` can still open a backup made under an older key, and `audit --verify` can read anchors sealed under one. Entries are pruned with the backups that need them. A retired key is no weaker than the backups it opens: whoever holds the current key can already read them.
