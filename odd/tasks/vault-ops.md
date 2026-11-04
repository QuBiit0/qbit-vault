# Feature: roadmap slice 1.11, import, rekey, lock/unlock, restore

Vault maintenance commands: explicit import from the environment or a dotenv file, master key
rotation that survives a crash, passphrase-cache lock/unlock, and restore from encrypted
backups (also those made under an earlier key). Branch `feat/cli-skeleton`.

## Specs

- S1. ROADMAP 1.11: "`import --from-env/--from-file`, `rekey`, `lock/unlock`, `restore`" (R-VAULT-08).
- S2. CLI.md: "`import --from-env NAME[,NAME…]` / `import --from-file PATH [--names A,B]` | Explicit, user-run import from the current environment or a dotenv file. Never run by `init`. Prints what it imported by name and offers to unset/remove the source."
- S3. CLI.md: "`rekey` | Rotate the master key." STORAGE.md: "`gentle-vault rekey` rotates the master key: decrypt, generate new key, encrypt, swap, and update keychain/key.enc atomically with a backup of the old envelope, and add the old key to `keys/retired.enc` (§ Retired keys)."
- S4. CLI.md: "`lock` / `unlock` | Passphrase mode: drop / refresh the cached master key." STORAGE.md: "`gentle-vault lock` deletes the file."
- S5. CLI.md: "`restore [--list] [--from TS]` | Restore the vault from an encrypted backup. Backups made under an earlier master key are opened with `keys/retired.enc`." STORAGE.md: "`gentle-vault restore --from <ts>` swaps a backup back in (with its own backup of the current state first)." CONTRACT `vault_corrupt`: "Point to `gentle-vault restore`".
- S6. STORAGE.md § Retired keys: "`keys/retired.enc` (`format: "gentle-vault-retired/1"`, sealed with the current master key) lists the master keys this vault used before ... so `restore` can still open a backup made under an older key."
- S7. AGENTS.md invariants 1, 2, 3, 6, 7: no value in any output; no plaintext on disk; init never imports; every capture is an explicit user action; every mutation snapshotted and atomic.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S4 | inline | `lock`, `unlock` (keychain `Refresh`, CLI, docs) | b7ff436 | done |
| T2 | S5, S6 | inline | retired keys store; `restore --list/--from`; resumable `vault.Rekey` (vault + CLI, docs) | 3a1e772 | done |
| T3 | S3, S6, S7 | inline | crash-safe `rekey`: staged key, promote, recovery on open (keychain + CLI, docs) | 90e50b4 | done |
| T4 | S2, S7 | inline | `import --from-env/--from-file` (dotenv parser + fuzz, one atomic write, CLI, docs) | next commit | in progress |

## Log

- L1. User: "si arranca con todo" (start slice 1.11 and continue the roadmap).
- L2. Decision (lock/unlock): `lock` in keychain mode succeeds with `locked: false` and says there is nothing to lock; in passphrase mode it deletes the cache. `unlock` always asks the passphrase (it refreshes, so it skips the cache), verifies it and caches the key where a cache exists; where none exists it reports that the passphrase is asked on each use. In keychain mode it only checks that the key opens the vault. Neither writes an audit record (not a vault decision).
- L3. Decision (restore): `--list` needs no key. `--from ID` validates ID against the snapshot-name pattern, asks `Restore the vault from ID? The current vault is backed up first. [y/N]` unless `--yes`, opens the snapshot's `vault.enc` with the current key or a retired one, and saves its body as the next write under the current key, so the rollback counter moves forward instead of tripping `vault_corrupt`, and the current pair is snapshotted first. It works when the current vault is corrupt or rolled back (the case `vault_corrupt` points to); when `state.json` is unreadable it takes the snapshot's. Grants are kept: they bind record ids, and a restored record keeps its id.
- L4. Decision (rekey): crash-safe in three phases. (1) Stage the new key: keychain account `master:next:<id>`, or `key.next.enc` wrapped with the same passphrase (asked and verified against `key.enc` first, so a typo cannot strand the key). (2) Finish, idempotent, under the vault lock: re-seal `vault.enc` (snapshot), `grants.enc` and `keys/retired.enc` with the new key, adding the old key to retired; each file is opened with the new key first, else the old one. (3) Promote the staged key over the main entry, refresh the unlock cache, delete the staged entry. `openSession` finishes an interrupted rekey whenever a staged key exists. Changing the passphrase is not part of rekey.
- L5. Decision (import): needs a confirmation through the prompt backend (`Import A, B from <source> into <layer>? Existing secrets with these names are replaced.`) unless `--yes`; inside a repository without `--global`/`--project` it asks the layer, or with no prompt backend is the usage error `choose --global or --project`. All names are stored in one locked write; replaced records drop their grants. Dotenv: `KEY=VALUE`, optional `export `, `#` comments, single quotes literal, double quotes with `\n \" \\` escapes and spanning lines, unquoted values trimmed with a ` #` comment stripped; invalid names are skipped and counted, never echoed; a missing `--names` entry is a usage error naming it. `--remove-source` deletes the file afterwards; interactively the user is asked. For `--from-env` a hint to unset the variables goes to stderr. Audit `capture` with `reason: "import from env|file"`.
- L6. Change to L4: recovery runs only when the main key cannot open the vault (and the vault is not rolled back) and a staged key exists, so no command pays an extra keychain read. A staged key left by a crash before re-sealing protects nothing and the next `rekey` overwrites it. `vault.Rekey` landed with T2 (it is what retires keys); T3 added staging, promotion and recovery.
- L7. Change to L5: `getenv` cannot tell an unset variable from an empty one, so both are `NAME is not set or empty in the environment`. A listed name twice is `NAME is listed twice`.
- L8. Process note: in `internal/vault` (restore, retired keys, Rekey) the code was written before its tests ran, so no RED was observed there; every CLI command and the keychain staging had an observed RED.
- L9. Independent verify (gentle-ai-verify): S1-S7 PASS, no blocker. Four warnings fixed with a RED test each: W1 `Promote` drops the unlock cache before renaming, so a stale old key is never trusted; W2 `unlock` and `restore` finish an interrupted rekey first (`openRecovering`), so restore never seals under the old key; W3 `rekeyRetired` returns read errors instead of overwriting the retired list; W4 `vault.Rekey` marks refusals before any write with `ErrRekeyNotStarted`, and only those unstage the key. Notes N1-N6 left as is (outside the threat model or same class as accepted residuals).
