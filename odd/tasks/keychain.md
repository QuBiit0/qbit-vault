# Feature: roadmap slice 1.3, master key in the OS keychain with passphrase fallback

`internal/keychain`: store and fetch the 32-byte master key in the OS keychain (go-keyring),
fall back to an Argon2id-wrapped `key.enc` when no keychain is reachable, and cache an unlocked
passphrase key only in memory-backed storage. Also closes the slice 1.2 follow-up that the vault
header fields outside `aad` are not authenticated. Branch `feat/cli-skeleton` (stacked).

## Specs

- S1. ROADMAP 1.3: "`keychain`: go-keyring backend + passphrase/Argon2id fallback + cached unlock" (R-VAULT-02).
- S2. R-VAULT-02: "The master key MUST be stored in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). When no keychain is available, the key MUST be wrapped with a user passphrase using Argon2id and stored at `$GENTLE_VAULT_HOME/key.enc`."
- S3. STORAGE.md § Master key: "32 bytes from `crypto/rand`." "stored via `go-keyring` under service `gentle-vault`, account `master:<vault-id>`" "`key.enc` = `{ kdf, nonce, ct }` where `ct` = XChaCha20-Poly1305(derived_key, master_key). `derived_key` = Argon2id(passphrase, salt, t=3, m=64 MiB, p=4, 32 bytes)." "`gentle-vault lock` deletes it."
- S4. AGENTS.md invariant 2: "No secret value ever touches disk unencrypted." Invariant 1: errors mention names only.
- S5. Slice 1.2 verify follow-up: "`kdf` and `cipher` are not in the AAD ... This must be revisited when slice 1.3 adds the KDF parameters."

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S5 | worker | `internal/vault`: drop `kdf` from vault.enc, authenticate `cipher` in `aad`, `Init` takes a caller-supplied vault id | e2cddb6 | done |
| T2 | S1-S4 | worker | `internal/keychain`: OS backend, passphrase backend with `key.enc`, memory-backed unlock cache, setup/unlock/lock | acd9f0b, fix in next commit | done |

## Log

- L1. User: "ok" (to continuing with slice 1.3 after the slice 1.2 report).
- L2. Decision: `vault.enc` no longer carries `kdf` (key.enc is the only place that describes key wrapping, and binds its own parameters as AAD). `cipher` moves into the authenticated `aad` object.
- L3. Decision (spec change to STORAGE.md § Master key): the unlocked passphrase key is cached only in a memory-backed runtime directory (`$XDG_RUNTIME_DIR/gentle-vault/`, tmpfs on Linux). Where none exists (Windows, macOS, Linux without XDG_RUNTIME_DIR) there is no cache and the passphrase is asked on each unlock. Reason: AGENTS.md invariant 2; Windows and macOS always have an OS keychain, so passphrase mode there is rare.
- L4. Decision: mode is implied by the files: `key.enc` present means passphrase mode, otherwise OS keychain. No extra state field.
- L5. Independent verify: S1-S5 pass, no blockers. Fixed: relative `XDG_RUNTIME_DIR` was accepted as the cache dir (key would land on ordinary disk); OS probe now deletes its throwaway entry when Set errors. Follow-ups: Argon2 ceiling 1 GiB could be lowered; Setup writes the key before `vault.Init`, so the CLI slice (1.4) must remove an orphan key if Init fails.
