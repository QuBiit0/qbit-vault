# Feature: roadmap slice 1.2, encrypted vault core with layers

`internal/vault`: AEAD envelope, atomic writes, backups, rollback counter, and the
global/project layered body with name resolution. Plus the review follow-up from slice 1.1:
usage errors must not echo user input. Branch `feat/cli-skeleton` (stacked on slice 1.1).

## Specs

- S1. ROADMAP 1.2: "`vault`: envelope, XChaCha20-Poly1305, atomic write, backups, rollback counter; `global`/`projects` body and name resolution" (R-VAULT-01,04,07,09, R-LAYER-01..03).
- S2. STORAGE.md § Vault file: "A JSON envelope with a cleartext header and one AEAD-encrypted body. The header is authenticated as additional data, so it cannot be altered without detection." "A fresh 24-byte nonce is generated for every write." "`aad.writes` is a monotonically increasing counter, also stored in `state.json`; a vault file with a lower counter than `state.json` is treated as a rollback and `vault_corrupt` is raised until the user runs `restore`."
- S3. STORAGE.md § Layers: "**Resolution** of `NAME` for a `cwd`: find the repository root of `cwd` ...; if `projects[root].secrets[NAME]` exists use it, else `global[NAME]`, else `unknown_secret`."
- S4. STORAGE.md § Atomic writes and backups: "1. Copy current file to `backups/<RFC3339-compact>/<filename>` ... 2. Write new content to `<filename>.tmp.<pid>` in the same directory, `fsync`. 3. `rename` over the target ... 4. `fsync` the directory on POSIX." "Backups are pruned to the last 20 by default".
- S5. R-VAULT-05: "Secret names MUST match `^[A-Z][A-Z0-9_]{0,63}$`". R-VAULT-07: "The vault MUST never store the value in any derived or cached form outside the encrypted file".
- S6. AGENTS.md invariants 1 and 2: errors mention the secret name only; no secret value touches disk unencrypted.
- S8. Verify findings (medium): "Windows rename fails if any other handle has the target open" (`atomic.go:188`, doc promises MoveFileEx flags the code does not set); "There is no cross-process lock" (`vault.go:25`, two processes can silently lose an update; two handles share one `.tmp.<pid>` name). Low: repair write creates a state-only snapshot that counts toward keep; failed saves consume snapshot slots; backup dir names can collide on coarse Windows clocks.
- S7. Slice 1.1 review follow-up (WARNING, risk + reliability): "usage-error-echoes-args" at `internal/cli/cli.go:100-102`.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1, S2, S4, S6 | worker | `internal/vault` envelope, atomic write, backups, state counter | 49280a9 | done |
| T2 | S1, S3, S5, S6 | worker | `internal/vault` layered body, records, resolve, put/remove/move/list, project root | 9126998 | done |
| T4 | S8 | worker | `internal/vault`: cross-process lock, Windows rename retry, snapshot hygiene | this commit (fix(vault)) | done |
| T3 | S7 | worker | `internal/cli`: usage errors without echoed input | next commit (fix(cli)) | done |

## Log

- L1. User: "asi como esta planteado ahora seria como el vault definitivo para los agentes? raíz del proyecto. Continua"
- L2. Decision: project root = nearest ancestor of `cwd` containing a `.git` entry (directory or worktree file), canonicalized (absolute, symlinks resolved, case-folded on Windows/macOS). No `git` subprocess in v1 core; equivalent to `git rev-parse --show-toplevel` for normal and linked worktrees.
- L3. Decision: file permissions/ACL enforcement stays in slice 1.4 as planned; 1.2 creates files 0600 / dirs 0700 on POSIX only.
- L4. Worker result: all checks green (gofmt, vet, build, test, FuzzEnvelope 10s ~1.6M execs, leakgrep over -v output). `go` directive moved to 1.26.0 because golang.org/x/crypto v0.58.0 requires it. Missing state.json next to an existing vault.enc is ErrCorrupt (deleting state must not bypass rollback detection). ErrInvalidName does not echo the rejected name. Symlink test skipped on this Windows machine (no symlink privilege).
- L5. Correction: backups are one snapshot directory per save holding the consistent (vault.enc, state.json) pair; keep=20 means the last 20 saves.
- L6. T4 done: `vault.lock` (O_EXCL, 5s bounded retry, 30s stale break) around every operation; unique temp names + leftover cleanup; Windows rename retry on transient errors (~2s); repair write without snapshot; failed save removes its snapshot unless vault.enc was already replaced (then it is the only copy of the previous pair). Follow-up for slice 2.1: map `ErrLocked` to a typed contract refusal (`vault_locked` means keychain unavailable, so a new retryable `vault_busy` or `internal` retryable needs a contract decision).
