# Feature: roadmap Phase 2S, remote sync

Multi-device zero-knowledge sync through a self-hosted `gentle-vault-server` (docs/REMOTE_SYNC.md).
This document tracks the slices S.1-S.10 of docs/ROADMAP.md § Phase 2S. Branch `feat/cli-skeleton`.

## Specs

- S1. User (spec L1, odd/tasks/remote-sync-spec.md): "un vault simple pero robusto ... que funcione con una base de datos encriptada local y en la nube"; L2: "el objetivo es poder usarlo en varias maquinas y tambien podria usarse como backup para sync"; L3: "Servidor propio de gentle-vault".
- S2. ROADMAP S.1: "Body schema 2 and migration: project ids, per-device `roots`, `device_id`, `kind`, `hlc`, tombstones; `link`; `list --layer all` marks unlinked layers; `keys/retired.enc` with `rekey`/`restore`" (R-SYNC-11, STORAGE).
- S3. STORAGE.md § Plaintext body, **Schema 2** and **Device id** paragraphs (verbatim authority), § Layers resolution: "find the project whose `roots[<this device>]` equals that root ... A project layer with no root for this device ... is invisible until the user runs `gentle-vault link`".
- S4. CLI.md `link LABEL [DIR]` row; REMOTE_SYNC.md § 7.3 (hlc format and merge keys) and § 7.5 (origin normalization, hint, user-only link).
- S5. ROADMAP S.2-S.10 rows (merge engine, crypto, server, packaging, client commands, rounds, revoke/rekey, e2e).
- S6. AGENTS.md invariants 1, 2, 7, 8, 9.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S2, S3, S6 | inline | S.1a: body schema 2 codec and migration, `device_id`, origin, hlc and tombstones stamped on save, newer schema refused | fc7ebeb | done |
| T2 | S2-S4 | inline | S.1b: `link`, unlinked layers in `list --layer all`, origin hint, broker `unlinked_match` | 0cab11d | done |
| T3 | S5 | inline | S.2 merge engine | db370d8 | done |
| T4 | S5 | inline | S.3 remote crypto | ea50f5f | done |
| T5 | S5 | inline | S.4 server core, S.5 pairing, recovery, rekey, anchors | fdca3e7 (S.4), 4c3f05e | done |
| T6 | S5 | inline | S.6 packaging: `gentle-vault-server` serve/invite/health, Dockerfile, compose | (S.6 commit) | done |
| T7 | S5 | inline | S.7-S.9 client | | pending |
| T8 | S5 | inline | S.10 e2e | | pending |

## Log

- L1. User chose "Phase 2S: sync entre máquinas" after Phase 2 (2026-11-04).
- L2. Decision (T1): the in-memory body keeps project layers keyed by this device's root, so resolution, grants and relink code stay as they are; the codec maps schema 2 (projects by id, `roots` per device) to it and keeps projects without a root for this device aside as unlinked. Every save compares the body before and after the mutation: a record whose content changed gets a fresh hlc, a record that disappeared leaves a tombstone. No command has to stamp anything.
- L3. Decision (T1): `device_id` is created by `init`, or on the first load of a vault that has none, and saved to `state.json` with the counter repair. Tombstones older than 180 days are purged on save. The hlc is `<unix_ms>.<counter>@<device_id>`, never lower than the highest one in the body.
- L4. T1 notes: RED observed (build). The codec lives in internal/vault/body2.go; `restore` writes a backup body as stored and it migrates on the next load. `relink` keeps the project id. `ListAll` reports unlinked layers with an empty root and `Unlinked: true`.
- L5. T2 notes: RED observed for vault and CLI. `link` errors are fixed strings (the label is user text and never echoed). The hint is printed by a human `list` only; `--json` never prints it, the broker reports `unlinked_match` instead. `vault.AddUnlinkedForTesting` is a test seam like `SetWalkStopForTesting`.
- L6. T3 notes: RED observed (build). `internal/merge` is pure over schema-2 bodies; records are opaque except `hlc`. Every case of REMOTE_SYNC § 7.3 has a test; FuzzMerge (1.47M executions, 30 s) checks that no change that differs from the base on either side is lost and that the result is deterministic. Conflict ids are a hash of key and losing clock, so the same conflict seen on two devices dedupes.
- L7. T4 notes: RED observed (build). Standard library only (crypto/hkdf, ed25519, ecdh X25519) plus x/crypto XChaCha20-Poly1305. The fixed vector was checked against an independent HKDF (Python, RFC 5869). The anchor AAD drops `generation`: the anchor key is derived from the master key, so a new generation already changes it. FuzzOpen: mutated objects never open, never panic.
- L8. T5 S.4 notes: RED observed (build). Standard library net/http with Go 1.22 method patterns; the log line uses `r.Pattern` so it never holds a path value. Tokens and challenges live in memory (a restart ends sessions). The server cannot open a vault version but checks its cleartext AAD (`account_id`, `generation`, `version = base + 1`) so a client bug cannot store a mislabelled version.
- L9. T5 S.5 notes: RED observed. The server checks that a pairing code fingerprints the keys it carries (`remote.PairingCode`), so a pairing can only carry the keys its code names; a poll answers `approved` once. A recovery token reads only the recovery envelope and registers one device. `rekey` is one transaction: new version under generation+1, one envelope per remaining device (exactly), new recovery envelope (the old lookup stops working), revoked devices unindexed and their tokens dropped; a device cannot revoke itself.
- L10. T6 notes: RED observed for the server commands. Validated with Docker 29.9.2: `buildx build --check` without warnings, image 16.8 MB, user 65532, `--read-only` container healthy, invite stored, bad `--ttl` exits 2, SIGTERM stops with 0; `compose up` with the named volume healthy. The validation found a real bug, fixed: the `/data` volume was created root-owned, so the non-root server could not write; `/data` is now created in the build stage and copied with owner 65532. Release jobs (goreleaser, GHCR push) are not part of this slice: there is no remote yet.
