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
| T1 | S2, S3, S6 | inline | S.1a: body schema 2 codec and migration, `device_id`, origin, hlc and tombstones stamped on save, newer schema refused | (S.1a commit) | done |
| T2 | S2-S4 | inline | S.1b: `link`, unlinked layers in `list --layer all`, origin hint, broker `unlinked_match` | | pending |
| T3 | S5 | inline | S.2 merge engine | | pending |
| T4 | S5 | inline | S.3 remote crypto | | pending |
| T5 | S5 | inline | S.4-S.5 server | | pending |
| T6 | S5 | inline | S.6 packaging | | pending |
| T7 | S5 | inline | S.7-S.9 client | | pending |
| T8 | S5 | inline | S.10 e2e | | pending |

## Log

- L1. User chose "Phase 2S: sync entre máquinas" after Phase 2 (2026-11-04).
- L2. Decision (T1): the in-memory body keeps project layers keyed by this device's root, so resolution, grants and relink code stay as they are; the codec maps schema 2 (projects by id, `roots` per device) to it and keeps projects without a root for this device aside as unlinked. Every save compares the body before and after the mutation: a record whose content changed gets a fresh hlc, a record that disappeared leaves a tombstone. No command has to stamp anything.
- L3. Decision (T1): `device_id` is created by `init`, or on the first load of a vault that has none, and saved to `state.json` with the counter repair. Tombstones older than 180 days are purged on save. The hlc is `<unix_ms>.<counter>@<device_id>`, never lower than the highest one in the body.
- L4. T1 notes: RED observed (build). The codec lives in internal/vault/body2.go; `restore` writes a backup body as stored and it migrates on the next load. `relink` keeps the project id. `ListAll` reports unlinked layers with an empty root and `Unlinked: true`.
