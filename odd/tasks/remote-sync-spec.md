# Feature: spec change for remote sync and multi-field requests

Spec-only change (no code): adds zero-knowledge self-hosted multi-device sync (`gentle-vault-server`),
multi-field typed capture in `request`, and an audit head anchored on the sync server. Lands as one
docs commit on `feat/cli-skeleton` before Phase 2 code freezes the contract.

## Specs

- S1. Product goal (L1): "un vault simple pero robusto que permita al agente de codigo solicitar secretos y credenciales cuando las necesite, sin exponerlas o enviarlas por internet en texto plano. la idea de esto es que funcione con una base de datos encriptada local y en la nube."
- S2. Capture (L1): "cuando el agente necesita un secreto le deja al usuario una caja de texto o varias dependiendo lo que necesite que ingrese el usuario si tiene interfaz grafica y si es por terminal sin interfaz grafica tambien deberia poder hacerlo."
- S3. No friction (L1): "para poder guardarlo en la nube para no exponer los secretos tuvo que usar unos scripts antes y esto es lo que quiero evitar. quiero armar algo que ya tenga todo junto y no tenga fricciones para el usuario"
- S4. Sync goal (L2): "el objetivo es poder usarlo en varias maquinas y tambien podria usarse como backup para sync"
- S5. Backend (L3): own self-hosted server, "Servidor propio de gentle-vault".
- S6. Design accepted (L4): zero-knowledge server; encryption key never leaves devices, separate server authentication; new device via recovery key or approval from a paired device; versioned upload with per-record merge including deletions; offline use; device revocation; Go binary + Docker image deployable on Dokploy; invariant 8 becomes "only network to the user-configured server, only encrypted data"; multi-field `request`; new roadmap phase; threat model adds what the server sees.
- S7. Borrowed ideas (L5): typed fields (visible vs hidden) and the audit head anchored on the sync server.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1-S7 | inline | `docs/REMOTE_SYNC.md` (new): keys, pairing, server API, merge, anchor | docs(spec) | done |
| T2 | S1-S7 | inline | `docs/PRD.md`: goals, non-goals, flows, R-SYNC-*, R-CAP multi-field, R-AUD-03 | docs(spec) | done |
| T3 | S2,S6,S7 | inline | `contracts/.../CONTRACT.md` + schema: `fields`, kinds, `refs`, capabilities | docs(spec) | done |
| T4 | S4-S6 | inline | `docs/STORAGE.md`: body schema 2, remote files, tokens for many names, anchor | docs(spec) | done |
| T5 | S6 | inline | `docs/THREAT_MODEL.md`: T6, assets, L21-L31, residuals, checklist | docs(spec) | done |
| T6 | S2-S6 | inline | `docs/CLI.md`, `docs/ARCHITECTURE.md`, `docs/AGENT_INTEGRATIONS.md`, `docs/INSTALL.md`, `docs/TESTING.md` | docs(spec) | done |
| T7 | S6 | inline | `docs/ROADMAP.md` phase 2S + slices; `AGENTS.md` invariants 3 and 8, layout | docs(spec) | done |

## Log

- L1. User: "quiero que continuemos pero antes quiero saber si estamos alineados para no seguir desarrollando algo que no sirva. Lo que yo necesito es un vault simple pero robusto que permita al agente de codigo solicitar secretos y credenciales cuando las necesite, sin exponerlas o enviarlas por internet en texto plano. la idea de esto es que funcione con una base de datos encriptada local y en la nube. cuando el agente necesita un secreto le deja al usuario una caja de texto o varias dependiendo lo que necesite que ingrese el usuario si tiene interfaz grafica y si es por terminal sin interfaz grafica tambien deberia poder hacerlo. estuve probando vaultwareden por mcp pero para poder guardarlo en la nube para no exponer los secretos tuvo que usar unos scripts antes y esto es lo que quiero evitar. quiero armar algo que ya tenga todo junto y no tenga fricciones para el usuario"
- L2. User: "el objetivo es poder usarlo en varias maquinas y tambien podria usarse como backup para sync"
- L3. User chose "Servidor propio de gentle-vault" over S3-compatible storage and a synced folder.
- L4. User: "perfecto." to the proposed server design and to writing the spec change first in a separate commit.
- L5. Competitive review of 8 open projects + OpaqueVault (Engram `gentle-vault/competitive-analysis`): none combines native multi-OS capture, per-use grants and self-hosted zero-knowledge sync. User: "si por favor. a fuego demosle" to writing the spec with typed fields and the server-anchored audit head; file injection and enforced HTTP host allowlist deferred.
- L6. Decisions taken while writing: CLI namespace `gentle-vault remote …` because `sync` already means re-applying host registrations (R-INS-08); grants, config and the audit log stay per machine (only the audit head digest is anchored, encrypted); project layers get a stable id with per-device roots, bound on a new machine with `gentle-vault link`; pairing uses two codes (new-device key fingerprint typed on the approver, confirmation code typed on the new device) so the server can neither substitute a device key nor plant its own master key; revoking a device rotates the master key and the recovery key; `exec` never touches the network.
