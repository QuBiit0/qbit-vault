# Feature: rename gentle-vault to QBit Vault

Rename the product from gentle-vault to QBit Vault (`qbit-vault`) everywhere in the repository; the folder rename is handed to the user.
Branch `feat/cli-skeleton`.

## Specs

- S1. User (2026-11-04): "necesito cambiar si o si el nombre de la app.. se tiene que llamar QBit Vault no gentle-vault ya que puede ser que no tenga autorizacion del creador de gentle-ai. Asi que desde el repo y directorio hasta el branding y documentacion vas a tener que cambiar."
- S2. User: "aparte quiero empezar a crear todas mis herramientas y quiero que tengan nombre de mi marca personal qbit."
- S3. User choices: identifier "qbit-vault (Recomendado)" (binary `qbit-vault`, server `qbit-vault-server`, module github.com/QuBiit0/qbit-vault, env QBIT_VAULT_*, home ~/.qbit-vault, MCP server `qbit-vault`); crypto strings "Cambiarlas también (Recomendado)"; git history "Conservar historial (Recomendado)"; folder "Lo renombrás vos al final (Recomendado)".

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| R1 | S1-S3 | inline | mechanical rename (GENTLE_VAULT -> QBIT_VAULT, gentle-vault -> qbit-vault, GV_ -> QBV_, GVR1 -> QVR1, e2e `gv` -> `qbv`), moved cmd/ dirs and the proposal, branding titles, README independence note, crypto vector | (R commit) | done |
| R2 | S1, S3 | inline | full suite, e2e battery, leftover grep | (R commit) | done |
| R3 | S1, S3 | user | rename the folder D:\Proyectos\Propios\Gentle-Vault to QBit-Vault and reopen the session there | | pending |

## Log

- L1. Not renamed, on purpose: third-party host names the product integrates with (Gentle AI, Gentle Shell, `gentle-ai-*` agents, `gentle-engram`, docs/GENTLE_SHELL_EXTENSION.md, which documents that host), and the commit trailer. Old commit messages and the Phase 2 review branches keep the old name (history kept by choice).
- L2. The README said the project was "designed as a companion to the Gentle AI ecosystem"; it now says it integrates with existing hosts, including Gentle AI, and that QBit Vault is an independent project of the QBit brand, not affiliated with or endorsed by those hosts' authors. The stale status line ("design phase, nothing built yet") was replaced with the real one.
- L3. Crypto domain strings changed with the name (HKDF salt `qbit-vault/v1`, envelope formats `qbit-vault-*`, pairing and auth messages). The fixed vector in internal/remote/crypto_test.go was recomputed with an independent RFC 5869 HKDF in Python: with the old salt it reproduces the old vector `888fb20b8110087c` (method check), with the new salt it gives `742d452644d92830`, equal to the Go code. Server env vars `GV_SERVER_*` became `QBV_SERVER_*`; the recovery key prefix `GVR1` became `QVR1`. Vaults created before the rename (test vaults only) do not open with the new binary: nothing was released.
