# Post-launch: pending fixes, full docs pass, repo cleanup

After 0.1.0-beta.17 (launch candidate, `odd/tasks/launch-polish.md`). Close every item deferred there, bring every document in line with the code, and leave the repository tidy. Fixes and simplification only: no new features.

## Specs

- S1. User (verbatim): "los pendientes, actualizar toda la documentacion y limpiar el repo para que no quede nada desprolijo"
- S2. Owner decisions (verbatim answers, 2026-11-07):
  - audit.head: "Detectarlo (recomendado)" — `audit.head` is written when the vault is created, and a missing head is reported as `head_mismatch` by `audit verify` and `doctor`; an existing vault without one gets it written the next time the audit log is opened by a command that writes (no false alarm on upgrade).
  - `remote status` exit code with warnings: "0, con los avisos en texto (recomendado)" — unchanged, documented.
  - Attribution: "qbitdev" — the project is presented as "QBit Vault by qbitdev" wherever an author or brand line appears (README, design, docs, TUI/splash text if any); repository URLs, the Go module path and the ghcr image keep `QuBiit0`/`qubiit0`.
  - `odd/tasks/`: "Dejarlas, con un README que explique (recomendado)" — kept; `odd/README.md` explains what they are and indexes them.
  - Parent defaults for the two minor open decisions (owner may override): a passphrase that does not match its confirmation is asked again, up to 3 times, instead of failing; no beta-cadence note (the CHANGELOG is enough).
- S3. Pending fixes (from `launch-polish.md` § P3 and S12 "Deferred"), each RED first, each observable effect asserted:
  - S3.1 (B-F4) as decided in S2.
  - S3.2 (A-F9) A refused or cancelled request starts a short cooldown per secret name and layer, not only per session, so a new session cannot re-prompt the same name at once.
  - S3.3 (A-F13) `request` storing a value and a concurrent `set` of the same name cannot interleave (the store happens under the vault lock with a re-check); confirm the race first, pin it with a test.
  - S3.4 `import` refuses the startup env names `exec` and `set` refuse (S12.3 of launch-polish), with the same message.
  - S3.5 PowerShell `-Command` is recognised by any unique prefix PowerShell accepts (`-c`, `-co`, `-com`, `-comm`, ...), so the script after it is inspected by the dump guard.
  - S3.6 (B-F5..F18) each storage/locking item is confirmed against the code first; fix the confirmed ones that are local and small (restore surfaces rekey-recovery errors; staged-key promote retries transient Windows errors; temp files are created with O_EXCL; Windows owner/empty-DACL check; stale-lock break cannot remove a lock another process just took; `init` reports keychain errors instead of ignoring them). An item that needs a format change (e.g. a rollback counter for `retired.enc`) is documented as a limit instead.
- S4. Sync follow-ups:
  - S4.1 (C-S08) A revoked device can rejoin: `remote join` on a device whose id the account revoked uses a new device id (and moves this device's project roots to it), so the account accepts it after a fresh pairing. REMOTE_SYNC § 4.5 and CLI.md drop the "known limitation" text.
  - S4.2 The joiner's confirmation-code question has its own wording (no `Saved in` / `Value: new` lines of a secret request): heading `Confirmation code`, text `Type the confirmation code shown on the device that approved this one`.
  - S4.3 `remote devices` does not say `last sync: never` for a device that only pulls: it shows the server's last-seen time as `last seen` (and `last sync` only when known).
  - S4.4 Passphrase confirmation retry as in S2.
- S5. The live server reports its real version: the Dokploy compose switches to `deploy/compose.image.yaml` (the published image), so a release (not a push to `main`) changes what runs; documented in `deploy/README.md` and INSTALL. Verified on `https://vault.leandroalvarez.com.ar/v1/info`.
- S6. Documentation pass: every file under `docs/`, `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `deploy/README.md`, `design/README.md`, `assets/brand/README.md`, `contracts/.../CONTRACT.md` and `odd/README.md` is checked against the code at the end of S3-S5: no "planned"/"pending"/"not published" text for things that exist, no description of behavior the code no longer has, commands and messages quoted exactly as the binary prints them, links valid. ROADMAP status table reflects reality. Attribution as in S2.
- S7. Repository cleanup: no merged or stale branches on GitHub, no stray or generated files tracked, `.gitignore` covers local tool folders, `CHANGELOG.md` `[Unreleased]` tidy, `odd/README.md` indexes the work logs.
- S8. Released as 0.1.0-beta.18 (also the first real run of the bumped goreleaser-action v7 and attest v4); attestation verified, image pulled, this machine and the WSL Ubuntu upgraded and synced.

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T1 | S3.1-S3.5 | worker | | done (uncommitted) |
| T2 | S3.6 | worker | | done (uncommitted) |
| T3 | S4.1-S4.4 | worker | | pending |
| T4 | S5 | parent (Dokploy API) | | pending |
| T5 | S6 + S2 attribution + odd/README | worker(s) | | pending |
| T6 | S7 | parent | | pending |
| T7 | S8 | parent | | pending |

## Log

- L1. User (verbatim): "los pendientes, actualizar toda la documentacion y limpiar el repo para que no quede nada desprolijo"
- L2. Owner answers to four questions: audit.head "Detectarlo (recomendado)"; remote status exit "0, con los avisos en texto (recomendado)"; attribution "qbitdev"; odd/tasks "Dejarlas, con un README que explique (recomendado)". Parent defaults for passphrase retry (3 tries) and no cadence note. Order: code (T1-T3) before the docs pass so docs describe the final code.
- T1 (worker, uncommitted): S3.1 missing `audit.head` next to 2+ records is `head_mismatch` (1 record = crash window; every released version wrote the head, so no upgrade alarm); S3.2 30 s all-sessions cooldown per name and layer (`grants.CoolShared`); S3.3 race confirmed, `request` now stores with `vault.PutMissing` (never replaces) and refuses retryably; S3.4 `import` runs `checkStartupEnv`; S3.5 `scriptOf` resolves any `-Command` prefix via `psOption`. Docs: STORAGE, CLI, THREAT_MODEL, CHANGELOG.
- T2 (worker, uncommitted): S3.6 confirmed and fixed test-first: restore surfaces an unreadable retired list (B-F5), keychain `renameWithRetry` for Promote and key-file writes (B-F6), vault temp files `O_EXCL` (B-F7), Windows `Check` rejects an empty DACL and a foreign owner (B-F14), stale-lock break serialized under `<lock>.break` with a re-check (B-F10), `Setup` returns a non-ErrNoKey keychain read error (B-F11); `retired.enc` rollback counter needs a format change: documented as a limit (STORAGE § Retired keys, THREAT_MODEL R8); "nits" and `init`'s `removeKey` ignoring a failed cleanup not mapped to a concrete item, left as is.
