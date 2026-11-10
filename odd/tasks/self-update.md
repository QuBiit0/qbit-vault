# Self-update: `qbit-vault update` and the TUI update notice

After 1.0.0. One command that brings an installed `qbit-vault` to the latest release, verified, and a TUI that says when a new version exists and updates from there. Released as 1.1.0 (a new feature).

## Specs

- S1. User (verbatim, 2026-11-10): "vale, arrancamos con lo que esta pendiente.. ni bien tenga el feedback de la comunidad (si es que alguno la utiliza) te lo paso" and the choice "qbit-vault update (recomendado primero)".
- S2. Owner decisions (verbatim answers):
  - Verification: "SHA-256 de checksums.txt (recomendado)" — the same check the installers do, over HTTPS from GitHub; Minisign is added later without changing the command.
  - Update notice: "la manera tiene que ser como hacen muchas otras app como gentle-shell cada vez que se abre que compruebe si hay una version nueva y en la misma tui aparezca para actualizarla".
- S3. `qbit-vault update` (CLI):
  - S3.1 It asks the releases API for the latest release (`https://api.github.com/repos/qbitdevz/qbit-vault/releases/latest`; `QBIT_VAULT_RELEASES_API` overrides the base exactly as the installers do) and compares it with the running version (semver; a pre-release is never newer than its release).
  - S3.2 Up to date: prints `qbit-vault <version> is up to date` and exits 0; nothing is downloaded.
  - S3.3 Newer: it confirms out of band through the prompt backend (`Update QBit Vault <current> to <latest>?`, Decline is the default, like every confirm); no prompt backend is `not_model_callable` (exit 3) as for the other user-only commands; a decline is `cancelled` (exit 1) and changes nothing.
  - S3.4 After the confirm it downloads the archive for this OS and architecture (the release asset names the installers use: `qbit-vault_<os>_<arch>.tar.gz`, `.zip` on Windows) and `checksums.txt`, checks the archive's SHA-256 against its line in `checksums.txt`, and extracts `qbit-vault` (`qbit-vault.exe`). A missing line, a mismatch, a missing binary in the archive or any download error stops with a clear message and leaves the installed binary untouched; nothing is written next to it but a temp file that is removed.
  - S3.5 The swap is atomic: POSIX renames the new file over the running one (same directory, mode 0755); Windows renames the running `qbit-vault.exe` to `qbit-vault.exe.old-<8 hex>` and moves the new one into place, and old copies are removed on a later run, as `install.ps1` does. A failure after the old binary was moved puts it back.
  - S3.6 Then it re-applies the recorded agent registrations exactly like `qbit-vault sync` (skipped with `QBIT_VAULT_NO_SYNC=1`, as in the installers) and prints `updated qbit-vault <current> -> <latest>; restart your agents so they load the new version`.
  - S3.7 `update --check` only reports: `update available: <current> -> <latest>` or `qbit-vault <version> is up to date`; exit 0 either way; no prompt, no download. `--json` for both forms: `{"ok":true,"current":"…","latest":"…","update_available":bool}` (and `"updated":true` after a real update).
  - S3.8 A build that is not a release (`dev`, a `+dirty` or pseudo-version, or no version) refuses to self-update with `this build is not a release; install with the one-line installer or 'go install github.com/qbitdevz/qbit-vault/cmd/qbit-vault@latest'` (exit 2, usage); `--check` still reports. A binary whose directory is not writable stops with `cannot replace <path>: re-run the install command` before downloading.
  - S3.9 The vault, grants, audit log and sync state are never opened or written; no secret is read; nothing but the GitHub API and the release assets is contacted, over HTTPS only (an `http://` override is accepted only for loopback, for tests).
- S4. TUI (the owner's notice):
  - S4.1 Every time the TUI opens it checks for a newer release in the background with a short timeout (5 s); the screen never waits for it and no error is shown when there is no network or the check fails (the Update section then says `could not check for updates`).
  - S4.2 When a newer release exists, the header shows `update available <latest>` and the Update section shows the current and latest versions, a link to the release notes, and the key `u update now`.
  - S4.3 `u` runs the update of S3 (the TUI is suspended for the confirm like every other action), then the Update section says `updated to <latest>; restart qbit-vault and your agents`; a failure shows its one-line message.
  - S4.4 `QBIT_VAULT_NO_UPDATE_CHECK=1` turns the open-time check off (the Update section then offers `c check now`); it never affects the explicit `qbit-vault update`.
  - S4.5 The TUI still never holds a secret value and creates no grant.
- S5. AGENTS.md invariant 8 already allows the optional update check; THREAT_MODEL, PRD, INSTALL (§ Self-update), CLI (command row, TUI Update row, env table: `QBIT_VAULT_NO_UPDATE_CHECK` is now read), ROADMAP and README (upgrading) describe the shipped behavior; CHANGELOG [Unreleased].
- S6. Tests (RED first): an httptest server stands in for the releases API and the assets (through `QBIT_VAULT_RELEASES_API` and the asset URLs it returns): up to date; newer + confirm swaps the binary (a temp copy, never the test binary itself); decline changes nothing; checksum mismatch and missing line leave the binary byte-identical; Windows rename path and cleanup of `.old-*`; non-release build refusal; no prompt backend; `--check` text and JSON; TUI model tests with a fake backend for S4.1-S4.4.
- S7. Released as 1.1.0 with the usual verification; then `qbit-vault update` itself is run on this machine from 1.1.0 once a later release exists, or `update --check` reports up to date.

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T1 | S3, S5 (CLI parts), S6 (CLI) | worker | | done (uncommitted) |
| T2 | S4, S5 (TUI parts), S6 (TUI) | worker | | done (uncommitted) |
| T3 | S7 | parent | | pending |

## Log

- L1. User (verbatim): "vale, arrancamos con lo que esta pendiente.. ni bien tenga el feedback de la comunidad (si es que alguno la utiliza) te lo paso"; chose "qbit-vault update (recomendado primero)".
- L2. Decisions: verification "SHA-256 de checksums.txt (recomendado)"; notice "la manera tiene que ser como hacen muchas otras app como gentle-shell cada vez que se abre que compruebe si hay una version nueva y en la misma tui aparezca para actualizarla". Parent choices to confirm in review: update is a user-only command with an out-of-band confirm (an agent cannot swap the binary silently); `--check` and the TUI check never prompt.
- L3. T1 built (uncommitted): `internal/selfupdate` (lookup, semver, download, SHA-256, tar.gz/zip extract, atomic swap with the Windows `.old-<8 hex>` path) and `internal/cli/update.go` (`update`, `update --check`, `--json`); tests in both packages written RED first. Decisions: the re-registration runs the new binary's `sync` as a subprocess (only when `state.json` exists; not opened); `--check` on a non-release build reports an update as available; the lookup accepts one release object or a list (newest published stable); a `sync` failure after a swap is a stderr note, exit 0. TUI lines in the docs are left to T2.
- L4. T2 built (uncommitted): `tui.Backend` gains `CheckUpdate() (UpdateInfo, error)` and `Update() Action` (cli: `selfupdate` client with a 5 s `tuiCheckTimeout`, `update` run under tea.Exec); `Options.NoUpdateCheck` (from `QBIT_VAULT_NO_UPDATE_CHECK=1`) and `Options.NotRelease`; the check is `Init`'s tea.Cmd so the first frame never waits; header `update available <latest>`; Update section states checking/failed/up to date/available/updated; keys `u`, `c`. Decisions: a non-release build makes no check; a failed check is silent apart from the section line; the release notes link is shown under the panes (too long for the list pane); `c` is also offered after a failed check; after `u` succeeds nothing more is offered (the running binary is still the old one). Tests RED first (compile failure on the new API) in internal/tui/update_test.go and internal/cli/tuibackend_test.go, tuicmd_test.go. Two expectations in model_test.go (`TestSectionSwitching` rows for Update) changed for the new section text.
