# Minisign-signed releases

Every release signs `checksums.txt` with Minisign, so a download is checked for who published it, not only for integrity against a checksum served from the same release. `qbit-vault update` requires the signature; the one-line installers verify it when `minisign` is installed and say how to verify by hand when it is not. The public key is pinned in the repository, the binary and the installers, never downloaded.

## Specs

- S1. User (verbatim, 2026-11-11): "si por favor hacelo" to "te recomiendo Minisign: hoy la release y `update` confían solo en el SHA-256 que viene de GitHub. ¿Lo arrancamos?". Owner choices (verbatim): "Secret de GitHub con environment protegido (recomendado)"; "Verifican si hay minisign; si no, avisan (recomendado)".
- S2. Format and verifier (`internal/minisign`, Go stdlib `crypto/ed25519` + `golang.org/x/crypto/blake2b`, no new dependency):
  - S2.1 Public key: the standard Minisign text form (`untrusted comment: minisign public key <KEYID>` + base64 of `Ed` ‖ key id (8) ‖ Ed25519 key (32)). Signature file `checksums.txt.minisig`: untrusted comment line, base64 of `ED` ‖ key id ‖ 64-byte signature over BLAKE2b-512 of the file, `trusted comment: <text>` line, base64 global signature over signature ‖ trusted comment text.
  - S2.2 Verify accepts only algorithm `ED` (prehashed), requires the key id to match, checks both signatures, and rejects trailing or malformed lines. Errors are fixed strings (`signature does not match`, `signature made with another key`, `malformed signature`), never file content.
  - S2.3 Compatibility is proven both ways in tests: a signature made by the repository's signer verifies with the real `minisign -V` when `minisign` is on PATH (skipped otherwise, never in the default CI path unless installed there), and the verifier accepts the published minisign test vectors or a fixture made with `minisign -S`.
- S3. Signer and key generation (`tools/release-sign`, Go, built only for the release workflow and the maintainer; not in the `qbit-vault` binary):
  - S3.1 `release-sign keygen` writes a Minisign public key file and prints a secret seed meant only for the GitHub secret; it reads nothing from the environment and never logs the seed except to the file or stdout the maintainer chooses.
  - S3.2 `release-sign sign <file>` reads the secret seed from the environment variable `QBIT_VAULT_SIGNING_KEY` (never an argument), writes `<file>.minisig` with trusted comment `timestamp:<unix> file:<name> version:<tag>`, and refuses an empty or malformed key. The seed never appears in output, errors or logs.
- S4. Release workflow (`.github/workflows/release.yml`, `.goreleaser.yaml`):
  - S4.1 GoReleaser publishes the release as a **draft**. A new job `sign` (needs the build job, `environment: release-signing`, `permissions: contents: write` only, pinned actions) downloads `checksums.txt` from the draft, verifies its SHA-256 lines against the draft's assets, builds `tools/release-sign`, signs, uploads `checksums.txt.minisig`, verifies the upload with the pinned public key, and only then publishes the release (draft false). The server-image job runs after `sign`.
  - S4.2 The provenance attestation still covers the archives and `checksums.txt` (AGENTS.md manifests rule), now also `checksums.txt.minisig`.
  - S4.3 `internal/cli/release_files_test.go` pins: the draft setting, the `sign` job's environment and minimal permissions, that only `sign` sees `QBIT_VAULT_SIGNING_KEY`, pinned actions, and the job order.
- S5. `qbit-vault update` (`internal/selfupdate`): after the SHA-256 check and before extracting, it downloads `checksums.txt.minisig` and verifies it with the pinned public key (`internal/minisign`, key compiled into the binary). A missing, malformed or non-matching signature stops with `the release <version> is not signed with the QBit Vault release key; nothing was changed` (exit 1), leaves the installed binary untouched, and never falls back to SHA-256 only. `update --check` is unchanged.
- S6. Installers (`scripts/install.sh`, `scripts/install.ps1`): the public key is pinned in the script. After the SHA-256 check: if `minisign` is on PATH, download `checksums.txt.minisig` and run `minisign -V -P <pinned key> -m checksums.txt -x checksums.txt.minisig`; failure stops the install before anything is written. If `minisign` is not installed: continue and print exactly `minisign not found: checksums.txt was checked with SHA-256 only. Verify the signature with: minisign -V -P <key> -m checksums.txt -x checksums.txt.minisig`. A release with no `.minisig` (older than the first signed one) is refused when `minisign` is installed and the requested version is at or above the first signed version; older explicit versions say they are unsigned.
- S7. Key pinning: one source of truth file `defaults/release-key.pub`; a Go test keeps the key in `internal/minisign` (embedded), `scripts/install.sh` and `scripts/install.ps1` byte-equal to it. Until the owner generates the real key (S9), a clearly named test key is used only in tests; the release cannot ship with a test key (a test fails if `defaults/release-key.pub` carries the test key id).
- S8. Docs: INSTALL (verify a download, the warning), THREAT_MODEL L12 (built), PRD R-NFR-03, ROADMAP, README (verify line), SECURITY or release notes footer in `.goreleaser.yaml` (`minisign -V` command next to `gh attestation verify`), AGENTS.md invariant 8 wording now true, CHANGELOG [Unreleased].
- S9. Owner setup (cannot be done by the agent: the secret never passes through the model): run `release-sign keygen` locally, commit the public key (S7), store the seed with `gh secret set QBIT_VAULT_SIGNING_KEY --env release-signing`, create the `release-signing` environment with the owner as required reviewer. Then release 1.4.0 and verify: draft until signed, `.minisig` present, `minisign -V` passes, `qbit-vault update` from 1.3.0 accepts it.

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T1 | S2, S3, S7 (verifier, signer, key pinning) | worker | | pending |
| T2 | S5, S6 (update and installers) | worker | | pending |
| T3 | S4, S8 (workflow, docs) | worker | | pending |
| T4 | verify S2-S8 (Risk: items 2, 5) | gentle-ai-verify | | pending |
| T5 | S9 owner setup, PR, release 1.4.0 | parent + owner | | pending |

## Log

- L1. User (verbatim): "si por favor hacelo"; choices "Secret de GitHub con environment protegido (recomendado)" and "Verifican si hay minisign; si no, avisan (recomendado)".
- L2. Research (explorer): releases carry `checksums.txt` (GoReleaser `checksum`, no `signs:`) and a build-provenance attestation over archives and checksums; install.sh/install.ps1 and `selfupdate.Download` check SHA-256 against the `checksums.txt` of the same release; PowerShell 5.1 and sh have no Ed25519; `golang.org/x/crypto/blake2b` is in an allowed module. Docs already promise Minisign "without changing the command" (PRD:13, R-NFR-03, INSTALL:167/290, THREAT_MODEL L12, ROADMAP:121-122, self-update S2). The e2e install battery does not exercise checksum verification. `release_files_test.go` pins workflow permissions, action pins and goreleaser globs. A post-publish signing step risks a window without signature, hence the draft-then-publish order (S4.1); drafts are invisible to `releases/latest`.
- L3. Parent decisions: our own Go signer instead of installing minisign in CI (no third-party binary in the signing job; output is standard Minisign so users verify with `minisign -V`); key seed (not the minisign encrypted secret-key file) in the secret.
