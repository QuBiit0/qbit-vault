# Roadmap and delivery plan

Sliced so every PR stays ≤ 400 changed lines (the review budget), each with code + tests + docs. Phases are sequential; slices within a phase are mostly parallelizable. IDs refer to `docs/PRD.md`.

**Status.** *done* = built, tested and merged to `main` (evidence: commit hashes from `odd/tasks/*.md`); *dropped* = removed from scope by a recorded decision; *moved* = scheduled in another phase; *not built* = not implemented. Releases are published from the `v*` tags (`CHANGELOG.md`): archives for Linux, macOS and Windows, `checksums.txt`, the two installers, a build-provenance attestation and the server image `ghcr.io/qbitdevz/qbit-vault-server`. 1.0.0 is the first stable release. **Not built:** the npm package, the Homebrew formula, the Pi / Gentle Shell native extension, and Minisign-signed checksums; `qbit-vault update` is built (CLI); Pi and Gentle Shell work through MCP in the meantime.

| Phase | Status |
| --- | --- |
| 0 alignment | done, except reserving the npm names (Phase 5) |
| 1 core vault | done |
| 2 contract and MCP | done |
| 2S remote sync | done |
| 3 hosts | done as scoped: Claude Code, Codex, Pi / Gentle Shell through MCP; OpenCode dropped; packaging moved to Phase 5 |
| 4 Gentle Shell / Pi extension | not built (Pi uses its MCP entry) |
| 5 hardening and release 1.0.0 | 1.0.0 is the first stable release: archives, installers, provenance and the server image are done; npm and Homebrew are not built (Minisign-signed checksums are built, first signed release 1.4.0); `qbit-vault update` is built after 1.0.0 (`odd/tasks/self-update.md`) |
| TUI | done (`odd/tasks/tui.md`); the Update section checks for a newer release on open and updates from there (`odd/tasks/self-update.md`) |

## Phase 0 — alignment (no code)

- [x] Original proposal written (`docs/PROPOSAL.md`, historical: the product was then called gentle-vault).
- [x] Repo location decided: its own repository, `github.com/qbitdevz/qbit-vault`. The product was renamed to QBit Vault and is independent of the hosts it integrates with (`odd/tasks/rename-qbit.md`, a78c03d).
- [ ] Reserve names: npm `qbit-vault`, `qbit-vault-pi`, `@qbit-vault/cli-*` (Phase 5). The Go module path is `github.com/qbitdevz/qbit-vault`.

## Phase 1 — core vault (CLI only, no hosts) — done

| Slice | Content | Req | Status |
| --- | --- | --- | --- |
| 1.1 | Repo skeleton, cobra CLI, `--json`, exit codes, `Secret` type with redacting `String/Format/MarshalJSON`, CI with leak grep | AGENTS.md | done (0b3a338, 9dfa50f, 54b0d60) |
| 1.2 | `vault`: envelope, XChaCha20-Poly1305, atomic write, backups, rollback counter; `global`/`projects` body and name resolution | R-VAULT-01,04,07,09, R-LAYER-01..03 | done (49280a9, 9126998, 1d685f6) |
| 1.3 | `keychain`: go-keyring backend + passphrase/Argon2id fallback + cached unlock | R-VAULT-02 | done (acd9f0b, e2cddb6) |
| 1.4 | `set --stdin`, `rm`, `list`, `describe`, `edit` with `--global`/`--project`, permissions enforcement | R-VAULT-03,05,06, R-CAP-07 | done (7a47d98, eba8752) |
| 1.4a | `mv`, `relink`, `list --layer` | R-LAYER-04,05 | done (9ba9eea, 7a47d98) |
| 1.5 | `audit`: hash chain, `--verify`, event writers | R-AUD-* | done (0156295, 3cd812a) |
| 1.6 | `grants`: encrypted `grants.enc`, (name, layer) binding, scopes, TTL, project root resolution, `grant`/`revoke`/`grants` (TTY-only) | R-GRANT-01,02,04,06 | done (8d165d5, ae77456, 9530bb2) |
| 1.7 | `redact`: streaming multi-encoding + fuzz | R-RED-01..03 | done (342c72d, 340dffa) |
| 1.8 | `exec`: env build/scrub, dump-guard from `dumpguard.yaml`, binary allowlist, timeout, pgroup, `--stream` | R-EXEC-* | done (cbe1fd6, 8035844, 4fb3686) |
| 1.9 | `prompt`: tty backend + prompt token; `set` interactive | R-CAP-01,04 | done (28cc860, e85a897) |
| 1.10 | `prompt`: osascript, powershell, zenity/kdialog backends | R-CAP-01 | done (d517de1, 141cda2, 2556989) |
| 1.11 | `import --from-env/--from-file`, `rekey`, `lock/unlock`, `restore` | R-VAULT-08 | done (5d256a5 `import`, 90e50b4 `rekey`, b7ff436 `lock`/`unlock`, 3a1e772 `restore`) |

Exit criterion: a human can `set`, `grant` and `exec` end-to-end on all three OSes with the leak battery green. CI runs the unit suite and the leak grep on Linux, macOS and Windows (`.github/workflows/ci.yml`).

## Phase 2 — contract and MCP — done

| Slice | Content | Req | Status |
| --- | --- | --- | --- |
| 2.1 | `broker` package implementing all ops + refusals; `broker --op` CLI; schema validation | CONTRACT.md | done (60ee2ac) |
| 2.2 | `request` with existence non-disclosure, layer choice, reason heuristic, rate limit; `list` with `policy` | R-API-02,03,06, R-CAP-02,03a,05 | done (8de9a67) |
| 2.2a | `manage` op: remove/edit/move/replace, prompt token, widening labels, cooldown | R-API-07,08 | done (2785344) |
| 2.2b | Multi-field `request`: `fields` with `kind`/`label`, `refs` response, tokens bound to several names, `set --stdin --fields`, `prompt --field`; record `kind` | R-API-02, R-CAP-08,09, R-VAULT-06 | done in the broker (9de39b0); `set --stdin --fields` and `prompt --field` moved to slice 4.3 (the broker stores multi-field captures itself, so MCP hosts do not need them) |
| 2.2c | Multi-field rendering in every prompt backend (PowerShell form, zenity `--forms`, consecutive boxes for osascript, kdialog and tty) | R-CAP-08, AGENT_INTEGRATIONS | done (9de39b0, 40c2c9b) |
| 2.3 | `mcp` stdio server, four tools, normative descriptions, `policy` as server `instructions`, `grant` refusal | R-API-01,05,06 | done (634802f) |
| 2.4 | Contract conformance test harness | TESTING.md | done (00c562b; review fixes eca2ef1) |

## Phase 2S — remote sync (`REMOTE_SYNC.md`) — done

Runs after Phase 2 so the contract is settled; S.1 can land earlier because it only changes the local body.

| Slice | Content | Req | Status |
| --- | --- | --- | --- |
| S.1 | Body schema 2 and migration: project ids, per-device `roots`, `device_id`, `kind`, `hlc`, tombstones; `link`; `list --layer all` marks unlinked layers; `keys/retired.enc` with `rekey`/`restore` | R-SYNC-11, STORAGE | done (fc7ebeb body schema 2; 0cab11d `link`) |
| S.2 | `internal/merge`: pure three-way merge, conflicts, roster rules, fuzz and property tests | R-SYNC-07 | done (db370d8; 12ec7be) |
| S.3 | `internal/remote` crypto: key derivations, device keys, recovery key format, key and recovery envelopes, remote vault object with padding, anchors, pairing and confirmation codes (pure, test vectors) | R-SYNC-02,04 | done (ea50f5f) |
| S.4 | `internal/server` core: file store, accounts and invites, device auth (challenge, token), vault CAS and last 10 versions, limits and rate limits, logging rules | R-SYNC-02,03 | done (fdca3e7) |
| S.5 | Server pairing, recovery, atomic `rekey`/revoke, anchors endpoints | R-SYNC-04,06,10 | done (4c3f05e) |
| S.6 | Packaging: `cmd/qbit-vault-server` (`serve`, `invite`), Dockerfile (static, non-root, read-only), `deploy/compose.yaml` for Dokploy, release jobs | R-SYNC-12 | done: binary, Dockerfile and `deploy/compose.yaml` (39c8b6b); the release workflow publishes `ghcr.io/qbitdevz/qbit-vault-server` (linux/amd64 and arm64) and `deploy/compose.image.yaml` runs it |
| S.7 | Client transport and `remote register` / `join` (pairing and `--recovery`) / `approve` / `logout`, all user-only through the prompt backend | R-SYNC-01,03,04,05 | done (9f3113f vault side, bc5d4b2 transport, d6f1fff commands) |
| S.8 | Sync rounds wired into mutating and reading commands, pending pushes, `remote sync` / `status` / `devices`, `--json` `remote` field, `doctor` | R-SYNC-07,09 | done (8c29c20); `doctor` landed with Phase 3 (bff3a29) |
| S.9 | `remote revoke-device`, `recovery-key --rotate`, rekey with sync, `conflicts` / `resolve`, `history` / `restore`, `audit --verify` anchors | R-SYNC-06,10 | done (f57ce32 revoke and rekey, 0f22398 conflicts, history, restore, anchors) |
| S.10 | E2E sync battery in Docker (three clients, rollback server, leak grep of `/data` and HTTP bodies) | TESTING.md | done (`bash e2e/docker-test.sh`, d0abf51; hardening b7c2092) |

Exit criterion (met by the Docker sync battery): TESTING.md Tier 2 step 7 green; a secret set on one OS is usable on another after `join`; the server volume holds no fixture value, name or path.

## Phase 3 — hosts — done as scoped

Scope decision (user, 2026-11-04, `odd/tasks/hosts.md` S8): a working tool for Claude Code, Codex and Gentle Shell / Pi. OpenCode is out; npm and Homebrew packaging moved to Phase 5 (they are not built; install with the release scripts or `go install`). Pi works through its MCP entry; the native extension is Phase 4 (built and published as git tags `pi-v<version>` of this repository; `init` prints its install command as a suggestion and never runs it).

| Slice | Content | Req | Status |
| --- | --- | --- | --- |
| 3.1 | `filemerge`: snapshot + atomic JSON/TOML merge + 3-way revert | R-INS-04 | done (2561f4c, 0b2bc91, aeef459) |
| 3.1a | `hook` subcommands with the dump-guard/bindings loading they need (added by the hosts scope) | R-HOST-02 | done (c20b0d0); rewriting references into `exec` is not built |
| 3.2 | Claude Code adapter: MCP entry, hooks (`pre-bash`, `post-bash`, `post-read`, `user-prompt`; `pre-bash` denies every `qbit-vault` subcommand except the read-only ones and `exec`, so mutating, `remote` and `link` commands stay user-only), deny rules | R-HOST-02, R-INS-05, R-SYNC-05 | done (720fb0c); Gentle AI entries are preserved by construction (owned-entry merge, golden tests), there is no separate abort-and-restore check |
| 3.3 | Codex adapter (MCP in `~/.codex/config.toml`; the prompt falls back to the terminal on its own) | R-HOST-03 | done (d00da6e) |
| 3.4 | OpenCode adapter (MCP + plugin when available) | R-HOST-04 | **dropped** (hosts.md S8, P6) |
| 3.5 | Pi (plain) adapter: MCP entry; the extension install command is printed, never run | R-HOST-01 | done (9ca10d6); the extension itself is Phase 4 (v1 built) |
| 3.6 | `init`, `sync`, `doctor`, `uninstall`, `state.json` receipts | R-INS-* | done (4373016 `init` + `doctor`, 309f37c `sync`, bff3a29 `uninstall`; Docker hosts battery `bash e2e/hosts-test.sh`, 27808b4) |
| 3.7 | npm launcher + platform packages + goreleaser + Minisign | R-INS-02, R-NFR-03 | **moved to Phase 5** (hosts.md P9) |

Dogfood round 1 (real use on Windows with Claude Code and Pi, `odd/tasks/dogfood-1.md`) added: `bash`/`sh` in `exec` never resolve to WSL and shell words stay intact (5180b22); a `once` grant is released when the child never started (5180b22); refusals answered over the broker and MCP are audited (97b796e); the dump guard stays strict and only `${#NAME}` is allowed, which the `secret_exec` description now tells agents (eaed280, after a relaxation was tried and withdrawn); session grants last 12 h and `session` is preselected in the approval dialog (2d5f944; superseded in 0.1.0-beta.8: agent dialogs offer once, always in this project, or no, see `CHANGELOG.md`).

## Phase 4 — Gentle Shell extension (`qbit-vault-pi`) — v1 built, published from `pi-v*` git tags (not on npm)

`packages/qbit-vault-pi` is built and tested (vitest with a fake binary, a Go test that keeps its `secret-patterns.yaml` equal to `defaults/`, the `pi-extension` CI job). The owner publishes it to npm, so `init` still prints no install line for it. Scope decided in `odd/tasks/pi-extension.md` S2; reference in `GENTLE_SHELL_EXTENSION.md`.

Built in v1: `/vault list|set|rm|revoke|audit|doctor` with completions, the footer status, paste interception with the shared pattern file, and the `session_shutdown` revoke. 0.2.0 adds the output and write guard on the built-in tools (`odd/tasks/output-guard.md`).

Deferred (nothing here is promised for a date):

| Item | Why |
| --- | --- |
| Capture inside the terminal | an extension cannot answer an MCP tool call (`tool_call` only blocks or mutates), so agent captures stay in the native dialog; the owner deferred a masked in-terminal input |
| Extension-registered tools and the `policy` in the system prompt | MCP already provides the four tools |
| Bash override with reference and binding scan, `--stream` plumbing | agents use `secret_exec` |
| `/vault mv`, `/vault edit`, fullscreen views | not needed for v1 |
| Sidebar entry | no Gentle Shell extension entry point found; the footer status is the indicator |
| `set --stdin --fields`, `prompt --field`, `prompt --confirm` | only needed by the deferred capture |

## Phase 5 — hardening and release 1.0.0

Done:

- GoReleaser archives for Linux, macOS and Windows (amd64 and arm64), `checksums.txt`, GitHub build provenance (`gh attestation verify`), the release workflow on `v*` tags, and `scripts/install.sh` / `install.ps1` (SHA-256 verified, in-place upgrade; both are release assets and are tested in CI on Linux, macOS and Windows). `odd/tasks/public-launch.md`.
- The server image `ghcr.io/qbitdevz/qbit-vault-server`, published by the release workflow, and `deploy/compose.image.yaml`.
- The three Docker batteries (sync, hosts, install from scratch; all on Linux), the unit suite and the leak grep in CI on Linux, macOS and Windows.
- Post-launch fixes and the documentation pass (`odd/tasks/post-launch.md`), the demo assets (`assets/demo/`, `assets/screenshots/`) and the README.
- Release 1.0.0, the first stable one (an immutable tag; see AGENTS.md § Conventions).

Not built (stated plainly, nothing here is promised for a date):

- The npm launcher and platform packages (`npx qbit-vault init`), the Homebrew formula, and reserving the npm names.
- Minisign-signed checksums: *built* (`odd/tasks/minisign.md`; the first signed release is `v1.4.0`, once the owner has generated the key, `docs/INSTALL.md` § Releasing).
- Minisign verification of `update`: *built* (`qbit-vault update` verifies `checksums.txt.minisig` with the key pinned in the binary, after the SHA-256, and refuses an unsigned release).
- A cross-agent battery (Tier 3 in `TESTING.md`) and Docker batteries for macOS and Windows.

## TUI — done

User request (2026-11-05, `odd/tasks/polish.md` S5): an interactive terminal app like the ones in engram and gentle-ai. Built in `odd/tasks/tui.md` (T1 af04545, T2 a308062, T3 60f409c, docs T4), reference in `CLI.md` § TUI.

- **Built.** `qbit-vault tui`, and `qbit-vault` with no arguments on a terminal (not with `--json` or `QBIT_VAULT_NO_TUI=1`). First-run splash and setup wizard (`init` with the chosen key storage and hosts). Three-pane home: Secrets (add, edit info, remove, unlock), Grants (list, revoke, revoke all; it cannot grant), Hosts (status, repair, uninstall, register), Audit (recent records, verify the local chain), Sync (status only), Doctor, and Update. Every action runs the real command path in-process; no value is ever shown and values and passphrases are typed only in the suspended prompt.
- **Not exercised.** The suspend and resume of the TUI around the masked prompt on a real terminal: tests replace that step. Leak tests use a fake host adapter, not real host config files.
- **Self-update (after 1.0.0).** The Update section checks for a newer release in the background every time the TUI opens (5 s, opt out with `QBIT_VAULT_NO_UPDATE_CHECK=1`), shows `update available <latest>` in the header, and `u` runs `qbit-vault update` with the TUI suspended. No secret value, no grant. Not built: Minisign verification.

## v2 candidates (not scheduled)

- Egress control for exec children (per-command network namespace / proxy) to close R1.
- Pluggable backends: `op://`, `pass`, Infisical, HashiCorp Vault; team sharing (several users on one sync server sharing selected secrets).
- File injection for secrets that tools read from a path (SSH keys, kubeconfig) without plaintext on disk (pipe or memory-backed file).
- Enforced host allowlist through a brokered `secret_http` call (today `hosts` is advisory).
- Biometric or OS-level confirmation (Touch ID, Windows Hello) for grants, against same-user UI automation (THREAT_MODEL R9).
- Project grants and project layers keyed by git remote.
- Keyed-hash secret names in the audit log (THREAT_MODEL R6).
- Browser-based capture for remote/SSH sessions.
- Secret-rotation hooks (`qbit-vault rotate NAME --via gh auth refresh`).
