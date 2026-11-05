# Roadmap and delivery plan

Sliced so every PR stays ≤ 400 changed lines (the review budget), each with code + tests + docs. Phases are sequential; slices within a phase are mostly parallelizable. IDs refer to `docs/PRD.md`.

**Status.** *done* = built, tested and merged to `main` (evidence: commit hashes from `odd/tasks/*.md`); *dropped* = removed from scope by a recorded decision; *moved* = scheduled in another phase; *pending* = not built. Nothing is released: there is no tag, no published package and no published image. Today QBit Vault is installed with `go install` or built from source (`INSTALL.md`).

| Phase | Status |
| --- | --- |
| 0 alignment | done, except reserving the npm names (Phase 5) |
| 1 core vault | done |
| 2 contract and MCP | done |
| 2S remote sync | done |
| 3 hosts | done as scoped: Claude Code, Codex, Pi / Gentle Shell through MCP; OpenCode dropped; packaging moved to Phase 5 |
| 4 Gentle Shell / Pi extension | pending |
| 5 hardening and release 0.1.0 | pending (now includes the packaging dropped from Phase 3) |
| TUI | done (`odd/tasks/tui.md`); self-update inside it waits for Phase 5 |

## Phase 0 — alignment (no code)

- [x] Original proposal written (`docs/PROPOSAL.md`, historical: the product was then called gentle-vault).
- [x] Repo location decided: its own repository, `github.com/QuBiit0/qbit-vault`. The product was renamed to QBit Vault and is independent of the hosts it integrates with (`odd/tasks/rename-qbit.md`, a78c03d).
- [ ] Reserve names: npm `qbit-vault`, `qbit-vault-pi`, `@qbit-vault/cli-*` (Phase 5). The Go module path is `github.com/QuBiit0/qbit-vault`.

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
| S.6 | Packaging: `cmd/qbit-vault-server` (`serve`, `invite`), Dockerfile (static, non-root, read-only), `deploy/compose.yaml` for Dokploy, release jobs | R-SYNC-12 | binary, Dockerfile and `deploy/compose.yaml` done (39c8b6b); release jobs and the published image are Phase 5 (no registry yet) |
| S.7 | Client transport and `remote register` / `join` (pairing and `--recovery`) / `approve` / `logout`, all user-only through the prompt backend | R-SYNC-01,03,04,05 | done (9f3113f vault side, bc5d4b2 transport, d6f1fff commands) |
| S.8 | Sync rounds wired into mutating and reading commands, pending pushes, `remote sync` / `status` / `devices`, `--json` `remote` field, `doctor` | R-SYNC-07,09 | done (8c29c20); `doctor` landed with Phase 3 (bff3a29) |
| S.9 | `remote revoke-device`, `recovery-key --rotate`, rekey with sync, `conflicts` / `resolve`, `history` / `restore`, `audit --verify` anchors | R-SYNC-06,10 | done (f57ce32 revoke and rekey, 0f22398 conflicts, history, restore, anchors) |
| S.10 | E2E sync battery in Docker (three clients, rollback server, leak grep of `/data` and HTTP bodies) | TESTING.md | done (`bash e2e/docker-test.sh`, d0abf51; hardening b7c2092) |

Exit criterion (met by the Docker sync battery): TESTING.md Tier 2 step 7 green; a secret set on one OS is usable on another after `join`; the server volume holds no fixture value, name or path.

## Phase 3 — hosts — done as scoped

Scope decision (user, 2026-11-04, `odd/tasks/hosts.md` S8): a working tool for Claude Code, Codex and Gentle Shell / Pi. OpenCode is out; packaging moves to Phase 5 (meanwhile: `go install`). Pi works through its MCP entry plus a printed `pi install npm:qbit-vault-pi` line; the native extension is Phase 4.

| Slice | Content | Req | Status |
| --- | --- | --- | --- |
| 3.1 | `filemerge`: snapshot + atomic JSON/TOML merge + 3-way revert | R-INS-04 | done (2561f4c, 0b2bc91, aeef459) |
| 3.1a | `hook` subcommands with the dump-guard/bindings loading they need (added by the hosts scope) | R-HOST-02 | done (c20b0d0); rewriting references into `exec` is not built |
| 3.2 | Claude Code adapter: MCP entry, hooks (`pre-bash`, `post-bash`, `post-read`, `user-prompt`; `pre-bash` denies every `qbit-vault` subcommand except the read-only ones and `exec`, so mutating, `remote` and `link` commands stay user-only), deny rules | R-HOST-02, R-INS-05, R-SYNC-05 | done (720fb0c); Gentle AI entries are preserved by construction (owned-entry merge, golden tests), there is no separate abort-and-restore check |
| 3.3 | Codex adapter (MCP in `~/.codex/config.toml`; the prompt falls back to the terminal on its own) | R-HOST-03 | done (d00da6e) |
| 3.4 | OpenCode adapter (MCP + plugin when available) | R-HOST-04 | **dropped** (hosts.md S8, P6) |
| 3.5 | Pi (plain) adapter: MCP entry; the extension install command is printed, never run | R-HOST-01 | done (9ca10d6); the extension itself is Phase 4 |
| 3.6 | `init`, `sync`, `doctor`, `uninstall`, `state.json` receipts | R-INS-* | done (4373016 `init` + `doctor`, 309f37c `sync`, bff3a29 `uninstall`; Docker hosts battery `bash e2e/hosts-test.sh`, 27808b4) |
| 3.7 | npm launcher + platform packages + goreleaser + Minisign | R-INS-02, R-NFR-03 | **moved to Phase 5** (hosts.md P9) |

Dogfood round 1 (real use on Windows with Claude Code and Pi, `odd/tasks/dogfood-1.md`) added: `bash`/`sh` in `exec` never resolve to WSL and shell words stay intact (5180b22); a `once` grant is released when the child never started (5180b22); refusals answered over the broker and MCP are audited (97b796e); the dump guard stays strict and only `${#NAME}` is allowed, which the `secret_exec` description now tells agents (eaed280, after a relaxation was tried and withdrawn); session grants last 12 h and `session` is preselected in the approval dialog (2d5f944).

## Phase 4 — Gentle Shell extension (`qbit-vault-pi`) — pending

Nothing of `packages/qbit-vault-pi` exists yet (there is no `packages/` directory). Until it does, Pi and Gentle Shell use QBit Vault through the MCP entry that `init` registers: the four tools and the native dialogs. The bash override, paste interception, `/vault` commands and the sidebar need the extension. Also planned here: `set --stdin --fields`, `prompt --field` and `prompt --confirm`.

| Slice | Content |
| --- | --- |
| 4.1 | Package skeleton, `broker.ts` spawn wrapper, TypeBox types, degraded mode |
| 4.2 | Tools `secret_request` / `secret_list` / `secret_exec` / `secret_manage`; `policy` in the system prompt |
| 4.3 | `CaptureView` masked input + layer and scope select; grant-only mode; `manage` confirmation view |
| 4.4 | Bash override with reference + binding scan, `--stream` plumbing |
| 4.5 | Read/write guards (`tool_call`, `tool_result`) |
| 4.6 | Paste interception (`input` hook) with shared `secret-patterns.yaml` + parity test |
| 4.7 | `/vault` commands (manual `set`, `mv`, `edit`, layer filters) and fullscreen views |
| 4.8 | Sidebar widget / status footer; session_end revoke |

## Phase 5 — hardening and release 0.1.0 — pending

- Cross-agent battery green on macOS/Linux/Windows (today only the three Docker batteries exist, all on Linux: sync, hosts and install from scratch).
- Packaging moved here from Phase 3 (slice 3.7): npm launcher and platform packages, Minisign-signed checksums, Homebrew tap, `qbit-vault update` and its opt-out check. Done early (`odd/tasks/public-launch.md`): GoReleaser archives for Linux, macOS and Windows, `checksums.txt`, GitHub build provenance, the release workflow on `v*` tags, and `scripts/install.sh` / `install.ps1` with SHA-256 verification, tested in CI.
- Sync battery green; `qbit-vault-server` image published and deployed once on Dokploy from `deploy/compose.yaml`.
- Security review checklist (THREAT_MODEL.md) walked for every package.
- Docs pass; `README` quickstart verified on a clean VM per OS in < 3 min.
- Tag `v0.1.0`, publish npm with provenance, Homebrew tap formula.
- Make the repository public (it is private today, so `go install` needs access to it).

## TUI — done

User request (2026-11-05, `odd/tasks/polish.md` S5): an interactive terminal app like the ones in engram and gentle-ai. Built in `odd/tasks/tui.md` (T1 af04545, T2 a308062, T3 60f409c, docs T4), reference in `CLI.md` § TUI.

- **Built.** `qbit-vault tui`, and `qbit-vault` with no arguments on a terminal (not with `--json` or `QBIT_VAULT_NO_TUI=1`). First-run splash and setup wizard (`init` with the chosen key storage and hosts). Three-pane home: Secrets (add, edit info, remove, unlock), Grants (list, revoke, revoke all; it cannot grant), Hosts (status, repair, uninstall, register), Audit (recent records, verify the local chain), Sync (status only), Doctor, and Update. Every action runs the real command path in-process; no value is ever shown and values and passphrases are typed only in the suspended prompt.
- **Not exercised.** The suspend and resume of the TUI around the masked prompt on a real terminal: tests replace that step. Leak tests use a fake host adapter, not real host config files.
- **Planned, not built.** Self-update: the Update section is a static screen that shows the manual `go install` command and makes no network call. `qbit-vault update` and the opt-out update check are Phase 5 and need published releases.

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
