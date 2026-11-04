# Roadmap and delivery plan

Sliced so every PR stays ≤ 400 changed lines (Gentle AI's review budget), each with code + tests + docs. Phases are sequential; slices within a phase are mostly parallelizable. IDs refer to `docs/PRD.md`.

## Phase 0 — alignment (no code)

- [ ] Discussion opened in gentle-ai (done: `gentle-vault-proposal.md`).
- [ ] Decide repo location from maintainer feedback (companion repo vs. in-tree).
- [ ] Reserve names: npm `gentle-vault`, `gentle-vault-pi`, `@gentle-vault/cli-*`; Go module path.

## Phase 1 — core vault (CLI only, no hosts)

| Slice | Content | Req |
| --- | --- | --- |
| 1.1 | Repo skeleton, cobra CLI, `--json`, exit codes, `Secret` type with redacting `String/Format/MarshalJSON`, CI with leak grep | AGENTS.md |
| 1.2 | `vault`: envelope, XChaCha20-Poly1305, atomic write, backups, rollback counter; `global`/`projects` body and name resolution | R-VAULT-01,04,07,09, R-LAYER-01..03 |
| 1.3 | `keychain`: go-keyring backend + passphrase/Argon2id fallback + cached unlock | R-VAULT-02 |
| 1.4 | `set --stdin`, `rm`, `list`, `describe`, `edit` with `--global`/`--project`, permissions enforcement | R-VAULT-03,05,06, R-CAP-07 |
| 1.4a | `mv`, `relink`, `list --layer` | R-LAYER-04,05 |
| 1.5 | `audit`: hash chain, `--verify`, event writers | R-AUD-* |
| 1.6 | `grants`: encrypted `grants.enc`, (name, layer) binding, scopes, TTL, project root resolution, `grant`/`revoke`/`grants` (TTY-only) | R-GRANT-01,02,04,06 |
| 1.7 | `redact`: streaming multi-encoding + fuzz | R-RED-01..03 |
| 1.8 | `exec`: env build/scrub, dump-guard from `dumpguard.yaml`, binary allowlist, timeout, pgroup, `--stream` | R-EXEC-* |
| 1.9 | `prompt`: tty backend + prompt token; `set` interactive | R-CAP-01,04 |
| 1.10 | `prompt`: osascript, powershell, zenity/kdialog backends | R-CAP-01 |
| 1.11 | `import --from-env/--from-file`, `rekey`, `lock/unlock`, `restore` | R-VAULT-08 |

Exit criterion: a human can `set`, `grant` and `exec` end-to-end on all three OSes with the leak battery green.

## Phase 2 — contract and MCP

| Slice | Content | Req |
| --- | --- | --- |
| 2.1 | `broker` package implementing all ops + refusals; `broker --op` CLI; schema validation | CONTRACT.md |
| 2.2 | `request` with existence non-disclosure, layer choice, reason heuristic, rate limit; `list` with `policy` | R-API-02,03,06, R-CAP-02,03a,05 |
| 2.2a | `manage` op: remove/edit/move/replace, prompt token, widening labels, cooldown | R-API-07,08 |
| 2.2b | Multi-field `request`: `fields` with `kind`/`label`, `refs` response, tokens bound to several names, `set --stdin --fields`, `prompt --field`; record `kind` | R-API-02, R-CAP-08,09, R-VAULT-06 |
| 2.2c | Multi-field rendering in every prompt backend (PowerShell form, zenity `--forms`, consecutive boxes for osascript, kdialog and tty) | R-CAP-08, AGENT_INTEGRATIONS |
| 2.3 | `mcp` stdio server, four tools, normative descriptions, `policy` as server `instructions`, `grant` refusal | R-API-01,05,06 |
| 2.4 | Contract conformance test harness | TESTING.md |

## Phase 2S — remote sync (`REMOTE_SYNC.md`)

Runs after Phase 2 so the contract is settled; S.1 can land earlier because it only changes the local body.

| Slice | Content | Req |
| --- | --- | --- |
| S.1 | Body schema 2 and migration: project ids, per-device `roots`, `device_id`, `kind`, `hlc`, tombstones; `link`; `list --layer all` marks unlinked layers; `keys/retired.enc` with `rekey`/`restore` | R-SYNC-11, STORAGE |
| S.2 | `internal/merge`: pure three-way merge, conflicts, roster rules, fuzz and property tests | R-SYNC-07 |
| S.3 | `internal/remote` crypto: key derivations, device keys, recovery key format, key and recovery envelopes, remote vault object with padding, anchors, pairing and confirmation codes (pure, test vectors) | R-SYNC-02,04 |
| S.4 | `internal/server` core: file store, accounts and invites, device auth (challenge, token), vault CAS and last 10 versions, limits and rate limits, logging rules | R-SYNC-02,03 |
| S.5 | Server pairing, recovery, atomic `rekey`/revoke, anchors endpoints | R-SYNC-04,06,10 |
| S.6 | Packaging: `cmd/gentle-vault-server` (`serve`, `invite`), Dockerfile (static, non-root, read-only), `deploy/compose.yaml` for Dokploy, release jobs | R-SYNC-12 |
| S.7 | Client transport and `remote register` / `join` (pairing and `--recovery`) / `approve` / `logout`, all user-only through the prompt backend | R-SYNC-01,03,04,05 |
| S.8 | Sync rounds wired into mutating and reading commands, pending pushes, `remote sync` / `status` / `devices`, `--json` `remote` field, `doctor` | R-SYNC-07,09 |
| S.9 | `remote revoke-device`, `recovery-key --rotate`, rekey with sync, `conflicts` / `resolve`, `history` / `restore`, `audit --verify` anchors | R-SYNC-06,10 |
| S.10 | E2E sync battery in Docker (three clients, rollback server, leak grep of `/data` and HTTP bodies) | TESTING.md |

Exit criterion: TESTING.md Tier 2 step 7 green; a secret set on one OS is usable on another after `join`; the server volume holds no fixture value, name or path.

## Phase 3 — hosts

| Slice | Content | Req |
| --- | --- | --- |
| 3.1 | `filemerge`: snapshot + atomic JSON/TOML merge + 3-way revert | R-INS-04 |
| 3.2 | Claude Code adapter: MCP entry, hooks (`pre-bash`, `post`, `user-prompt`; `pre-bash` refuses `gentle-vault` mutating, `remote` and `link` subcommands in the agent's shell), deny-list, Gentle AI preservation check | R-HOST-02, R-INS-05, R-SYNC-05 |
| 3.3 | Codex adapter (MCP, sandbox → tty prompt) | R-HOST-03 |
| 3.4 | OpenCode adapter (MCP + plugin when available) | R-HOST-04 |
| 3.5 | Pi (plain) adapter: MCP entry + extension install | R-HOST-01 |
| 3.6 | `init`, `sync`, `doctor`, `uninstall`, `state.json` receipts | R-INS-* |
| 3.7 | npm launcher + platform packages + goreleaser + Minisign | R-INS-02, R-NFR-03 |

## Phase 4 — Gentle Shell extension (`gentle-vault-pi`)

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

## Phase 5 — hardening and release 0.1.0

- Cross-agent battery green on macOS/Linux/Windows.
- Sync battery green; `gentle-vault-server` image published and deployed once on Dokploy from `deploy/compose.yaml`.
- Security review checklist (THREAT_MODEL.md) walked for every package.
- Docs pass; `README` quickstart verified on a clean VM per OS in < 3 min.
- Tag `v0.1.0`, publish npm with provenance, Homebrew tap formula, `install.sh`/`install.ps1`.

## v2 candidates (not scheduled)

- Egress control for exec children (per-command network namespace / proxy) to close R1.
- Pluggable backends: `op://`, `pass`, Infisical, HashiCorp Vault; team sharing (several users on one sync server sharing selected secrets).
- File injection for secrets that tools read from a path (SSH keys, kubeconfig) without plaintext on disk (pipe or memory-backed file).
- Enforced host allowlist through a brokered `secret_http` call (today `hosts` is advisory).
- Biometric or OS-level confirmation (Touch ID, Windows Hello) for grants, against same-user UI automation (THREAT_MODEL R9).
- Project grants and project layers keyed by git remote.
- Keyed-hash secret names in the audit log (THREAT_MODEL R6).
- `gentle-ai install --components vault` native integration; contract moved under gentle-ai `contracts/`.
- Browser-based capture for remote/SSH sessions.
- Secret-rotation hooks (`gentle-vault rotate NAME --via gh auth refresh`).
