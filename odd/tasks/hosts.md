# Feature: roadmap Phase 3, hosts

Register qbit-vault with the coding agents (Claude Code, Codex, OpenCode, Pi) safely: snapshotted, atomic, reversible config edits, hooks, `init`/`sync`/`doctor`/`uninstall`, packaging.
Branch `feat/cli-skeleton`. Spec authority: docs/ROADMAP.md § Phase 3, docs/PRD.md (R-INS-*, R-HOST-*, R-SYNC-05, R-NFR-03), docs/AGENT_INTEGRATIONS.md, docs/INSTALL.md, docs/STORAGE.md, docs/CLI.md, AGENTS.md.

## Specs

- S1. User (2026-11-04): "Cerrar minors de 2S y después Fase 3"; "vamos con todo".
- S2. ROADMAP Phase 3 rows 3.1-3.7 (quoted there): 3.1 "`filemerge`: snapshot + atomic JSON/TOML merge + 3-way revert"; 3.2 "Claude Code adapter: MCP entry, hooks (`pre-bash`, `post`, `user-prompt`; `pre-bash` refuses `qbit-vault` mutating, `remote` and `link` subcommands in the agent's shell), deny-list, Gentle AI preservation check"; 3.3 "Codex adapter (MCP, sandbox → tty prompt)"; 3.4 "OpenCode adapter (MCP + plugin when available)"; 3.5 "Pi (plain) adapter: MCP entry + extension install"; 3.6 "`init`, `sync`, `doctor`, `uninstall`, `state.json` receipts"; 3.7 "npm launcher + platform packages + goreleaser + Minisign".
- S3. PRD R-INS-04: "Every config file `init` touches MUST be snapshotted first to `backups/<timestamp>/<path>` and written atomically with a merge that preserves unrelated keys"; R-INS-06 "`init` MUST finish by running `doctor`"; R-INS-07 `doctor` "MUST be read-only"; R-INS-08 "`sync` MUST re-apply registrations idempotently"; R-INS-09 "`uninstall` MUST restore all snapshots… `--purge` requires typing the word `purge`"; AGENTS.md invariants 7 and 8.
- S4. Decision (user, 2026-11-04): TOML for `~/.codex/config.toml` is a minimal in-house editor: "Solo agrego/reemplazo/borro nuestra tabla [mcp_servers.qbit-vault] como texto; el resto del archivo del usuario queda byte a byte igual, comentarios incluidos. Sin dependencia nueva."
- S5. Decision (user): Pi extension: "init configura el MCP de Pi y muestra `pi install npm:qbit-vault-pi` para que lo corras vos. El invariante 8 queda intacto."
- S6. Decision (user): broken hook: "Fail-open: el comando corre sin reescritura y el agente ve un aviso. Los secretos igual nunca están en el entorno del agente; un hook roto no bloquea todo tu trabajo."
- S7. Parent decisions (doc contradictions found by exploration): hook subcommand names follow CLI.md (`hook pre-bash`, `hook post-bash`, `hook post-read`, `hook user-prompt`); receipts in state.json use absolute paths (no `~`, Windows-portable); the Claude deny entry uses the resolved vault home, not a literal `~/.qbit-vault`; JSON merges preserve the user's key order and formatting outside our keys; a hooks slice (bindings.yaml, dumpguard loading, `hook` subcommands) is added before 3.2.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| P1 | S2-S4, S7 | worker | 3.1 `internal/filemerge`: snapshot to backups, atomic write, order-preserving JSON merge/unmerge of owned keys, TOML table editor, 3-way revert | | pending |
| P2 | S2, S3, S7 | worker | 3.6a `state.json` hosts receipts, `init` step runner (idempotent, re-runs host steps on an existing vault), minimal read-only `doctor` | | pending |
| P3 | S2, S6, S7 | worker | hooks: `hook pre-bash/post-bash/post-read/user-prompt`, bindings, refusal of mutating/remote/link subcommands, fail-open | | pending |
| P4 | S2, S3, S7 | worker | 3.2 Claude Code adapter (MCP, hooks, deny-list, Gentle AI preservation) | | pending |
| P5 | S2, S4 | worker | 3.3 Codex adapter (TOML, sandbox -> tty) | | pending |
| P6 | S2 | worker | 3.4 OpenCode adapter (MCP; plugin when available) | | pending |
| P7 | S2, S5 | worker | 3.5 Pi adapter (MCP entry, printed install command) | | pending |
| P8 | S2, S3 | worker | 3.6b `sync`, `uninstall` (+ `--purge`), full `doctor` (incl. sync conflicts) | | pending |
| P9 | S2 | worker | 3.7 npm launcher, platform packages, goreleaser, Minisign | | pending |

## Log

- L1. User answers (verbatim choices): TOML "Editor mínimo propio (Recomendado)"; Pi "Imprime el comando (Recomendado)"; broken hook "Deja pasar y avisa (Recomendado)".
- L2. Exploration (gentle-ai-explore): nothing host-side exists; `init` is vault-only and returns early on an existing vault; no `hook`, `doctor`, `sync`, `uninstall`, `filemerge`, `bindings.yaml`, `packages/` or goreleaser. Order: P1 and P2 first, P3 before P4, P4-P7 independent of each other after P1-P3, P8 after an adapter exists, P9 independent.
