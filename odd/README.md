# odd/: development logs

`odd/tasks/` holds the work logs of QBit Vault: for each part of the product, how it was specified, built and tested, one file per feature. The specification itself is in [docs/](../docs/) and [contracts/](../contracts/secrets-broker/v1/CONTRACT.md); these logs are **not user documentation**. To use the tool, start at the [README](../README.md).

## What a task file holds

| Section | Content |
| --- | --- |
| Specs (`S1`, `S2`, ...) | What was asked, with the author's words quoted verbatim, and the requirements it maps to |
| Tasks | A table of task IDs, which specs they serve, how each was routed, its commit and its status |
| Log (`L1`, `L2`, ...) | Decisions, discoveries, test evidence (RED/GREEN), review outcomes and commit hashes |

## Why they are in the repository

- They are the evidence behind the statuses in [docs/ROADMAP.md](../docs/ROADMAP.md) (the commit hashes come from here).
- They record why a choice was made when the code alone does not say.
- They are history: a file keeps the wording of its time (branch names such as `feat/cli-skeleton`, the earlier product name in `rename-qbit.md`). When a task file and the code disagree, the code and `docs/` win.

## Index of `odd/tasks/`

Foundations (roadmap Phase 1):

| File | What it records |
| --- | --- |
| [cli-skeleton.md](tasks/cli-skeleton.md) | Repository skeleton: Go module, cobra CLI, `--json`, exit codes, the redacting `Secret` type, CI with the leak grep |
| [vault-core.md](tasks/vault-core.md) | Encrypted vault core: AEAD envelope, atomic writes, backups, rollback counter, global and project layers |
| [keychain.md](tasks/keychain.md) | Master key in the OS keychain, Argon2id passphrase fallback, unlock cache |
| [cli-secrets.md](tasks/cli-secrets.md) | `set`, `rm`, `list`, `describe`, `edit`, `mv`, `relink` and file permissions |
| [audit.md](tasks/audit.md) | The hash-chained audit log and `audit --verify` |
| [grants.md](tasks/grants.md) | Grants (`once`, `session`, `project`), prompt tokens, `grant` / `revoke` / `grants` |
| [redact.md](tasks/redact.md) | Streaming multi-encoding redaction |
| [exec.md](tasks/exec.md) | `exec`: injection into one child, dump guard, binary allowlist |
| [tty-prompt.md](tasks/tty-prompt.md) | The terminal prompt backend and the prompt token |
| [native-prompt.md](tasks/native-prompt.md) | Native dialogs: PowerShell, osascript, zenity, kdialog |
| [vault-ops.md](tasks/vault-ops.md) | `import`, `rekey`, `lock` / `unlock`, `restore` |
| [global-project-layers.md](tasks/global-project-layers.md) | Spec change: global and project layers, agent-managed vault, manual entry |

Contract, hosts and sync:

| File | What it records |
| --- | --- |
| [broker.md](tasks/broker.md) | Contract v1 as code: broker, `request`, `manage`, the MCP server |
| [hosts.md](tasks/hosts.md) | Registering Claude Code, Codex and Pi: `init`, `sync`, `doctor`, `uninstall`, hooks; OpenCode dropped |
| [agent-skill.md](tasks/agent-skill.md) | The `qbit-vault` agent skill, installed by `init` and kept current by `sync` |
| [remote-sync-spec.md](tasks/remote-sync-spec.md) | Spec change: zero-knowledge sync, multi-field requests, the audit anchor |
| [remote-sync.md](tasks/remote-sync.md) | The sync client and `qbit-vault-server`, slices S.1 to S.10 |
| [remote-sync-hardening.md](tasks/remote-sync-hardening.md) | Open minors closed after the sync review |
| [backup-recovery.md](tasks/backup-recovery.md) | The server on Dokploy and the encrypted offline `export` / `import --from-export` |

Product, interface and launch:

| File | What it records |
| --- | --- |
| [rename-qbit.md](tasks/rename-qbit.md) | The rename from gentle-vault to QBit Vault |
| [dogfood-1.md](tasks/dogfood-1.md) | Fixes from the first real use on Windows |
| [prompt-ux.md](tasks/prompt-ux.md) | Clearer capture dialogs, replace-and-grant in one decision, value checks |
| [polish.md](tasks/polish.md) | Repository polish, visual identity, README, TUI design |
| [tui.md](tasks/tui.md) | The interactive terminal app |
| [launch-prep.md](tasks/launch-prep.md) | Preparing the repository for a public launch |
| [public-launch.md](tasks/public-launch.md) | Going public: release binaries and the one-line installers |
| [pending-round.md](tasks/pending-round.md) | The round after the public beta: WSL friction at `init`, review follow-ups |
| [launch-polish.md](tasks/launch-polish.md) | The pre-launch audit and its step-by-step plan |
| [post-launch.md](tasks/post-launch.md) | Post-launch fixes, the full documentation pass, repository cleanup, demo assets and the 1.0.0 release |

## Where to look

| If you want to know | Read |
| --- | --- |
| How the product works | [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md), [docs/CLI.md](../docs/CLI.md) |
| What is built and what is planned | [docs/ROADMAP.md](../docs/ROADMAP.md), [docs/PRD.md](../docs/PRD.md) § 0 |
| Why the sync design is what it is | `tasks/remote-sync-spec.md`, then [docs/REMOTE_SYNC.md](../docs/REMOTE_SYNC.md) |
| Why the product is called QBit Vault | `tasks/rename-qbit.md` |
| The latest work (TUI, polish, launch preparation) | `tasks/tui.md`, `tasks/polish.md`, `tasks/launch-prep.md` |

Contributors do not need to add a file here. A maintainer may open one for a larger feature.
