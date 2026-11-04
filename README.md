# QBit Vault

**A secrets broker for coding agents: the agent *uses* your credentials, it never *sees* them.**

QBit Vault (`qbit-vault`) lets Pi / Gentle Shell, Claude Code, Codex and OpenCode run commands that need a `GITHUB_TOKEN`, a `DATABASE_URL` or any API key, without the value ever entering the model's context, the chat transcript, the session file or the provider's servers.

- The agent asks for a **handle** (`GITHUB_TOKEN`, with a reason).
- You type the value **out of band** (masked input in the shell, never in the chat).
- The value is stored in an **encrypted local vault**, key in your OS keychain.
- The runtime **injects** it into one child process, **redacts** the output, and returns `{ ok }` to the model.

It integrates with existing agent hosts, including the [Gentle AI](https://github.com/Gentleman-Programming/gentle-ai) setup, and keeps their conventions (deny list, no credentials at install time, versioned contracts, atomic writes with backups, signed releases). QBit Vault is an independent project of the QBit brand; it is not affiliated with or endorsed by the authors of those hosts. Status: the vault, the broker and MCP server, and multi-device sync through the self-hosted `qbit-vault-server` are implemented and tested; host registration (`init` for each agent), the Pi extension and the first release are in progress (docs/ROADMAP.md).

## Install (one command)

```bash
npx qbit-vault@latest init
```

That single command, on macOS, Linux and Windows:

1. Installs the signed `qbit-vault` binary for your platform (no postinstall scripts, checksum-verified).
2. Creates an **empty** encrypted vault at `~/.qbit-vault/` and stores the master key in the OS keychain (passphrase fallback).
3. Detects your agents (`~/.pi/agent`, `~/.gentle-shell/agent`, `~/.claude`, `~/.codex`, OpenCode) and registers the MCP server, hooks and deny-list entries for each one, snapshotting every config file before touching it.
4. Installs the Gentle Shell / Pi extension (`gentle-shell install npm:qbit-vault-pi`).
5. Prints `qbit-vault doctor` so you can see exactly what was configured.

Nothing is asked for at install time. No secret is read from your environment. See [docs/INSTALL.md](docs/INSTALL.md).

Alternatives: `brew install <tap>/qbit-vault`, `curl -fsSL .../install.sh | bash`, `go install github.com/<owner>/qbit-vault/cmd/qbit-vault@latest`.

## Use it from the agent

Just ask for the work. The agent sees four tools:

| Tool | What the model gets back |
| --- | --- |
| `secret_request(name, reason)` | `{ ok, ref: "secret://GITHUB_TOKEN" }` after you typed the value in a masked prompt. Never the value. |
| `secret_list()` | Names, layers, descriptions, scopes, plus the rules of what the agent can and cannot do. Never values. |
| `secret_exec(command, secrets)` or the shell tool itself | Redacted stdout/stderr. The value only existed inside that child process. |

Example session in Gentle Shell:

```
you   > create a release on GitHub for v1.2.0
agent > I need GITHUB_TOKEN to call gh. Requesting it.
        [secret_request GITHUB_TOKEN  reason: "gh release create v1.2.0"]
shell > ┌ qbit-vault ───────────────────────────────┐
        │ GITHUB_TOKEN  for: gh release create v1.2.0 │
        │ value: ●●●●●●●●●●●●●●●●●●●●                 │
        │ grant: [this command] [30 min] [this repo]  │
        └─────────────────────────────────────────────┘
agent > [bash gh release create v1.2.0 --notes-file CHANGELOG.md]   ← runs via qbit-vault exec
        Release created: https://github.com/you/repo/releases/tag/v1.2.0
```

| `secret_manage(action, name, ...)` | Proposes remove / edit / move / replace. You confirm or decline outside the chat; the agent gets `{ ok }`. |

Next time the agent needs `GITHUB_TOKEN` it asks only for a **grant**, not the value. See [docs/AGENT_INTEGRATIONS.md](docs/AGENT_INTEGRATIONS.md).

## Global and project secrets

Every secret is **global** (usable everywhere) or belongs to **one project** (repository). A project secret overrides a global one with the same name, so `DATABASE_URL` can differ per repo. Project secrets live in the same encrypted vault in `~/.qbit-vault/`, never inside the repository.

You can always add them yourself, no agent needed:

```bash
qbit-vault set GITHUB_TOKEN --global     # masked prompt
cd ~/code/shop-api && qbit-vault set DATABASE_URL --project
qbit-vault list                          # what this directory sees, never values
```

In Pi / Gentle Shell the same is `/vault set NAME`.

## What makes it hold

1. **Transcript**: values never appear in tool results, messages or session files.
2. **Output**: every stdout/stderr passes a redaction filter; `env`, `printenv`, `set`, `/proc/*/environ` are refused while secrets are injected.
3. **Disk**: the vault, project paths and grants are encrypted at rest with a key that lives in your OS keychain; a copied `~/.qbit-vault/` is useless without it. Writing a literal secret through the agent's write/edit tools is blocked or rewritten to a reference.
4. **Prompt injection**: grants have scope and TTL; per-secret allowlists of binaries/hosts; first use per session always confirms.
5. **Accidental paste**: secret-shaped text typed into the chat is intercepted before it reaches the model and offered to the vault instead.

Full analysis: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Documentation map

| Document | What it is |
| --- | --- |
| [docs/PRD.md](docs/PRD.md) | Requirements with stable IDs (R-xxx), scope, non-goals |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, attackers, leak paths, controls, residual risk |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flows, process model, decisions |
| [contracts/secrets-broker/v1/CONTRACT.md](contracts/secrets-broker/v1/CONTRACT.md) | The `gentle-ai.secrets-broker/v1` wire contract and refusals |
| [docs/STORAGE.md](docs/STORAGE.md) | Vault file format, crypto, keychain, grants, audit log |
| [docs/CLI.md](docs/CLI.md) | Every command, flag and exit code |
| [docs/AGENT_INTEGRATIONS.md](docs/AGENT_INTEGRATIONS.md) | MCP server, hooks and capture path per agent |
| [docs/GENTLE_SHELL_EXTENSION.md](docs/GENTLE_SHELL_EXTENSION.md) | The Pi / Gentle Shell extension (`qbit-vault-pi`) |
| [docs/INSTALL.md](docs/INSTALL.md) | What `init` does, step by step, and how to undo it |
| [docs/TESTING.md](docs/TESTING.md) | Test tiers, leak tests, cross-agent battery |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phased delivery in ≤400-line PR slices |
| [AGENTS.md](AGENTS.md) | Instructions for the coding agent building this repo |

## Status and relationship to Gentle AI

Proposed to the Gentle AI maintainers as a companion package first (`qbit-vault` Go core + `qbit-vault-pi` Gentle Shell extension), with a later `gentle-ai install --components vault` path if adopted. The proposal text is in [qbit-vault-proposal.md](qbit-vault-proposal.md).

## License

MIT. "Gentle AI" and "Gentle Shell" are trademarks of their respective owner; this project is a community companion and implies no endorsement.
