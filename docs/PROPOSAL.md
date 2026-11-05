# Proposal: QBit Vault (`qbit-vault`) — a secrets broker so agents can *use* credentials without ever *seeing* them

**Type:** Idea / design discussion (pre-issue, per the issue-first workflow)
**Scope:** gentle-ai component candidate + Gentle Shell companion package
**Status of the work:** Nothing built yet. This is a request for direction before any code exists.

## The gap

Gentle AI already covers the *negative* half of credential safety:

- The permissions component ships a sensitive-paths deny list (`~/.ssh/*`, `**/.env*`, `~/.aws/credentials`, `**/*.pem`, `**/*.key`, ...).
- PRD R-MCP-04: the installer never stores or requests API keys, tokens or credentials.
- The always-installed remote-authorization boundary: local-development access does not authorize reuse of ambient credentials, SSH agents or sessions.

What does not exist is the *positive* half: a sanctioned way for an agent to **use** a `GITHUB_TOKEN`, a `DATABASE_URL` or a provider key **without the value ever entering the model's context**. Today, when an agent needs to run `gh`, a migration or a deploy, the realistic paths are:

1. the secret sits in the ambient shell env (the agent sees it with `env`; the deny list does not cover that),
2. the user pastes it into the chat (it lands in the transcript, the session file and the provider), or
3. the user leaves the agent and does the step by hand.

The deny list closes the door. Nothing opens a window. `qbit-vault` is that window, built on the same rules.

## Principle

> The agent requests a *handle*, the human supplies the *value* out of band, the runtime *injects* it into a bounded child process, and the model only ever sees `{ ok, ref, grant }` plus redacted output.

No tool result, message, log or session file ever carries a secret value. Secrets are not *read* by agents; they are *used* by the runtime on the agent's behalf, under an explicit grant.

## How it stays aligned with Gentle AI's rules

| Existing rule | What `qbit-vault` does about it |
| --- | --- |
| Installer never requests or stores credentials (R-MCP-04) | `install`/`sync` only create an **empty** encrypted store and register adapters. Capture happens exclusively at runtime, on an explicit user action, never during setup, never from the environment. |
| Sensitive-paths deny list | The vault directory is **added** to the deny list for every agent. The vault is an encrypted file (XChaCha20-Poly1305 / AES-GCM) with the master key in the OS keychain (passphrase + Argon2id fallback). The vault is never a `.env`. |
| Remote-authorization boundary | Made mechanical: no inheritance from ambient env, no inheritance to subagents without their own grant, per-process injection with TTL, optional per-secret scopes (allowed binaries / hosts). |
| Bounded, versioned capabilities (`review-integration/v2`, `sdd-research-capability/v1`) | A declared contract from day one: `gentle-ai.secrets-broker/v1` with `request/v1`, `grant/v1`, `exec/v1`, `revoke/v1`, typed refusals, consumers reject envelopes they do not understand. |
| Backups before every write, atomic mutations (`filemerge`) | Atomic vault writes (tmp + rename), encrypted snapshot before each mutation, agent-config changes (hooks, MCP entries, deny-list additions) go through the same backup path. |
| Explicit TUI consent, local telemetry opt-out | Every capture and every grant requires an explicit confirmation. The audit log (who asked for what, when, why, which command used it) is local and append-only; nothing leaves the machine. |
| Signed releases, pinned versions, no postinstall | Minisign-signed checksums, npm provenance, zero postinstall, one audited crypto dependency. |
| Pi is owned by Gentle Shell; Claude Code / Codex / OpenCode by gentle-ai | Core + MCP server in Go (gentle-ai side); UX extension in TypeScript as a Gentle Shell companion package, like `gentle-engram`. |

## Architecture

```
qbit-vault (Go — same stack as gentle-ai)
├── core      encrypted store, keychain, grants, scopes, audit
├── CLI       qbit-vault init | set | list | revoke | exec | doctor
├── MCP       stdio server → Claude Code, Codex, OpenCode, Pi (native MCP since v4)
└── adapters  per-agent hooks + deny-list additions, via backup + atomic merge

gentle-shell companion (TypeScript)
└── extension masked inline capture (ctx.ui), bash override with env injection,
    output redaction, paste interception, audit widget in the sidebar
    (talks to the core over CLI/MCP; never opens the vault itself)
```

### Agent-facing surface (v1)

- `secret_request(name, reason, scope?)` → if missing, opens an **out-of-band masked prompt** (TUI input in Gentle Shell; native OS dialog or elicitation elsewhere). Returns `{ ok, ref }`, never the value.
- `secret_list()` → names, descriptions, scopes, timestamps. Never values.
- `secret_exec` / `bash` override → detects references (`{{secret:ns/name}}` or declared env names), asks for a grant if none is active (this command / this session (TTL) / this repo), runs the child with the value injected **only** into that process, and returns **redacted** output.

### Controls that make it hold

1. **Transcript**: values never appear in tool results, messages or session files.
2. **Command output**: every stdout/stderr (and `read`/`write` payloads) passes a redaction filter for active secrets; dump commands (`env`, `printenv`, `set`, `/proc/self/environ`) are refused while secrets are injected.
3. **Disk**: writing a literal secret through `write`/`edit` is blocked or rewritten to a reference; an optional pre-commit scanner is installed by the same command.
4. **Prompt injection**: per-secret scopes, TTL grants, explicit confirmation on first use per session, mandatory confirmation for secrets marked `sensitive`.
5. **Accidental paste**: `pi.on("input")` (and `UserPromptSubmit` on Claude Code) detects secret-shaped input before it reaches the model and offers to store it as a reference instead.

### Install

```
npx qbit-vault init            # or: gentle-ai install --components vault (if adopted)
gentle-shell install npm:qbit-vault
```

Detects installed agents, creates the empty store, keychain-backs the master key, registers hooks/MCP entries and deny-list additions through the backup path. Nothing is asked for at install time.

## Questions for maintainers

1. **Shape**: companion package first (`qbit-vault` repo, Go core + Gentle Shell extension) with a later `gentle-ai install --components vault` path, or would you rather see it proposed directly as a component inside this repo?
2. **Contract**: is `gentle-ai.secrets-broker/v1` the right place in the capability taxonomy, and should it live under `contracts/` alongside `review-integration`?
3. **R-MCP-04 wording**: would you accept an explicit clarification that the rule governs *install/sync time* and that runtime capture under explicit user consent is in scope?
4. **Backends**: v1 = local encrypted store + OS keychain. Pluggable backends (`op://`, `pass`, Infisical) later. Objections to that order?
5. **Naming**: `qbit-vault` follows the `gentle-*` convention; happy to use whatever fits the trademark policy.

If the direction is welcome, I will open a Feature Request issue scoped to the v1 contract and threat model (≤400-line PR slices, issue-first), and start the companion repo.

---
*Disclosure: this proposal was drafted with material AI assistance and reviewed and owned by me, per AI_POLICY.md.*
