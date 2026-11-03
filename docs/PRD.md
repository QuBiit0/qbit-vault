# PRD: gentle-vault

Version 0.1 (design). Requirement IDs are stable; reference them from issues, PRs and tests.

## 1. Problem statement

Coding agents routinely need credentials to finish real work: `gh` needs a token, migrations need a database URL, deploys need provider keys. Today the only ways to supply them are all leaks:

- the value sits in the ambient shell environment, where the agent can read it with `env` and any prompt-injected command can exfiltrate it;
- the user pastes it into the chat, where it enters the transcript, the on-disk session file and the model provider's servers;
- the user interrupts the agent and performs the step by hand, which defeats the point of having an agent.

Gentle AI already blocks the *reading* of credential files through its sensitive-paths deny list and refuses to store credentials at install time. There is no sanctioned path for an agent to *use* a credential without seeing it. gentle-vault provides that path.

## 2. Goals

- G1. An agent can complete a task that needs a credential without the credential value ever entering its context, transcript, session file or provider request.
- G2. Supplying a credential takes the user one masked input and one grant decision, inside the same terminal session, with no context switch.
- G3. Installation is one command on macOS, Linux and Windows and configures every supported agent that is present.
- G4. The design is adoptable by Gentle AI as a native component without rewrite: same language, same contract style, same mutation and release discipline.
- G5. Pi / Gentle Shell gets the richest experience (inline masked input, shell-tool override, sidebar audit); Claude Code, Codex and OpenCode get a functionally equivalent one through MCP and hooks.
- G6. Secrets are organized in a **global** layer (used everywhere) and **project** layers (bound to one repository), managed with the same few commands by the user and, with user confirmation, by the agent.
- G7. The agent can always learn, in one call, exactly what it may and may not do with the vault.

## 3. Non-goals (v1)

- Team or multi-user sharing of secrets.
- Remote or third-party backends (1Password, Bitwarden, Infisical, HashiCorp Vault, cloud secret managers). The backend interface is defined so these can be added in v2.
- Secret rotation, expiry of the values themselves, or leak detection in external services.
- A long-running daemon. v1 is a stateless CLI plus a stdio MCP server started by the host.
- Browser-based capture page.
- Auto-approval policies ("always allow X without asking"). Grants are explicit; the broadest v1 grant is "this repository until revoked", chosen by the user in the prompt.
- Protecting against a fully compromised user account or kernel. See `THREAT_MODEL.md` § Out of scope.

## 4. Personas and primary flows

**Solo developer running an agent in a terminal** (the v1 persona).

- F1 *First use*: agent needs `GITHUB_TOKEN`; vault has none; user types it in a masked prompt; chooses grant scope; command runs; output is redacted.
- F2 *Reuse*: agent needs `GITHUB_TOKEN` in a new session; vault has it; user is asked only for a grant.
- F3 *Accidental paste*: user pastes `ghp_…` into the chat; the extension intercepts it before the model sees it and offers to store it as `secret://GITHUB_TOKEN`.
- F4 *Inspection*: user runs `gentle-vault list` / `audit` to see names, layers, scopes and who used what, when.
- F7 *Manual entry*: user runs `gentle-vault set DATABASE_URL --project` (or `/vault set` in Pi) and types the value in a masked prompt, with no agent involved.
- F8 *Agent-proposed management*: agent calls `secret_manage(move, DATABASE_URL, to: project, reason)`; user sees the proposal out of band and confirms or declines; the agent only learns `ok` or `user_declined`.
- F9 *Project override*: `DATABASE_URL` exists globally and in repo A; commands in repo A use A's value, everywhere else the global one.
- F5 *Revocation*: user runs `gentle-vault revoke GITHUB_TOKEN` (grant) or `gentle-vault rm GITHUB_TOKEN` (value).
- F6 *Uninstall*: `gentle-vault uninstall` restores every agent config from its snapshot and optionally deletes the vault.

## 5. Functional requirements

### 5.1 Vault

- R-VAULT-01. Secrets MUST be stored in a single encrypted file at `$GENTLE_VAULT_HOME/vault.enc` (default `~/.gentle-vault/`), using an AEAD cipher (XChaCha20-Poly1305) with a per-write random nonce. See `STORAGE.md`.
- R-VAULT-02. The master key MUST be stored in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). When no keychain is available, the key MUST be wrapped with a user passphrase using Argon2id and stored at `$GENTLE_VAULT_HOME/key.enc`.
- R-VAULT-03. The vault file, key file, grants file and audit log MUST be created with mode `0600` (owner-only ACL on Windows).
- R-VAULT-04. Every write MUST be atomic (write temp file in the same directory, fsync, rename) and MUST be preceded by an encrypted snapshot to `$GENTLE_VAULT_HOME/backups/`.
- R-VAULT-05. Secret names MUST match `^[A-Z][A-Z0-9_]{0,63}$` so that a name is always a valid environment variable name on every platform.
- R-VAULT-06. Each secret record MUST carry: name, layer (`global` or `project`), description (optional), created_at, updated_at, `sensitive` flag, allowed `binaries` (list of executable base names; empty = any), allowed `hosts` (list of hostnames; empty = any; advisory in v1, see R-EXEC-08).
- R-VAULT-07. The vault MUST never store the value in any derived or cached form outside the encrypted file (no index, no search cache, no clipboard).
- R-VAULT-08. `init` and `sync` MUST NOT read, import or copy any value from the process environment, from `.env` files or from other credential stores. Importing is an explicit `gentle-vault import` the user runs with a path.
- R-VAULT-09. Everything except the cleartext envelope header MUST be encrypted at rest: values, names, descriptions, project roots and grants. A copy of `$GENTLE_VAULT_HOME` without the master key MUST reveal no secret value and no secret name outside the audit log (see `STORAGE.md` § What a leaked directory reveals).

### 5.1a Layers

- R-LAYER-01. Every secret belongs to exactly one layer: `global`, or `project` bound to one repository root (resolved with `git rev-parse --show-toplevel`, else the nearest ancestor containing `.git`).
- R-LAYER-02. The same name MAY exist in the global layer and in any number of project layers. Resolution for a `cwd` is: the project layer of the repository containing `cwd`, else the global layer, else `unknown_secret`.
- R-LAYER-03. Project layers MUST be stored inside `vault.enc` in `$GENTLE_VAULT_HOME`, never inside the repository, so they cannot be committed.
- R-LAYER-04. `request` and `set` outside a repository MUST only offer the global layer. Asking for the project layer there is refused with `no_project`.
- R-LAYER-05. Moving a secret between layers (`mv`, `manage move`) MUST keep its value and metadata, MUST drop its grants, and MUST ask before overwriting an existing secret with the same name in the target layer.

### 5.2 Capture (out-of-band input)

- R-CAP-01. The value MUST be captured through a channel the model cannot observe: Pi/Gentle Shell `ctx.ui.custom` masked input; otherwise a native dialog (macOS `osascript` with hidden answer, Windows PowerShell `Read-Host -AsSecureString` in a separate window, Linux `zenity --password` / `kdialog --password`), with a final fallback of reading from `/dev/tty` (or `CONIN$`) with echo disabled.
- R-CAP-02. The prompt MUST show the secret name and the agent-supplied reason, so the user can judge whether the request is legitimate.
- R-CAP-03. The prompt MUST offer the grant scope choices (R-GRANT-02) in the same interaction so a first use costs exactly one prompt.
- R-CAP-03a. The capture prompt MUST also offer the layer choice (`global` / `this project`) when `cwd` is inside a repository, defaulting to the agent's `suggested_layer` or `global`.
- R-CAP-04. Blank or whitespace-only input MUST fail the capture without writing anything. Surrounding whitespace MUST be trimmed. Cancel MUST leave the vault unchanged.
- R-CAP-05. Capture MUST be rate-limited per session (default: a refused or cancelled request for the same name cannot be re-asked for 60 s) to blunt prompt-injection loops that nag the user.
- R-CAP-06. The extension MUST intercept user input that matches known secret patterns (GitHub `ghp_`/`github_pat_`, OpenAI `sk-`, AWS `AKIA`, Slack `xox`, Stripe `sk_live`, private key PEM blocks, JWTs, and high-entropy strings ≥ 32 chars when preceded by `=` or `:`) **before** it reaches the model, and offer to store it as a named secret, replacing the text with its reference.
- R-CAP-07. The user MUST be able to add or replace a value manually, without any agent request: `gentle-vault set NAME [--global|--project]` in any terminal and `/vault set NAME` in Pi / Gentle Shell. Both use the same masked capture (R-CAP-01) and never accept the value as an argument. Inside a repository with neither flag, the prompt asks for the layer.

### 5.3 Grants

- R-GRANT-01. A grant binds (secret name, layer, session id, scope, expiry). A grant for the global `NAME` does not cover a project `NAME`, and the reverse. No exec may inject a secret without an active grant.
- R-GRANT-02. Scopes: `once` (this exec only), `session` (this host session, default TTL 30 min, configurable), `project` (this repository root until revoked; survives sessions). Secrets flagged `sensitive` MUST only accept `once`.
- R-GRANT-03. A grant MUST be created only from an explicit user confirmation delivered through the host UI or the native prompt. The MCP tool surface MUST NOT be able to create a grant on its own.
- R-GRANT-04. Grants MUST be persisted (metadata only, no values), encrypted with the master key, at `$GENTLE_VAULT_HOME/grants.enc` so that a host restart does not silently widen or narrow access.
- R-GRANT-05. Subagents MUST NOT inherit grants. A subagent is a different session id and must obtain its own.
- R-GRANT-06. `gentle-vault revoke <name> [--all]` and `gentle-vault revoke --session <id>` MUST take effect immediately for any later exec.

### 5.4 Exec (injection)

- R-EXEC-01. `gentle-vault exec --session <id> --secret NAME[=ENV] ... -- <command>` MUST run `<command>` as a child process whose environment is the parent environment **minus** any variable already named like a vault secret, **plus** the granted values. The value MUST NOT be exported to the parent.
- R-EXEC-02. The host-side shell tool (Pi `bash` override, Claude Code `PreToolUse` hook) MUST rewrite a command that references a known secret (`$NAME`, `${NAME}`, `%NAME%`, `$env:NAME`, `{{secret:NAME}}`) into a `gentle-vault exec` invocation. A reference to a name with no active grant MUST trigger the grant prompt (R-GRANT-03), not a silent empty variable.
- R-EXEC-03. While any secret is injected, the command MUST be refused (typed refusal `dump_command`) if it matches the dump-command list: `env`, `printenv`, `set` (bare), `export -p`, `declare -x`, `cat|less|more /proc/*/environ`, `Get-ChildItem Env:`, `gci env:`, `[Environment]::GetEnvironmentVariables()`, `echo $NAME`/`echo %NAME%`/`Write-Output $env:NAME` where NAME is injected. The list MUST be a data file, not code, so it can be extended without a release.
- R-EXEC-04. stdout and stderr MUST be streamed through the redactor (R-RED-01) before being returned to the host.
- R-EXEC-05. The child's exit code MUST be propagated unchanged.
- R-EXEC-06. Exec MUST audit each invocation in two phases (R-AUD-01). Before the child starts, an `exec` record with `outcome: "started"` (session, secret names, layer, command redacted, cwd) is appended; if that append fails, exec is refused (`internal`) and nothing runs (fail-closed). After the child ends, an `exec` record with `outcome: "finished"` carries exit code, duration and redaction count; it is best effort (a failed append prints a warning to stderr). `once` grants are consumed before the child starts, so a failed run still uses the grant.
- R-EXEC-07. When the secret's `binaries` allowlist is non-empty, the program of **every** pipeline or sequence segment of the command (after resolving the wrappers `sudo`, `env`, `command`, `exec`, `nohup`, `time`, `npx`, `bunx`, `pnpm exec|dlx`, `yarn dlx`, `uv run`, `uvx`, `poetry run`, and `sh -c` style shells) MUST be in the list, because the injected environment reaches every process the shell starts; shell builtins that start no process are exempt. Otherwise typed refusal `scope_binary`, naming the secret whose list was violated.
- R-EXEC-08. `hosts` is advisory in v1: exec logs a warning in the audit record when the command text contains a hostname not in the list. Network-level enforcement is a v2 item.
- R-EXEC-09. Exec MUST honor a wall-clock timeout (default 10 min, flag `--timeout`) and kill the process group on expiry.

### 5.5 Redaction

- R-RED-01. The redactor MUST replace, in any byte stream it is given, every active secret value and its encodings: raw, base64 (standard and URL-safe, with and without padding), percent-encoded, JSON-escaped, and the value with surrounding quotes stripped. Replacement token: `[REDACTED:NAME]`.
- R-RED-02. The redactor MUST work on streams (chunk boundaries must not defeat it): keep a sliding buffer of at least the longest active value's encoded length.
- R-RED-03. Values shorter than 8 bytes MUST still be redacted but MUST log an audit warning that short secrets produce false positives.
- R-RED-04. Host adapters MUST also run the agent's file `read` results through the redactor while a grant is active (Pi: tool_result hook; Claude Code: `PostToolUse` on `Read`).

### 5.6 Agent-facing surface

- R-API-01. The broker MUST expose exactly four agent-callable tools in v1: `secret_request`, `secret_list`, `secret_exec`, `secret_manage`. Tool names are identical across hosts.
- R-API-02. `secret_request(name, reason, suggested_scope?, suggested_layer?)` returns `{ ok, ref, grant: {scope, expires_at} }` or a typed refusal. It never returns a value, and it never returns whether the value *exists* before the user has confirmed (to avoid enumeration by prompt injection): the user prompt shows "already stored, grant only?" vs "new value" but the model only learns `ok`.
- R-API-03. `secret_list()` returns names and metadata only for the secrets visible from `cwd`: the current project layer plus global secrets not overridden by it, each marked with its layer. It MUST also return a `policy` block (R-API-06).
- R-API-06. The `policy` block MUST state, as fixed normative text from `CONTRACT.md`, what the agent can do (request, list, exec, propose management) and cannot do (read values, grant itself, skip confirmation, print the environment while secrets are injected, use a secret outside its allowlist), plus the current project root or `null`, the available scopes and layers, and the active cooldowns by name. The MCP server MUST ship the same text as its server `instructions`.
- R-API-07. `secret_manage(action, name, layer, reason, changes?, to?)` lets the agent **propose** `remove`, `edit` (description, binaries, hosts, sensitive), `move` (between global and the current project) or `replace` (new value captured out of band). Every action MUST open a user confirmation through the capture channel (R-CAP-01) showing the action, name, layer, the diff of changes and the reason. Nothing is applied without that confirmation. The agent only receives `{ ok, applied }` or a typed refusal, never a value.
- R-API-08. `secret_manage` MUST NOT create a grant, widen a grant, or clear the `sensitive` flag without the confirmation stating it explicitly in the prompt. It follows the same per-name cooldown as `request` (R-CAP-05).
- R-API-04. `secret_exec(command, secrets: [{name, env?}], cwd?, timeout?)` is the portable fallback for hosts without a shell-tool hook. It behaves exactly as R-EXEC-*.
- R-API-05. Tool descriptions shipped to the model MUST state plainly that values are never returned and that requesting a secret without a concrete reason will be refused by the user.

### 5.7 Hosts

- R-HOST-01. Pi / Gentle Shell: the extension `gentle-vault-pi` MUST provide masked capture, bash override, read/write redaction, paste interception, `/vault` commands and a sidebar audit widget. See `GENTLE_SHELL_EXTENSION.md`.
- R-HOST-02. Claude Code: `init` MUST register the MCP server (`claude mcp add` or `~/.claude/settings.json` merge), a `PreToolUse` hook on `Bash` that rewrites to `exec` and enforces the dump-command list, a `PostToolUse` hook on `Bash`/`Read` for redaction, a `UserPromptSubmit` hook for paste interception, and add `$GENTLE_VAULT_HOME` to the `permissions.deny` read list.
- R-HOST-03. Codex: `init` MUST register the MCP server in `~/.codex/config.toml`. Capture uses the native dialog. Exec is through `secret_exec` only.
- R-HOST-04. OpenCode: `init` MUST register the MCP server in the OpenCode config and, where the OpenCode plugin API offers `tool.execute.before/after`, install a plugin for bash rewrite and redaction; otherwise `secret_exec` only.
- R-HOST-05. Every host registration MUST be reversible by `gentle-vault uninstall` using the snapshots taken at registration time.

### 5.8 Audit

- R-AUD-01. An append-only JSONL log at `$GENTLE_VAULT_HOME/audit.jsonl` MUST record: capture (name, layer, session, reason, `by: agent|user`), grant (name, layer, session, scope, expiry), exec (R-EXEC-06), manage (action, name, layer, session, reason, outcome), refusal (type, name, session), revoke, rm, mv. Never values.
- R-AUD-02. Each record MUST include the SHA-256 of the previous record (hash chain) so tampering is detectable by `gentle-vault audit --verify`.
- R-AUD-03. The log MUST never leave the machine. No telemetry in v1.

### 5.9 Install, sync, doctor, uninstall

- R-INS-01. `npx gentle-vault@latest init` MUST complete the whole setup (R-INS-02..06) with no further input on a machine with a working keychain; it MUST ask exactly one question (passphrase) where no keychain exists.
- R-INS-02. The npm launcher MUST have no `postinstall`. Platform binaries MUST ship as `optionalDependencies` (`@gentle-vault/cli-darwin-arm64`, etc.) and be verified against a checksum embedded in the launcher before first run.
- R-INS-03. `init` MUST detect installed agents by their config directories and register only those present, unless `--agents` is given.
- R-INS-04. Every config file `init` touches MUST be snapshotted first to `$GENTLE_VAULT_HOME/backups/<timestamp>/<path>` and written atomically with a merge that preserves unrelated keys.
- R-INS-05. `init` MUST add `$GENTLE_VAULT_HOME/**` to each agent's file-read deny list where the agent supports one, and MUST verify that the Gentle AI permissions component's deny list, when present, is not weakened.
- R-INS-06. `init` MUST finish by running `doctor` and printing its report.
- R-INS-07. `doctor` MUST be read-only and report: binary version and signature status, vault present/locked/unlocked, keychain backend in use, per-agent registration status (MCP, hooks, deny-list), extension version for Pi, active grants count, audit chain validity.
- R-INS-08. `sync` MUST re-apply registrations idempotently after a host or gentle-vault upgrade.
- R-INS-09. `uninstall` MUST restore all snapshots, remove the extension, and leave the vault in place unless `--purge` is given, which requires typing the word `purge`.

## 6. Non-functional requirements

- R-NFR-01 *Portability*: macOS (arm64, amd64), Linux (amd64, arm64, including WSL2 and headless without Secret Service), Windows 10+ (amd64). Headless Linux uses the passphrase fallback.
- R-NFR-02 *Latency*: `exec` overhead ≤ 50 ms over running the command directly on a warm keychain; prompt round-trip is user-bound.
- R-NFR-03 *Supply chain*: releases signed (Minisign) with `checksums.txt`; npm packages published with provenance; version pinning in every config `init` writes; no postinstall; dependency set listed in `AGENTS.md` and enforced by a CI check.
- R-NFR-04 *Observability*: `--json` on every command for host adapters; human output otherwise.
- R-NFR-05 *Compatibility*: contract `gentle-ai.secrets-broker/v1` is frozen on first stable release; additive changes bump the minor capability version; consumers refuse unknown major versions.
- R-NFR-06 *Testing*: leak tests on every tier (see `TESTING.md`); a PR touching exec/redact/prompt/mcp/hooks without extending the leak test is rejected by CI.

## 7. Success criteria for v1

- A user can go from nothing to "agent created a GitHub release using a token it never saw" in under 3 minutes on all three OSes.
- The leak test battery passes with zero secret bytes in any captured transcript, log, session file or tool result across Pi, Claude Code, Codex and OpenCode.
- Gentle AI maintainers can read `CONTRACT.md` and `ARCHITECTURE.md` and identify where it would slot into `internal/components/` without asking design questions.

## 8. Open questions

- Q1. Should `project` grants and project layers be keyed by git remote URL instead of filesystem root, so a re-clone keeps them? (Decided for v1: root path. `gentle-vault relink OLD NEW` moves a project layer and its grants to a new checkout path. Remote keying stays a v2 candidate.)
- Q2. Should `secret_list` be hidden from the model entirely and exposed only to the user via `/vault list`? (Leaning: keep it; the agent needs to know which handles exist to avoid re-asking.)
- Q3. Windows native prompt: PowerShell window vs. a tiny Go/Win32 dialog. (Leaning: PowerShell for v1, zero extra dependencies.)
