# PRD: QBit Vault (`qbit-vault`)

Version 0.1. Requirement IDs are stable; reference them from issues, PRs and tests. The requirements are normative: a requirement is met unless a *Status* note says otherwise.

## 0. Implementation status

Built and tested on `main` (evidence in `ROADMAP.md`): the vault, layers, grants, audit, redaction, `exec`, the native prompts, the contract broker and MCP server (§§ 5.1–5.6, 5.8), the sync client and server (§ 5.10, `REMOTE_SYNC.md`), and host registration for **Claude Code, Codex and Pi / Gentle Shell** (§ 5.7, 5.9). Not built:

- the Pi extension `qbit-vault-pi` (Phase 4): R-HOST-01, the Pi parts of R-CAP-01 and R-CAP-06, R-RED-04 and R-EXEC-02 on Pi; `set --stdin --fields` and `prompt --field` (R-CAP-08 is met by the broker for MCP hosts);
- the Claude Code `PreToolUse` rewrite of secret references into `exec` (R-EXEC-02) and its `grant_required` / `dump_command` denials; today `pre-bash` only keeps user-only commands out of the agent's shell;
- the npm launcher, signed releases, `install.sh`/Homebrew and `qbit-vault update` (Phase 5): R-INS-01 as worded, R-INS-02, R-NFR-03, the binary-signature part of R-INS-07;
- OpenCode (R-HOST-04): dropped by a recorded decision (`odd/tasks/hosts.md` S8);
- self-update, in the TUI or as `qbit-vault update` (Phase 5): the TUI's Update section is a static *planned* screen.

Also built, outside the numbered requirements of this document: the interactive TUI (`qbit-vault tui`, and `qbit-vault` with no arguments on a terminal; `CLI.md` § TUI, `ROADMAP.md`). It is a front end over the existing commands and keeps their invariants (no value shown, values typed only in the prompt backend, grants revoke-only). Not exercised: its suspend and resume around the masked prompt on a real terminal.

Pre-release from `v0.1.0-beta.2`. Install with the `install.sh` / `install.ps1` one-liners (release archive, SHA-256 verified), `go install github.com/QuBiit0/qbit-vault/cmd/qbit-vault@latest`, or from source (`INSTALL.md`).

## 1. Problem statement

Coding agents routinely need credentials to finish real work: `gh` needs a token, migrations need a database URL, deploys need provider keys. Today the only ways to supply them are all leaks:

- the value sits in the ambient shell environment, where the agent can read it with `env` and any prompt-injected command can exfiltrate it;
- the user pastes it into the chat, where it enters the transcript, the on-disk session file and the model provider's servers;
- the user interrupts the agent and performs the step by hand, which defeats the point of having an agent.

Agent harnesses can already block the *reading* of credential files through deny lists and refuse to store credentials at install time. There is no sanctioned path for an agent to *use* a credential without seeing it. qbit-vault provides that path.

## 2. Goals

- G1. An agent can complete a task that needs a credential without the credential value ever entering its context, transcript, session file or provider request.
- G2. Supplying a credential takes the user one masked input and one grant decision, inside the same terminal session, with no context switch.
- G3. Installation is one command on macOS, Linux and Windows and configures every supported agent that is present. (Today: the `install.sh` / `install.ps1` one-liners or `go install`, then `qbit-vault init`; the `npx` launcher is Phase 5.)
- G4. The design is embeddable by any agent harness without rewrite: one static binary, a versioned contract, snapshot-first config mutation and a documented release discipline.
- G5. Pi / Gentle Shell gets the richest experience (inline masked input, shell-tool override, sidebar audit; the extension is Phase 4); Claude Code and Codex get a functionally equivalent one through MCP and, for Claude Code, hooks. OpenCode is out of scope.
- G6. Secrets are organized in a **global** layer (used everywhere) and **project** layers (bound to one repository), managed with the same few commands by the user and, with user confirmation, by the agent.
- G7. The agent can always learn, in one call, exactly what it may and may not do with the vault.
- G8. The same vault works on several machines and is backed up off the machine through a self-hosted, zero-knowledge sync server (`qbit-vault-server`), with no scripts and no plaintext leaving a device. See `REMOTE_SYNC.md`.
- G9. When a task needs several values (host, user and password of a database), the agent asks once and the user fills every box in one prompt; fields that are not secret (a hostname) are visible while typed, secret ones are masked.

## 3. Non-goals (v1)

- Team or multi-user sharing of secrets.
- Third-party backends (1Password, Bitwarden, Infisical, HashiCorp Vault, cloud secret managers). The backend interface is defined so these can be added in v2. qbit-vault's own sync server (G8) is in v1; it stores ciphertext only and is not a backend in this sense.
- Secret rotation, expiry of the values themselves, or leak detection in external services.
- A long-running daemon on the user's machine. v1 is a stateless CLI plus a stdio MCP server started by the host; sync runs inside the commands that change or read the vault (`REMOTE_SYNC.md` § 7.1). The sync server is a separate, optional deployment.
- Browser-based capture page.
- Auto-approval policies ("always allow X without asking"). Grants are explicit; the broadest v1 grant is "this repository until revoked", chosen by the user in the prompt.
- Protecting against a fully compromised user account or kernel. See `THREAT_MODEL.md` § Out of scope.

## 4. Personas and primary flows

**Solo developer running an agent in a terminal** (the v1 persona).

- F1 *First use*: agent needs `GITHUB_TOKEN`; vault has none; user types it in a masked prompt; chooses grant scope; command runs; output is redacted.
- F2 *Reuse*: agent needs `GITHUB_TOKEN` in a new session; vault has it; user is asked only for a grant.
- F3 *Accidental paste*: user pastes `ghp_…` into the chat; the host intercepts it before the model sees it. Claude Code (built): the `user-prompt` hook blocks the prompt and tells the user to store it with `qbit-vault set`. Pi (Phase 4): the extension offers to store it as `secret://GITHUB_TOKEN` and replaces the text.
- F4 *Inspection*: user runs `qbit-vault list` / `audit` to see names, layers, scopes and who used what, when.
- F7 *Manual entry*: user runs `qbit-vault set DATABASE_URL --project` (or `/vault set` in Pi) and types the value in a masked prompt, with no agent involved.
- F8 *Agent-proposed management*: agent calls `secret_manage(move, DATABASE_URL, to: project, reason)`; user sees the proposal out of band and confirms or declines; the agent only learns `ok` or `user_declined`.
- F9 *Project override*: `DATABASE_URL` exists globally and in repo A; commands in repo A use A's value, everywhere else the global one.
- F5 *Revocation*: user runs `qbit-vault revoke GITHUB_TOKEN` (grant) or `qbit-vault rm GITHUB_TOKEN` (value).
- F6 *Uninstall*: `qbit-vault uninstall` restores every agent config from its snapshot and optionally deletes the vault.
- F10 *Several fields*: agent needs a database; it calls `secret_request` once with `DB_HOST` (text), `DB_USER` (text) and `DB_PASSWORD` (secret); the user fills three boxes in one dialog and picks one scope; the agent gets three references.
- F11 *First sync*: user runs `qbit-vault remote register --server https://vault.example.com`, types the invite code, writes down the recovery key; every later change syncs on its own.
- F12 *Second machine*: user runs `qbit-vault init` and `qbit-vault remote join --server …` on the new machine, then `qbit-vault remote approve` on the old one and types the codes each one shows; the new machine has every secret. In a repository it already had, `qbit-vault link <label>` binds the project layer to the local checkout.
- F13 *Lost machine*: from another device, `qbit-vault remote revoke-device <id>` removes it and rotates the master key and the recovery key; with no device left, `remote join --recovery` and the recovery key restore the vault.

## 5. Functional requirements

### 5.1 Vault

- R-VAULT-01. Secrets MUST be stored in a single encrypted file at `$QBIT_VAULT_HOME/vault.enc` (default `~/.qbit-vault/`), using an AEAD cipher (XChaCha20-Poly1305) with a per-write random nonce. See `STORAGE.md`.
- R-VAULT-02. The master key MUST be stored in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). When no keychain is available, the key MUST be wrapped with a user passphrase using Argon2id and stored at `$QBIT_VAULT_HOME/key.enc`.
- R-VAULT-03. The vault file, key file, grants file and audit log MUST be created with mode `0600` (owner-only ACL on Windows).
- R-VAULT-04. Every write MUST be atomic (write temp file in the same directory, fsync, rename) and MUST be preceded by an encrypted snapshot to `$QBIT_VAULT_HOME/backups/`.
- R-VAULT-05. Secret names MUST match `^[A-Z][A-Z0-9_]{0,63}$` so that a name is always a valid environment variable name on every platform.
- R-VAULT-06. Each secret record MUST carry: name, layer (`global` or `project`), `kind` (`secret`, masked at capture, or `text`, visible at capture; both are stored, injected and redacted alike and never returned), description (optional), created_at, updated_at, `sensitive` flag, allowed `binaries` (list of executable base names; empty = any), allowed `hosts` (list of hostnames; empty = any; advisory in v1, see R-EXEC-08).
- R-VAULT-07. The vault MUST never store the value in any derived or cached form outside the encrypted file (no index, no search cache, no clipboard).
- R-VAULT-08. `init` and `sync` MUST NOT read, import or copy any value from the process environment, from `.env` files or from other credential stores. Importing is an explicit `qbit-vault import` the user runs with a path.
- R-VAULT-09. Everything except the cleartext envelope header MUST be encrypted at rest: values, names, descriptions, project roots and grants. A copy of `$QBIT_VAULT_HOME` without the master key MUST reveal no secret value and no secret name outside the audit log (see `STORAGE.md` § What a leaked directory reveals).

### 5.1a Layers

- R-LAYER-01. Every secret belongs to exactly one layer: `global`, or `project` bound to one repository root (resolved with `git rev-parse --show-toplevel`, else the nearest ancestor containing `.git`).
- R-LAYER-02. The same name MAY exist in the global layer and in any number of project layers. Resolution for a `cwd` is: the project layer of the repository containing `cwd`, else the global layer, else `unknown_secret`.
- R-LAYER-03. Project layers MUST be stored inside `vault.enc` in `$QBIT_VAULT_HOME`, never inside the repository, so they cannot be committed.
- R-LAYER-04. `request` and `set` outside a repository MUST only offer the global layer. Asking for the project layer there is refused with `no_project`.
- R-LAYER-05. Moving a secret between layers (`mv`, `manage move`) MUST keep its value and metadata, MUST drop its grants, and MUST ask before overwriting an existing secret with the same name in the target layer.

### 5.2 Capture (out-of-band input)

- R-CAP-01. The value MUST be captured through a channel the model cannot observe: Pi/Gentle Shell `ctx.ui.custom` masked input; otherwise a native dialog (macOS `osascript` with hidden answer, a Windows PowerShell WinForms dialog with a masked box in a separate window, Linux `zenity --entry --hide-text` / `kdialog --password`), with a final fallback of reading from `/dev/tty` (or `CONIN$`) with echo disabled.
- R-CAP-02. The prompt MUST show the secret name and the agent-supplied reason, so the user can judge whether the request is legitimate.
- R-CAP-03. The prompt MUST offer the grant scope choices (R-GRANT-02) in the same interaction so a first use costs exactly one prompt.
- R-CAP-03a. The capture prompt MUST also offer the layer choice (`global` / `this project`) when `cwd` is inside a repository, defaulting to the agent's `suggested_layer` or `global`.
- R-CAP-04. Blank or whitespace-only input MUST fail the capture without writing anything. Surrounding whitespace MUST be trimmed. Cancel MUST leave the vault unchanged. In a capture of several fields this is all-or-nothing: one blank field, a cancel or a timeout writes none of them. A typed value that starts and ends with the same quote, or holds invisible characters (zero-width, BOM, no-break space, soft hyphen), MUST be pointed out before it is saved, offering the value without them (preselected), the value as typed, or cancel; a clean value asks nothing more.
- R-CAP-05. Capture MUST be rate-limited per session (default: a refused or cancelled request for the same name cannot be re-asked for 60 s) to blunt prompt-injection loops that nag the user.
- R-CAP-06. *Status: Claude Code built (the `user-prompt` hook blocks a prompt with a stored value or a well-known secret shape; it does not offer to store it and has no generic high-entropy match); Pi extension Phase 4.* The extension MUST intercept user input that matches known secret patterns (GitHub `ghp_`/`github_pat_`, OpenAI `sk-`, AWS `AKIA`, Slack `xox`, Stripe `sk_live`, private key PEM blocks, JWTs, and high-entropy strings ≥ 32 chars when preceded by `=` or `:`) **before** it reaches the model, and offer to store it as a named secret, replacing the text with its reference.
- R-CAP-08. One capture MUST be able to ask for 1 to 8 fields under a single reason, a single layer choice and a single scope choice (R-API-02). Fields already stored are shown as stored and get no box; the model is not told which ones were. The offered scopes are those every field allows (a `sensitive` field limits all of them to `once`). Every backend renders the fields in one interaction: one form where the backend has forms (Pi, PowerShell, zenity `--forms`), otherwise consecutive boxes in the same prompt, where cancelling any box cancels the whole capture.
- R-CAP-09. A `text` field MUST be visible while typed and a `secret` field masked; nothing else differs. The kind is chosen by the agent's request and shown to the user, who can still cancel; an agent that marks a secret as `text` only makes it visible on the user's own screen.
- R-CAP-07. The user MUST be able to add or replace a value manually, without any agent request: `qbit-vault set NAME [--global|--project]` in any terminal and `/vault set NAME` in Pi / Gentle Shell. Both use the same masked capture (R-CAP-01) and never accept the value as an argument. Inside a repository with neither flag, the prompt asks for the layer.

### 5.3 Grants

- R-GRANT-01. A grant binds (secret name, layer, session id, scope, expiry). A grant for the global `NAME` does not cover a project `NAME`, and the reverse. No exec may inject a secret without an active grant.
- R-GRANT-02. Scopes: `once` (this exec only), `session` (this host session, default TTL 12 h, configurable; preselected in the approval dialog whenever the record allows it, unless the user named another scope on their own command line), `project` (this repository root until revoked; survives sessions; for a global secret, the repository the user approved it in). A `session` grant ends when the agent restarts, since a restarted MCP server is a new session; the dialog says so. Inside a repository the agent's dialogs (`request`, and `manage` replace) offer instead `12 hours: in this project, even if the agent restarts`: a `project` grant that expires after the default session TTL, so restarts do not ask again. A `project` grant may carry such an end; one without it lasts until revoked. Secrets flagged `sensitive` MUST only accept `once`.
- R-GRANT-03. A grant MUST be created only from an explicit user confirmation delivered through the host UI or the native prompt. The MCP tool surface MUST NOT be able to create a grant on its own.
- R-GRANT-04. Grants MUST be persisted (metadata only, no values), encrypted with the master key, at `$QBIT_VAULT_HOME/grants.enc` so that a host restart does not silently widen or narrow access.
- R-GRANT-05. Subagents MUST NOT inherit grants. A subagent is a different session id and must obtain its own.
- R-GRANT-06. `qbit-vault revoke <name> [--all]` and `qbit-vault revoke --session <id>` MUST take effect immediately for any later exec.

### 5.4 Exec (injection)

- R-EXEC-01. `qbit-vault exec --session <id> --secret [ENV=]NAME ... -- <command>` MUST run `<command>` as a child process whose environment is the parent environment **minus** any variable already named like a vault secret, **plus** the granted values. The value MUST NOT be exported to the parent.
- R-EXEC-02. *Status: not built (Claude Code rewrite and Pi bash override); MCP hosts use `secret_exec`.* The host-side shell tool (Pi `bash` override, Claude Code `PreToolUse` hook) MUST rewrite a command that references a known secret (`$NAME`, `${NAME}`, `%NAME%`, `$env:NAME`, `{{secret:NAME}}`) into a `qbit-vault exec` invocation. A reference to a name with no active grant MUST trigger the grant prompt (R-GRANT-03), not a silent empty variable.
- R-EXEC-03. While any secret is injected, the command MUST be refused (typed refusal `dump_command`) if it matches the dump-command list: `env`, `printenv`, `set` (bare), `export -p`, `declare -x`, `cat|less|more /proc/*/environ`, `Get-ChildItem Env:`, `gci env:`, `[Environment]::GetEnvironmentVariables()`, `echo $NAME`/`echo %NAME%`/`Write-Output $env:NAME` where NAME is injected. The list MUST be a data file, not code, so it can be extended without a release. The list also covers bare `export`, `declare`/`typeset` (bare, `-p`, or naming an injected variable), `compgen -e|-v`, any read of `/proc/<self|pid|$$|$BASHPID>/environ`, `find -exec env|printenv`, `${!var}` indirection, here-strings and here-documents that reference an injected name, interpreter one-liners that read the environment (awk, perl, python, node, ruby), `$env:NAME` anywhere and `Get-Content env:`, cmd `set PREFIX` and `%NAME:~0,5%`; wrappers (`nice`, `timeout`, `stdbuf`, `strace`, `chroot`, `ionice`, `setsid`, `doas`, `xargs`, `sudo`, `env`, ...) are resolved before matching. Under `--shell cmd|pwsh` the raw command is tested too. Only `${#NAME}` (the length expansion) is not a dump; counter pipes (`| wc -c`), PowerShell `$env:NAME.Length` and digests of the value stay refused, because a text guard cannot see `set -x`, redefined commands or PowerShell's argument parsing. On Windows a bare `bash` or `sh` never resolves to WSL's launcher (CLI.md § Exec). This is a best-effort layer (THREAT_MODEL R1, R2).
- R-EXEC-04. stdout and stderr MUST be streamed through the redactor (R-RED-01) before being returned to the host.
- R-EXEC-05. The child's exit code MUST be propagated unchanged.
- R-EXEC-06. Exec MUST audit each invocation in two phases (R-AUD-01). Before the child starts, an `exec` record with `outcome: "started"` (session, secret names, layer, command redacted, cwd) is appended; if that append fails, exec is refused (`internal`) and nothing runs (fail-closed). After the child ends, an `exec` record with `outcome: "finished"` carries exit code, duration and redaction count; it is best effort (a failed append prints a warning to stderr). A `once` grant is claimed atomically just before the child is started and spent only if the process is actually created: a command refused before that (dump guard, allowlist, usage, no POSIX shell on Windows) or one that cannot start leaves the grant usable (the claim is given back and the `finished` record says `not started`), while a child that starts and fails, times out or is interrupted keeps it spent.
- R-EXEC-07. When the secret's `binaries` allowlist is non-empty, the program of **every** pipeline or sequence segment of the command (after resolving the wrappers `sudo`, `env`, `command`, `exec`, `nohup`, `time`, `npx`, `bunx`, `pnpm exec|dlx`, `yarn dlx`, `uv run`, `uvx`, `poetry run`, and `sh -c` style shells) MUST be in the list, because the injected environment reaches every process the shell starts; shell builtins that start no process are exempt. A wrapper flag the parser does not know, or a short-flag cluster it cannot read with certainty (`strace -fQ`, `sudo --foo bar`), makes the segment ambiguous and the command is refused with `scope_binary`; the dump guard also tests such a segment with the wrapper and its words removed at every split point. Under `--shell cmd|pwsh` (after resolving `auto`) the segmentation does not apply, so with a non-empty `binaries` list only a single simple command (no chaining, quoting or substitution characters of that shell) is accepted. Otherwise typed refusal `scope_binary`, naming the secret whose list was violated.
- R-EXEC-08. `hosts` is advisory in v1: exec logs a warning in the audit record when the command text contains a hostname not in the list. Network-level enforcement is a v2 item.
- R-EXEC-09. Exec MUST honor a wall-clock timeout (default 10 min, flag `--timeout`) and kill the process group on expiry.

### 5.5 Redaction

- R-RED-01. The redactor MUST replace, in any byte stream it is given, every active secret value and its encodings: raw, base64 (standard and URL-safe, with and without padding), percent-encoded, JSON-escaped, and the value with surrounding quotes stripped. Replacement token: `[REDACTED:NAME]`.
- R-RED-02. The redactor MUST work on streams (chunk boundaries must not defeat it): keep a sliding buffer of at least the longest active value's encoded length.
- R-RED-03. Values shorter than 8 bytes MUST still be redacted but MUST log an audit warning that short secrets produce false positives.
- R-RED-04. Host adapters MUST also run the agent's file `read` results through the redactor while a grant is active (Pi: tool_result hook; Claude Code: `PostToolUse` on `Read`).

### 5.6 Agent-facing surface

- R-API-01. The broker MUST expose exactly four agent-callable tools in v1: `secret_request`, `secret_list`, `secret_exec`, `secret_manage`. Tool names are identical across hosts.
- R-API-02. `secret_request(name | fields[], reason, suggested_scope?, suggested_layer?)` returns `{ ok, refs: [{name, ref, layer}], grant: {scope, expires_at} }` (plus `ref` and `layer` when a single `name` was asked) or a typed refusal. `fields` holds 1 to 8 `{name, kind?, label?, description?}` (R-CAP-08). It never returns a value, and it never returns whether the value *exists* before the user has confirmed (to avoid enumeration by prompt injection): the user prompt shows "already stored, grant only?" vs "new value" but the model only learns `ok`.
- R-API-03. `secret_list()` returns names and metadata only for the secrets visible from `cwd`: the current project layer plus global secrets not overridden by it, each marked with its layer. It MUST also return a `policy` block (R-API-06).
- R-API-06. The `policy` block MUST state, as fixed normative text from `CONTRACT.md`, what the agent can do (request, list, exec, propose management) and cannot do (read values, grant itself, skip confirmation, print the environment while secrets are injected, use a secret outside its allowlist), plus the current project root or `null`, the available scopes and layers, and the active cooldowns by name. The MCP server MUST ship the same text as its server `instructions`.
- R-API-07. `secret_manage(action, name, layer, reason, changes?, to?)` lets the agent **propose** `remove`, `edit` (description, binaries, hosts, sensitive), `move` (between global and the current project) or `replace` (new value captured out of band). Every action MUST open a user confirmation through the capture channel (R-CAP-01) showing the action, name, layer, the diff of changes and the reason. Nothing is applied without that confirmation. The agent only receives `{ ok, applied }` or a typed refusal, never a value.
- R-API-08. `secret_manage` MUST NOT create a grant, widen a grant, or clear the `sensitive` flag without the confirmation stating it explicitly in the prompt. It follows the same per-name cooldown as `request` (R-CAP-05).
- R-API-04. `secret_exec(command, secrets: [{name, env?}], cwd?, timeout?)` is the portable fallback for hosts without a shell-tool hook. It behaves exactly as R-EXEC-*.
- R-API-05. Tool descriptions shipped to the model MUST state plainly that values are never returned and that requesting a secret without a concrete reason will be refused by the user.

### 5.7 Hosts

- R-HOST-01. *Status: Phase 4, not built; today `init` registers Pi's MCP entry and prints the extension install command.* Pi / Gentle Shell: the extension `qbit-vault-pi` MUST provide masked capture, bash override, read/write redaction, paste interception, `/vault` commands and a sidebar audit widget. See `GENTLE_SHELL_EXTENSION.md`.
- R-HOST-02. Claude Code: `init` MUST register the MCP server (a `~/.claude.json` merge), a `PreToolUse` hook on `Bash`/`PowerShell` that rewrites to `exec` and enforces the dump-command list, a `PostToolUse` hook on `Bash`/`PowerShell`/`Read` for redaction, a `UserPromptSubmit` hook for paste interception, and add `$QBIT_VAULT_HOME` to the `permissions.deny` read list. *Status: built, except that the `PreToolUse` hook does not rewrite or apply the dump guard yet; it keeps user-only `qbit-vault` commands out of the agent's shell (R-SYNC-05).*
- R-HOST-03. Codex: `init` MUST register the MCP server in `~/.codex/config.toml`. Capture uses the native dialog. Exec is through `secret_exec` only.
- R-HOST-04. *Status: dropped (`odd/tasks/hosts.md` S8); no OpenCode adapter exists and none is planned for 0.1.* OpenCode: `init` MUST register the MCP server in the OpenCode config and, where the OpenCode plugin API offers `tool.execute.before/after`, install a plugin for bash rewrite and redaction; otherwise `secret_exec` only.
- R-HOST-05. Every host registration MUST be reversible by `qbit-vault uninstall` using the snapshots taken at registration time.

### 5.8 Audit

- R-AUD-01. An append-only JSONL log at `$QBIT_VAULT_HOME/audit.jsonl` MUST record: capture (name, layer, session, reason, `by: agent|user`), grant (name, layer, session, scope, expiry), exec (R-EXEC-06), manage (action, name, layer, session, reason, outcome), refusal (type, name, session), revoke, rm, mv. Never values.
- R-AUD-02. Each record MUST include the SHA-256 of the previous record (hash chain) so tampering is detectable by `qbit-vault audit --verify`.
- R-AUD-03. The log MUST never leave the machine. No telemetry in v1. With sync enabled, only an encrypted digest of the log's head (sequence number and line hash) is uploaded, so tampering with the local log becomes detectable (R-SYNC-10).

### 5.9 Install, sync, doctor, uninstall

- R-INS-01. `qbit-vault init` MUST complete the whole setup (R-INS-03..06) with no further input on a machine with a working keychain. Where no keychain exists, `init` falls back to the passphrase mode of R-VAULT-02 (two prompts) and says so; with no way to prompt it fails naming `--passphrase --passphrase-stdin`. The `npx qbit-vault@latest init` form is Phase 5; today the binary comes from `go install`.
- R-INS-02. *Status: Phase 5, not built (no `packages/`).* The npm launcher MUST have no `postinstall`. Platform binaries MUST ship as `optionalDependencies` (`@qbit-vault/cli-darwin-arm64`, etc.) and be verified against a checksum embedded in the launcher before first run.
- R-INS-03. `init` MUST detect installed agents by their config directories and register only those present, unless `--agents` is given.
- R-INS-04. Every config file `init` touches MUST be snapshotted first to `$QBIT_VAULT_HOME/backups/<timestamp>/<path>` and written atomically with a merge that preserves unrelated keys.
- R-INS-05. `init` MUST add `$QBIT_VAULT_HOME/**` to each agent's file-read deny list where the agent supports one, and MUST verify that deny entries other tools put there, when present, are not weakened. *Status: Claude Code gets Read and Edit deny rules; Codex and Pi get none (their adapters write only the MCP entry). Existing entries survive because the merge touches only entries qbit-vault owns (golden and e2e tests); there is no separate verify-and-abort step.*
- R-INS-06. `init` MUST finish by running `doctor` and printing its report.
- R-INS-07. `doctor` MUST be read-only and report: binary version and signature status, vault present/locked/unlocked, keychain backend in use, per-agent registration status (MCP, hooks, deny-list), extension version for Pi, active grants count, audit chain validity, and with sync enabled the server, last sync, pending push, conflicts, generation and anchor state (without contacting the server). *Status: built are vault state and keychain mode, permissions, per-step host registration and drift, the audit chain and the grants store (the last two only when broken), and the sync line (server, devices, conflicts, pending push, last round). Not built: binary version/signature, Pi extension version, the active grants count, generation and anchor state.*
- R-INS-08. `sync` MUST re-apply registrations idempotently after a host or qbit-vault upgrade.
- R-INS-09. `uninstall` MUST restore all snapshots, and leave the vault in place unless `--purge` is given, which requires typing the word `purge`.

### 5.10 Remote sync

Normative protocol: `REMOTE_SYNC.md`.

- R-SYNC-01. Sync MUST be opt-in (`qbit-vault remote register` or `remote join`). Without it qbit-vault makes no network call beyond those of AGENTS.md invariant 8.
- R-SYNC-02. The server MUST be zero-knowledge: it stores only ciphertext sealed on the device, public keys, counters and timestamps. No key that decrypts a vault object is ever sent to it, and authentication to it uses keys independent of the encryption keys.
- R-SYNC-03. The client MUST refuse a server URL that is not `https://`, except loopback `http://`, and MUST verify every downloaded object (AEAD, AAD account, generation and version, signatures) before using it. A version or generation older than one already seen is `remote_rollback`.
- R-SYNC-04. A new device MUST obtain the master key only by pairing with an existing device, verified by two codes typed by the user (the new device's key fingerprint on the approver, a confirmation code derived from the master key on the new device), or by the user's recovery key. Neither path lets the server substitute a device key or plant a master key of its own.
- R-SYNC-05. Every command that registers, pairs, recovers, revokes, rotates the recovery key, resolves a conflict, restores a version, logs out or links a project MUST be user-only: its input and the codes and keys it shows go through the prompt backend (R-CAP-01), never arguments, stdin, stdout, stderr, `--json` or the audit log; with no prompt backend it is refused with `not_model_callable`.
- R-SYNC-06. Revoking a device MUST rotate the master key and the recovery key in one atomic server transaction; remaining devices accept the new key only from a non-revoked device of their own encrypted roster.
- R-SYNC-07. Merge MUST be per record (three-way against the last agreed version, hybrid logical clocks, tombstones). When both sides changed a record the newer change wins and the other is kept as a conflict for the user to resolve; no record is lost silently.
- R-SYNC-08. Grants, prompt tokens, configuration and the audit log MUST NOT sync. A grant never applies to a record replaced on another device.
- R-SYNC-09. The local vault MUST stay authoritative and usable offline. `exec` MUST NOT touch the network; a change made offline syncs on a later command.
- R-SYNC-10. With sync enabled the client MUST upload, encrypted, the head of its audit log, and `audit --verify` MUST check the local log against those anchors.
- R-SYNC-11. Project layers MUST be identified independently of their path, with one root per device. A project layer reaches a new machine only when the user links it (`qbit-vault link`), never by matching a remote URL automatically.
- R-SYNC-12. `qbit-vault-server` MUST ship as one static binary and a container image that runs as non-root with a read-only root filesystem and one data volume, deployable behind a TLS reverse proxy (Dokploy).

## 6. Non-functional requirements

- R-NFR-01 *Portability*: macOS (arm64, amd64), Linux (amd64, arm64, including WSL2 and headless without Secret Service), Windows 10+ (amd64). Headless Linux uses the passphrase fallback.
- R-NFR-02 *Latency*: `exec` overhead ≤ 50 ms over running the command directly on a warm keychain; prompt round-trip is user-bound.
- R-NFR-03 *Supply chain* (*Phase 5, not built*): releases signed (Minisign) with `checksums.txt`; npm packages published with provenance; version pinning in every config `init` writes; no postinstall; dependency set listed in `AGENTS.md` and enforced by a CI check.
- R-NFR-04 *Observability*: `--json` on every command for host adapters; human output otherwise.
- R-NFR-05 *Compatibility*: contract `qbit-vault.secrets-broker/v1` is frozen on first stable release; additive changes bump the minor capability version; consumers refuse unknown major versions.
- R-NFR-06 *Testing*: leak tests on every tier (see `TESTING.md`); a PR touching exec/redact/prompt/mcp/hooks/remote/server without extending the leak test is rejected by CI.
- R-NFR-07 *Sync server*: Linux amd64 and arm64 images; one instance serves at least 100 accounts on 256 MiB of memory; a sync round with no change costs one request answered `304`.

## 7. Success criteria for v1

- A user can go from nothing to "agent created a GitHub release using a token it never saw" in under 3 minutes on all three OSes.
- A secret stored on one machine is usable on a second machine after `init`, `remote join` and one approval, in under 2 minutes, and the server's data directory contains no fixture value, secret name or project path.
- The leak test battery passes with zero secret bytes in any captured transcript, log, session file or tool result across Pi, Claude Code and Codex.
- A host maintainer can read `CONTRACT.md` and `ARCHITECTURE.md` and integrate the broker without asking design questions.

## 8. Open questions

- Q1. Should `project` grants and project layers be keyed by git remote URL instead of filesystem root, so a re-clone keeps them? (Decided for v1: root path. `qbit-vault relink OLD NEW` moves a project layer and its grants to a new checkout path. Remote keying stays a v2 candidate. With sync, project layers get a path-independent id and per-device roots (R-SYNC-11); the origin URL only produces a hint to run `link`.)
- Q2. Should `secret_list` be hidden from the model entirely and exposed only to the user via `/vault list`? (Leaning: keep it; the agent needs to know which handles exist to avoid re-asking.)
- Q3. Windows native prompt: PowerShell window vs. a tiny Go/Win32 dialog. (Decided and built: PowerShell, zero extra dependencies.)
