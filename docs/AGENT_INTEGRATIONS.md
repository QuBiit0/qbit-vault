# Agent integrations

One broker, one contract, three hosts: Claude Code, Codex and Pi / Gentle Shell. OpenCode was in the original design and is dropped (`odd/tasks/hosts.md` S8; no adapter exists). "Built" means `init` registers it and it is tested; *planned* items need the Pi extension (Phase 4, `GENTLE_SHELL_EXTENSION.md`) and are not built. "MCP" is the portable path through `secret_exec`; today it is the path every host uses.

| Capability | Pi / Gentle Shell | Claude Code | Codex |
| --- | --- | --- | --- |
| `secret_request` / `secret_list` / `secret_exec` / `secret_manage` tools | MCP (built, Pi ≥ 0.99); extension-registered tools (planned) | MCP (built) | MCP (built) |
| Agent rules (`policy`) known up front | `secret_list` (built); system prompt (planned) | MCP `instructions` + `secret_list` | MCP `instructions` + `secret_list` |
| Manual entry by the user | `qbit-vault set` in a terminal; `/vault set` (planned) | `qbit-vault set` in a terminal | same |
| Masked capture | native dialog or terminal prompt (built); `ctx.ui.custom` inline (planned) | native dialog | native dialog |
| Transparent injection into the host's own shell tool | `bash` override (planned) | `PreToolUse` rewrite (planned; `pre-bash` today only denies user-only commands) | no (use `secret_exec`) |
| Output redaction of the host's shell/read tools | `tool_result` hook (planned) | `PostToolUse` hooks `post-bash` and `post-read` (built) | n/a (`secret_exec` output is already redacted) |
| Paste interception | `pi.on("input")` (planned) | `UserPromptSubmit` hook `user-prompt` (built; blocks) | not available |
| Vault dir on read deny list | none registered | `permissions.deny` Read and Edit (built) | none registered |
| Audit widget | sidebar (planned) | none (`qbit-vault audit --tail` in a terminal) | none |

## MCP server (all hosts)

Started by the host as `qbit-vault mcp`. Exposes exactly four tools with the normative descriptions from `CONTRACT.md`, and the `policy` text as the server `instructions` returned at `initialize`, so hosts that surface MCP instructions give the agent its rules before any call. Input schemas are the `requestReq`, `listReq`, `execReq`, `manageReq` definitions minus the envelope fields, which the server fills in (`session` from `QBIT_VAULT_SESSION` or a generated `mcp:<uuid>`, `cwd` from the server's working directory, which hosts start in the project root).

The MCP server never exposes `grant`: there is no such tool, and a `grant` envelope sent over a model-facing transport (`broker --op`) is refused with `not_model_callable` unless it carries a prompt token the broker's own prompt backend issued.

### Registration written by `init`

**Claude Code** (adapter `claude-code`, `internal/hosts/claude`): four steps, each written into a user-scope file after a snapshot, owning only its own entries.

| Step | File | Owns |
| --- | --- | --- |
| `mcp` | `~/.claude.json` | `mcpServers.qbit-vault` |
| `hooks` | `~/.claude/settings.json` | the hook entries whose `statusMessage` starts with `qbit-vault hook ` |
| `deny` | `~/.claude/settings.json` | the two `permissions.deny` strings below |
| `skill` | `~/.claude/skills/qbit-vault/SKILL.md` | the whole file (§ Agent skill) |

Claude Code keeps **user-scoped MCP servers in `~/.claude.json`** (top-level `mcpServers`), not in `settings.json`; hooks and permissions live in `settings.json` (checked 2026-11-04 against <https://code.claude.com/docs/en/mcp.md> § MCP installation scopes and <https://code.claude.com/docs/en/settings.md>). Detection is read-only: `~/.claude` is a directory, or a `claude` binary is on `PATH`.

`~/.claude.json` (`command` is the absolute, symlink-resolved path of the running `qbit-vault`; `env` appears only when the vault home is not `~/.qbit-vault`):

```json
{ "mcpServers": { "qbit-vault": { "type": "stdio", "command": "/usr/local/bin/qbit-vault", "args": ["mcp"], "env": { "QBIT_VAULT_HOME": "/data/vault" } } } }
```

`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse":  [{ "matcher": "Bash|PowerShell", "hooks": [{ "type": "command", "command": "/usr/local/bin/qbit-vault", "args": ["hook", "pre-bash"], "timeout": 10, "statusMessage": "qbit-vault hook pre-bash" }] }],
    "PostToolUse": [
      { "matcher": "Bash|PowerShell", "hooks": [{ "type": "command", "command": "/usr/local/bin/qbit-vault", "args": ["hook", "post-bash"], "timeout": 30, "statusMessage": "qbit-vault hook post-bash" }] },
      { "matcher": "Read", "hooks": [{ "type": "command", "command": "/usr/local/bin/qbit-vault", "args": ["hook", "post-read"], "timeout": 30, "statusMessage": "qbit-vault hook post-read" }] }
    ],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "/usr/local/bin/qbit-vault", "args": ["hook", "user-prompt"], "timeout": 30, "statusMessage": "qbit-vault hook user-prompt" }] }]
  },
  "permissions": { "deny": ["Read(//home/me/.qbit-vault/**)", "Edit(//home/me/.qbit-vault/**)"] }
}
```

Decisions behind the shapes:
- **Exec form.** `command` is the binary and `args` its arguments (<https://code.claude.com/docs/en/hooks.md> § Exec form and shell form): no shell parses the line, so a path with spaces (`C:\Program Files\QBit Vault\qbit-vault.exe`) needs no quoting. On Windows exec form needs a real `.exe`, which `qbit-vault.exe` is. The hooks always exit 0 (S6, fail open), so `onFailure` is left unset.
- **Ownership marker.** Exec form leaves no `qbit-vault hook` text in `command`, so each entry carries it in `statusMessage` (the spinner text Claude Code shows while the hook runs): `qbit-vault hook pre-bash`, `... post-bash`, `... post-read`, `... user-prompt`. Re-running `init` replaces exactly those entries (also after the binary moved) and never touches another tool's hook, Gentle AI's included.
- **Deny rules use the resolved vault home in Claude Code's absolute form** `//path` (a single leading slash would anchor at `~/.claude`; on Windows `C:\Users\me\.qbit-vault` is written `//c/Users/me/.qbit-vault`; <https://code.claude.com/docs/en/permissions.md> § How path patterns match). `Read` also stops the `cat`/`head`/`tail` that Claude Code recognizes in Bash; `Edit` covers the write tools (a `Write(...)` rule never matches). A shell that reads the directory by another route is not stopped, which is why no secret is ever in the agent's environment either. Each entry is owned by its full string; the user's other entries keep their place and order.
- **Timeouts.** 10 s for `pre-bash` (never opens the vault), 30 s for the others.
- **Not honored yet:** `CLAUDE_CONFIG_DIR` (a relocated Claude Code config) is not read; the adapter writes under the user home.

Hook semantics (Claude Code hook protocol):
- `pre-bash` (implemented; the rewrite below is not, see "What `pre-bash` does today"): reads `{session_id, tool_input.command, cwd}`; if the command references known secrets or an implicit binding matches, returns `hookSpecificOutput.updatedInput.command = "qbit-vault exec --session claude:<session_id> --secret … -- <cmd>"`. If a referenced secret has no grant, returns `permissionDecision: "deny"` with reason `grant_required: NAME — call secret_request`. Dump-guard violations: deny with `dump_command`.
- `post-bash` / `post-read` (implemented, see "What the post and prompt hooks do today"): read `tool_response`; return it redacted via `hookSpecificOutput.updatedToolOutput` (it must keep the tool's output shape, see below). This path is a last line of defense, the pre hook is the real control.
- `user-prompt` (implemented): blocks a prompt that carries the value of a stored secret or a well-known secret shape, with a reason telling the user to store it with `qbit-vault set NAME`. The `/vault set NAME` shortcut and `config.paste_capture: true` (open the native prompt immediately) are not implemented.

#### Hook protocol (verified)

Checked on 2026-11-04 against the official reference, <https://code.claude.com/docs/en/hooks.md> (the page `docs.claude.com/en/docs/claude-code/hooks` now serves). Re-verify when Claude Code changes major behavior; `internal/hook/testdata` holds recorded events.

- **Input.** One JSON object on stdin. Common fields: `session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, plus `tool_name`, `tool_input`, `tool_use_id` for tool events. Bash: `tool_input.command` (also `description`, `timeout`, `run_in_background`). **PowerShell is a separate tool** with the same `tool_input.command`; on Windows without Git Bash there is no Bash tool at all, so matchers must be `Bash|PowerShell`. Read: `tool_input.file_path`.
- **Exit codes.** 0 = success, stdout JSON applies. **2 = blocking error** (PreToolUse blocks the call, stderr is the reason; JSON cannot override it). **Any other code, a crash, or unparseable/invalid JSON = non-blocking error**: the action proceeds and the user sees a `hook error` notice. Claude never sees stderr of a hook that exits 0. So qbit-vault hooks always exit 0 and speak only through stdout JSON.
- **stdout.** Exactly one JSON object and nothing else. Empty stdout with exit 0 means no opinion: the normal permission flow applies.
- **PreToolUse decision** is `hookSpecificOutput`: `hookEventName: "PreToolUse"`, `permissionDecision` `allow|deny|ask|defer`, `permissionDecisionReason` (shown to Claude for `deny`, to the user for `ask`, debug log only for `allow`), `updatedInput` (replaces the **whole** `tool_input`, so repeat unchanged fields), `additionalContext` (added next to the tool result). **`allow` skips the permission prompt**, so a hook that only wants to warn or stay out of the way must not send it. Precedence across hooks: `deny` > `defer` > `ask` > `allow`. The top-level `decision`/`reason` for this event are deprecated.
- **Warnings.** `systemMessage` (any event) is shown to the user; `additionalContext` reaches Claude as a system reminder next to the tool result (PreToolUse, PostToolUse, UserPromptSubmit and others). Each is capped at 10,000 characters. qbit-vault's fail-open answer uses both.
- **PostToolUse** (tool already ran, cannot be undone): input adds `tool_response` (Bash: `stdout`, `stderr`, `interrupted`, `isImage`) and `duration_ms`. Output: `hookSpecificOutput.updatedToolOutput` **replaces** the tool result Claude sees (it must match the tool's output shape; for built-in tools a mismatch is ignored and the original is kept; it does not change telemetry or what the user's terminal showed); `additionalContext`; top-level `decision: "block"` + `reason` only adds the reason next to the result, Claude still sees the original. Exit 2 shows stderr to Claude. Redaction is therefore possible; the shapes P3b uses are under "What the post and prompt hooks do today".
- **UserPromptSubmit**: input adds `prompt` (pasted text arrives expanded; it may be wrapped in `<pasted_content id=…>` lines). Output: top-level `decision: "block"` + `reason` (shown to the user, not to Claude), `hookSpecificOutput.additionalContext` (to Claude), `sessionTitle`, `suppressOriginalPrompt`. It **cannot rewrite the prompt**. Plain-text stdout on exit 0 is also added to Claude's context. A blocked prompt's text still lands in the transcript and prompt history unless `suppressOriginalPrompt: true` is set, and even then it can remain in local files.

Differences from what this document said before: the PostToolUse replacement field is `updatedToolOutput` (not `updatedResponse`); the post commands are `hook post-bash` and `hook post-read` (CLI.md), not `hook post`; the PreToolUse matcher includes `PowerShell`.

#### What `pre-bash` does today

`qbit-vault hook pre-bash` (internal/hook) never opens the vault, prompts or uses the network (the post and prompt hooks below do read the vault); a run takes microseconds in-process and tens of milliseconds as a process on Windows.

- It splits the command across `&&`, `||`, `;`, `|`, `&`, newlines, `( )`, `$( )` and backticks (also inside double quotes), strips env assignments, redirections, `sudo`/`doas`/`env`/`exec`/`command`/`builtin`/`nohup`/`time`/`nice`/`xargs`/`timeout`, and looks inside `sh|bash|zsh|dash|ksh|fish|pwsh|powershell|cmd -c|-Command|/c` strings, `npx|bunx|pnpx|npm exec|pnpm dlx|yarn dlx|bun x` (with `@version`), and the command after `--` of `qbit-vault exec`. A program is `qbit-vault` by its base name, case-insensitive, with or without `.exe`/`.cmd`/`.bat`/`.ps1`, at any path. `pwsh`/`powershell` with an encoded command (`-e`, `-ec`, `-enc`, `-EncodedCommand`, any case, `-` or `/`) is refused too: its base64 script cannot be read.
- **Agent may run** (no output, the host's permission flow applies): no subcommand (bare, `--help`, `--version`), and `version`, `help`, `list`, `describe`, `grants`, `audit` (including `--verify`), `doctor`, and `exec` (its grants are the control; the command after `--` is checked recursively).
- **Denied** with `permissionDecision: "deny"` and the fixed reason `This qbit-vault command is user-only: ask the user to run it in their own terminal. The agent's shell cannot run it.` (the command is never echoed): every other subcommand, so `set rm mv edit relink link import restore rekey lock unlock grant revoke init uninstall sync update prompt mcp broker hook` and `remote` with any or no sub-subcommand (R-SYNC-05), and any unknown name. A line that mentions `qbit-vault` but cannot be parsed (unbalanced quote or substitution, here-document) or goes through `eval`/`iex`/`Invoke-Expression`/`Start-Process`/`Invoke-Command` is denied too.
- **Fails open** (S6): unreadable or oversized stdin, malformed JSON, a wrong `command` type, a handler error or a panic gives exit 0 and `{"systemMessage":…,"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":…}}` with the text `qbit-vault hook failed; the command ran without its checks; run 'qbit-vault doctor'`, and no `permissionDecision`. A detected forbidden invocation is never a failure: it is always denied.
- **Not done yet (pre-bash):** rewriting commands that reference bound secrets into `qbit-vault exec` (R-EXEC-02) and the `grant_required` / `dump_command` denials need the vault's names, bindings and grants; they belong to the slice that loads bindings (P3b or later). Until then such commands pass through unchanged, and the secret is simply absent from the agent's environment.
- **Limits.** The scanner is a guard against the model running a user-only command by mistake or by prompt injection, not a sandbox: an invocation built at run time (base64, `$VAR` as program, a script file) is not seen. The real controls are that those commands need the user's own prompt backend (`not_model_callable`, R-SYNC-05) and that no secret is in the agent's environment.

#### What the post and prompt hooks do today

`hook post-bash`, `hook post-read` and `hook user-prompt` (internal/hook, `internal/cli/hookcmd.go`) redact or block using the values in the vault. They open it **without prompting**, the way `remote status` does: through the OS keychain or an unexpired unlock cache, never a passphrase prompt, and they never finish an interrupted rekey.

- **Which values.** Every stored value of at least 8 bytes (`redact.ShortLen`), in every layer, plus shorter values that have an active grant (any session). A value the agent reads from a file or a log is a leak whether or not a grant covers it, so grants do not gate redaction; shorter values without a grant are skipped because redacting three or four characters would mangle ordinary output. `exec` redacts its injected values whatever their length. Encodings are the ones `internal/redact` knows: raw, base64 (standard and URL-safe, padded or not, also inside a larger base64 blob), percent-encoding, JSON-escaped, UTF-16LE and UTF-16BE (a file written by Windows PowerShell 5.1 `Out-File`), and the value with surrounding quotes. The marker is `[REDACTED:NAME]`.
- **Shape.** The hook decodes `tool_response`, redacts every string value inside it (never keys), and re-emits the same structure as `hookSpecificOutput.updatedToolOutput`, so the replacement has the shape of the original by construction. Bash and PowerShell: `{stdout, stderr, interrupted, isImage}` (documented). Read: `{type, file: {filePath, content, numLines, startLine, totalLines}}`; the official reference does not document Read's output object, this is the shape Claude Code produced when recorded (`testdata/posttooluse_read.json`), and the hook does not depend on it. Object keys come back in alphabetical order, which JSON does not care about. The answer also carries `additionalContext`: `qbit-vault redacted N occurrence(s) of stored secrets`. When nothing matched, nothing is printed.
- **Size.** A PostToolUse event is read up to 64 MiB and the whole output is redacted (memory is a few times the event size). A bigger event fails open.
- **Cost.** No vault open when the result holds no text. With a vault: opening it, listing the records and redacting a 2 KB output took about 65 ms in-process on Windows with ten secrets (23 ms of that is the test harness); as a process the run is dominated by process start (about 85 ms here, the same as `qbit-vault version`).
- **Locked vault fails open.** A passphrase vault with no unlock cache (or a vault the keychain cannot give a key for) cannot be read without a prompt, so the hook lets the output through **unredacted** and says so, in `systemMessage` and `additionalContext`: `qbit-vault could not check this output for secrets (vault locked); run 'qbit-vault unlock'` (`this prompt` for user-prompt). **With a passphrase vault that is locked, the post hooks do not redact anything.** Run `qbit-vault unlock` before the agent session. Any other failure (garbage event, vault error, panic) gives the generic warning of pre-bash. A home with no vault is silent: there is nothing to redact.
- **`user-prompt`.** A prompt that contains a stored value (any encoding above, including inside `<pasted_content>` blocks) is blocked: `{"decision":"block","reason":"This prompt contains the value of a stored secret, so qbit-vault blocked it. Store secrets with 'qbit-vault set NAME' in your own terminal and refer to them by name.","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}`. The reason never includes the prompt or a name, and `suppressOriginalPrompt` keeps the text out of the block message. A prompt that matches a well-known secret shape (`ghp_`/`gho_`/`ghs_`, `github_pat_`, `AKIA`/`ASIA` keys, `xox*-` Slack tokens, `sk_live_`/`rk_live_`, `sk-`/`sk-ant-`/`sk-proj-` keys of 32 or more characters, PEM private key headers, JWTs) is blocked too, with `This prompt looks like it contains a secret, ...`; that check needs no vault, so it works while the vault is locked. Generic high-entropy strings are not matched (too many false positives). **Limit:** a blocked prompt still lands in the transcript and the prompt history (Claude Code writes them before the hook can act); the hook cannot remove it, only keep it out of the block message.
- **Limits.** Redaction happens after the tool ran and only changes what the model sees; telemetry and the user's terminal keep the original. A value the shell transformed (hex, ROT13, split across lines of a table) is not recognized.

**Codex** (`~/.codex/config.toml`, merged; plus the `skill` step, `~/.agents/skills/qbit-vault/SKILL.md`, § Agent skill):

```toml
[mcp_servers.qbit-vault]
command = "/abs/path/to/qbit-vault"
args = ["mcp"]

# only when the vault home is not ~/.qbit-vault:
[mcp_servers.qbit-vault.env]
QBIT_VAULT_HOME = "/abs/path/to/vault"
```

Format checked against https://developers.openai.com/codex/mcp (§ Configure with config.toml) on 2026-11-04: `[mcp_servers.<name>]` tables with `command` (required), `args`, `env`, `startup_timeout_sec` (default 10) and `tool_timeout_sec` (default 60). `init` writes only `command`, `args` and, for a custom vault home, the `env` subtable; the timeouts keep Codex's defaults. `command` is the absolute path of the running binary, written as a TOML basic string (backslashes and quotes escaped).

Only our table is edited, as text, through `internal/filemerge`: every other byte of `config.toml` (comments, other `[mcp_servers.*]` tables, line endings, a missing final newline) stays identical, the file is snapshotted first and written atomically, and `uninstall` removes just our table. A config that defines our table in a form the editor cannot edit safely (inline table, dotted keys, an array of tables, a table defined twice) is refused and left untouched. Detection: `~/.codex` is a directory or `codex` is on `PATH`.

Sandbox note: `init` does **not** set `QBIT_VAULT_PROMPT`. The Codex docs (checked 2026-11-04) say nothing that requires it, and the sandbox they describe governs the shell commands the model runs; Codex spawns MCP servers itself, as ordinary child processes, so we expect the native dialog to open as it does from any other process (not yet verified end to end inside a Codex session). Forcing `tty` would be wrong by default: an MCP server's stdin and stdout are the protocol pipe, and the terminal prompt needs a controlling terminal, which the server may not have. The prompt already falls back to the terminal on its own when there is no desktop session (§ Native capture dialog). A user whose setup does block the dialog can add `QBIT_VAULT_PROMPT = "tty"` to the `env` subtable by hand; since that table is ours, `doctor` then reports drift and the next `init` rewrites it; there is no supported override in this release.

Limitation: Codex moves its config when `CODEX_HOME` is set (https://developers.openai.com/codex/config-advanced, Config and state locations). The adapter does not read it and always uses `~/.codex/config.toml`, the same way the Claude adapter ignores `CLAUDE_CONFIG_DIR`.

**OpenCode**: dropped. The original design registered an MCP entry in `~/.config/opencode/opencode.json` and a bash-rewrite plugin; no adapter exists, `--agents opencode` is an unknown agent, and none is planned for 0.1 (`odd/tasks/hosts.md` S8).

**Pi (plain, without Gentle Shell)**: for Pi ≥ 0.99, an MCP entry in `~/.pi/agent/mcp.json` so the four tools exist (built, below). The extension (`qbit-vault-pi`, the rich path) is Phase 4: it is not published yet, so there is no command to run.

**Pi / Gentle Shell registration written by `init`** (adapter `pi`, `internal/hosts/pi`): two steps: `skill` writes `~/.agents/skills/qbit-vault/SKILL.md`, shared with Codex (§ Agent skill), and `mcp` is merged into `<Pi agent dir>/mcp.json` after a snapshot, owning only `mcpServers.qbit-vault`:

```json
{ "mcpServers": { "qbit-vault": { "command": "/abs/path/to/qbit-vault", "args": ["mcp"] } } }
```

`env` with `QBIT_VAULT_HOME` appears only when the vault home is not `~/.qbit-vault` (a path containing `${` or starting with `!` is refused, because Pi expands both in `env` values). `type` is omitted: Pi picks stdio from `command`. Format checked 2026-11-04 against the Pi docs (<https://github.com/badlogic/pi-mono>, `packages/coding-agent/docs/mcp.md`): Pi connects MCP servers natively since 0.99, reads user servers from `<agent dir>/mcp.json` (top-level `mcpServers`; stdio entries use `command`, `args`, `env`) and project servers from `.pi/mcp.json` (only after project trust; not touched). The `pi-mcp-adapter` extension reads the same file. The agent directory is `$PI_CODING_AGENT_DIR` when set (`docs/environment-variables.md`: "Override the config directory; default is `~/.pi/agent`"), else `<user home>/.pi/agent`; a leading `~` is expanded against the user home and a relative path is refused. Gentle Shell is detected by a `gentle-shell` binary on `PATH` and uses the same file when it runs on Pi; a Gentle Shell with its own agent directory (`~/.gentle-shell/agent`) is reached through `PI_CODING_AGENT_DIR`. Detection is read-only: the agent directory or `~/.pi` exists, or `pi` or `gentle-shell` is on `PATH`.

The extension is **not** installed by `init` (it needs the network, invariant 8). While the extension is unpublished, `init` and `sync` print no install command for it and `--json` has no `install_command`; once it is published, `init` will print the command for the user to run. Not honored: `.pi/mcp.json`, and an agent directory passed with a Pi command-line option.

**Gentle Shell** (planned, with the extension): `gentle-shell install npm:qbit-vault-pi` into `~/.gentle-shell/agent` (or `--link` home). See `GENTLE_SHELL_EXTENSION.md`.

## Agent skill

The MCP instructions and the four tool descriptions say *what* the tools do; the `qbit-vault` skill says *when* to reach for them: whenever a command needs a credential, call `secret_list`, then `secret_request` for what is missing, then `secret_exec`; never ask the user to paste a value; what to do with each refusal. Source: `internal/hosts/skill/SKILL.md`, embedded in the binary.

| Host | Skill file | Why there |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/qbit-vault/SKILL.md` | Claude Code's personal skills directory |
| Codex | `~/.agents/skills/qbit-vault/SKILL.md` | Codex reads user skills from `~/.agents/skills` (`~/.codex/skills` is its legacy name; openai/codex#10437, checked 2026-11-05) |
| Pi | the same file as Codex | Pi reads `~/.agents/skills` too; a second copy in `~/.pi/agent/skills` would collide by name |

Rules (step `skill`, `internal/hosts/skill`, written with `filemerge.WriteOwnedFile`):

- **Only where it is needed.** Only registered hosts get it, and the file is written only when its bytes differ from the skill this build carries: a current copy is never rewritten, snapshotted or re-recorded. The skill text has no version string, so a release that does not change it touches nothing.
- **Always current.** `sync` rewrites a stale copy (snapshot first), and `install.sh` / `install.ps1` run `sync` after every upgrade, so each release installs its own skill. `doctor` reports a stale or missing copy as `host.<name>.skill` drift (`run 'qbit-vault sync'`).
- **Whole file, ours only.** The file carries the marker `<!-- Managed by qbit-vault:`. A `SKILL.md` at that path without it is the user's own skill of that name and wins: the step records it without writing, `doctor` accepts it, and `uninstall` leaves it; registration does not fail because of it. Edits to our file are replaced by the next `sync`; keep your own notes in another skill.
- **Uninstall.** `uninstall` deletes our copy (snapshot first) and its directory when empty; a copy the user replaced (no marker) stays. The shared Codex/Pi file stays while the other host is still registered. qbit-vault never writes `CLAUDE.md`, `AGENTS.md` or any other instruction file of the user.

## Native capture dialog (non-Pi hosts)

`qbit-vault prompt`, `set`, `grant` and every other command that asks the user pick a backend in the same order. With `QBIT_VAULT_PROMPT` unset: the platform's **native dialog when a desktop session is available**, otherwise the terminal. `QBIT_VAULT_PROMPT=tty|powershell|osascript|zenity|kdialog` forces one; a named backend that is not installed fails with `prompt backend <name> is unavailable` and never falls back to another one.

| OS | Backend | Mechanism | Used when |
| --- | --- | --- | --- |
| Windows | `powershell` | `powershell.exe -NoProfile -NonInteractive -STA -Command -` with a WinForms script on stdin: a TopMost dialog, masked `TextBox` (`UseSystemPasswordChar`), radio buttons for layer and scope, `Confirm` / `Decline` or `OK` / `Cancel` buttons | the process runs in an interactive session (not session 0) and `powershell.exe` exists at `%SystemRoot%\System32\WindowsPowerShell\v1.0\` |
| macOS | `osascript` | `display dialog ... with hidden answer` for the value, `choose from list` for layer and scope, `display dialog` with `Decline` / `Confirm` buttons; the script is sent on stdin | `/usr/bin/osascript` exists, and the shell is not an SSH session without a GUI (`SSH_CONNECTION` or `SSH_TTY` set and neither `__CFBundleIdentifier` nor `TERM_PROGRAM` set) |
| Linux (desktop) | `zenity` or `kdialog` | zenity: `--entry --hide-text` for the value (`--password` has no text field, so it could not show the request), `--list --radiolist`, `--question`; kdialog: `--password`, `--radiolist` (a confirmation too: Decline preselected, because `--yesno` cannot default to no and Escape answers like its no button). zenity is tried first; kdialog renders every text as rich text, so the request is HTML-escaped and its layout lines become `<br>` | `DISPLAY` or `WAYLAND_DISPLAY` is set and one of the two is on `PATH` |
| Any | `tty` | opens `/dev/tty` (`CONIN$` on Windows), disables echo, reads value, prints the scope choice menu | the fallback, or `QBIT_VAULT_PROMPT=tty` |

The dialog always shows: secret name, the reason verbatim (control and bidi characters shown as visible escapes, so a reason cannot add a line or paint over the dialog), the host and session id, the project label (or `global`), and whether the value is **new** or **already stored (it will be replaced)**. When the value is new and `cwd` is inside a repository, the dialog also asks for the layer (`Global` / `This project`). For `secret_manage` the same backends render a confirmation (opened by the broker itself; a `prompt --confirm` command for hosts is planned, slice 4.3) with the action, the diff and `Confirm` / `Decline`; closing the dialog or pressing Esc is `Decline`, and on Windows and macOS so is Enter (the default button). A passphrase asked twice (`init`) is two dialogs.

**Several fields in one prompt** (CONTRACT `request` with `fields`, R-CAP-08). The request text, the layer question and the scope choice appear once; every new field gets its own box labelled with its `label` (default the name), masked for `secret` and visible for `text`; stored fields are listed as *already stored* without a box. PowerShell renders one WinForms form with one `TextBox` per field (`UseSystemPasswordChar` only on secret ones; each value comes back as one base64 line on the helper's private stdout); zenity uses one `--forms` dialog (`--add-password` for secret fields, `--add-entry` for text ones, answers split on a control-character separator); osascript and kdialog have no multi-field form, so they show one box per field in a row, each repeating the request header and a `field 2 of 3` line, and cancelling any box cancels the whole capture; the terminal does the same with one line per field (echo off for secret fields, on for text fields). Empty boxes, a cancel or the timeout store nothing (R-CAP-04).

**Remote sync prompts.** `remote register`, `join`, `approve`, `revoke-device`, `recovery-key --rotate`, `resolve`, `restore`, `logout` and `link` ask and display through the same backends: the invite code and the recovery key in a masked box, the pairing and confirmation codes in a visible one, and the recovery key and the confirmation code shown in a dialog (or on the controlling terminal) that is never the command's stdout (`REMOTE_SYNC.md` § 4).

**Showing what the user must keep.** The recovery key and the pairing confirmation code (REMOTE_SYNC.md § 4) are shown out of band, never on stdout, stderr or `--json`. Their text never travels in a helper's argv, because any local user can read a process's command line: PowerShell and osascript get it inside the script on stdin, zenity through `--text-info` reading stdin, the terminal backend writes it to the controlling terminal and waits for Enter. kdialog takes text only as arguments, so it reports `prompt backend unavailable` for these screens; set `QBIT_VAULT_PROMPT=tty` or install zenity. Every line is escaped like any request text.

**Where the helper is found.** `powershell.exe` and `osascript` are run from their fixed system locations and are never looked up on `PATH`, because anything that can put a file earlier on `PATH` could stand in for the dialog and receive the value. On Windows the directory comes from the system API (`GetSystemWindowsDirectory`), with `C:\Windows` as fallback, and the file must exist; from WSL, forcing `powershell` uses `/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe` when it exists. `zenity` and `kdialog` have no single fixed location on Linux, but they are not taken from `PATH` either: they are looked up only in `/usr/bin`, `/bin` and `/usr/local/bin`, in that order, and the backend is unavailable when none holds them. No helper is located through `PATH`.

**Input rules, identical on every backend.** A secret value loses its line terminator and surrounding whitespace (R-CAP-04, the same `bytes.TrimSpace` rule as `set --stdin`). A passphrase loses only its line terminator, never other whitespace, so the same passphrase derives the same key whether it was typed in a dialog, on the terminal or given to `init --passphrase-stdin`. Input longer than the read bound (64 KiB plus margin) is refused with `value too large` and wiped, never truncated.

**How the value comes back.** The value never travels on qbit-vault's own stdout, which the host can read. It comes back on the **helper's** stdout: a private anonymous pipe between the dialog helper and qbit-vault that the agent does not hold. The helper's script or arguments carry the request text only (for PowerShell as base64 data, for AppleScript as escaped literals, for zenity and kdialog as single argv elements), never a value, and the helper's environment is qbit-vault's own with nothing added. qbit-vault reads the pipe as bytes into one buffer and wipes it after copying the value into a `Secret`; a failing or cancelled helper yields only a typed error (`cancelled`, `prompt timed out`, or `prompt backend unavailable`) with none of the helper's output. A dialog that cannot open when it was selected (no display, helper crashed) is the unavailable error, not a silent retry on the terminal.

`prompt --value` hands the value to the host on file descriptor 3, which POSIX hosts can open. Windows does not pass numbered descriptors to child processes, so there `--value` is refused; a Windows host captures with its own prompt (the Pi extension's masked input) or lets `set` open the native dialog, and stores with `set --stdin`.

## Deny-list alignment with Gentle AI

For Claude Code, `init` adds the vault home to `permissions.deny` (the `deny` step above) with a merge that owns only its two entries, so every entry another tool put there, Gentle AI's included, keeps its place and order (tested with golden files and in the Docker hosts battery). A separate step that re-reads the entries and aborts and restores the snapshot if one went missing (PRD R-INS-05) is **not built**; `doctor` reports drift of our own entries only. Codex and Pi have no deny registration.

## Implicit bindings

**Planned, not built.** See `ARCHITECTURE.md` § Implicit binding table: no code loads `bindings.yaml` yet. The design is that the Pi extension and the Claude Code hook read the same file, so behavior is identical.

## Subagents

A subagent is a new session id. Over MCP, each MCP server process uses `QBIT_VAULT_SESSION` or generates its own `mcp:<16 hex>`, so a subagent with its own server needs its own grants. Planned with the extension and the hook rewrite: Pi subagents and Gentle Agents get `pi:<child-id>`, and Claude Code subagents (same `session_id`, distinct `agent_id`) get `claude:<session_id>/<agent_id>`. No grant inheritance (R-GRANT-05). The user sees a separate prompt naming the session.
