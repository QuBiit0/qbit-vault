# Agent integrations

One broker, one contract, four hosts. The table shows what each host gets and through which mechanism. "Rich" means the extension/hook path; "MCP" means the portable fallback through `secret_exec`.

| Capability | Pi / Gentle Shell | Claude Code | OpenCode | Codex |
| --- | --- | --- | --- | --- |
| `secret_request` / `secret_list` / `secret_exec` / `secret_manage` tools | extension-registered tools (and MCP since Pi ≥ 0.99) | MCP | MCP | MCP |
| Agent rules (`policy`) known up front | system prompt + `secret_list` | MCP `instructions` + `secret_list` | MCP `instructions` + `secret_list` | MCP `instructions` + `secret_list` |
| Manual entry by the user | `/vault set` (masked, inline) | `gentle-vault set` in a terminal | same | same |
| Masked capture inside the terminal | `ctx.ui.custom` inline | native dialog | native dialog | native dialog |
| Transparent injection into the host's own shell tool | `bash` override | `PreToolUse` hook rewrite | plugin `tool.execute.before` (when available) | no (use `secret_exec`) |
| Output redaction of the host's shell/read tools | `tool_result` hook | `PostToolUse` hook | plugin `tool.execute.after` | n/a (secret_exec output is already redacted) |
| Paste interception | `pi.on("input")` | `UserPromptSubmit` hook | not available | not available |
| Vault dir on read deny list | Gentle AI permissions / Pi settings | `permissions.deny` | OpenCode permissions | Codex sandbox config |
| Audit widget | sidebar | `/vault` skill prints `audit --tail` | none | none |

## MCP server (all hosts)

Started by the host as `gentle-vault mcp`. Exposes exactly four tools with the normative descriptions from `CONTRACT.md`, and the `policy` text as the server `instructions` returned at `initialize`, so hosts that surface MCP instructions give the agent its rules before any call. Input schemas are the `requestReq`, `listReq`, `execReq`, `manageReq` definitions minus the envelope fields, which the server fills in (`session` from `GENTLE_VAULT_SESSION` or a generated `mcp:<uuid>`, `cwd` from the server's working directory, which hosts start in the project root).

The MCP server never exposes `grant`. A `grant` envelope arriving on its stdin is answered with `not_model_callable` and audited.

### Registration written by `init`

**Claude Code** (`~/.claude/settings.json`, merged, snapshotted):

```json
{
  "mcpServers": { "gentle-vault": { "command": "gentle-vault", "args": ["mcp"] } },
  "hooks": {
    "PreToolUse":  [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "gentle-vault hook pre-bash" }] }],
    "PostToolUse": [{ "matcher": "Bash|Read", "hooks": [{ "type": "command", "command": "gentle-vault hook post" }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "gentle-vault hook user-prompt" }] }]
  },
  "permissions": { "deny": ["Read(~/.gentle-vault/**)"] }
}
```

Hook semantics (Claude Code hook protocol):
- `pre-bash`: reads `{session_id, tool_input.command, cwd}`; if the command references known secrets or an implicit binding matches, returns `hookSpecificOutput.updatedInput.command = "gentle-vault exec --session claude:<session_id> --secret … -- <cmd>"`. If a referenced secret has no grant, returns `permissionDecision: "deny"` with reason `grant_required: NAME — call secret_request`. Dump-guard violations: deny with `dump_command`.
- `post`: reads `tool_response`; returns it redacted via `updatedResponse`-style output where supported, otherwise appends a `systemMessage` warning if a value was detected (and the user is alerted; this path is a last line of defense, the pre hook is the real control).
- `user-prompt`: scans the prompt for secret-shaped tokens; on match returns `decision: "block"` with a reason telling the user to run `/vault set NAME` (or the native prompt is opened immediately when `config.paste_capture: true`).

**Codex** (`~/.codex/config.toml`, merged):

```toml
[mcp_servers.gentle-vault]
command = "gentle-vault"
args = ["mcp"]
```

Sandbox note: Codex's sandbox may block the native dialog from spawning; `init` sets `env = { GENTLE_VAULT_PROMPT = "tty" }` on Linux/macOS when it detects a seatbelt/landlock sandbox config, which makes `request` read from `/dev/tty` with echo off instead.

**OpenCode** (`~/.config/opencode/opencode.json`, merged):

```json
{ "mcp": { "gentle-vault": { "type": "local", "command": ["gentle-vault", "mcp"], "enabled": true } } }
```

plus, when the OpenCode plugin API is present, a plugin file `~/.config/opencode/plugin/gentle-vault.ts` implementing `tool.execute.before` (rewrite bash to exec, dump-guard) and `tool.execute.after` (redaction). Gentle AI v4 manages OpenCode V2 plugins; `init` writes outside Gentle AI's managed set and `doctor` verifies no collision.

**Pi (plain, without Gentle Shell)**: `pi install npm:gentle-vault-pi` for the extension (rich path) and, for Pi ≥ 0.99, an MCP entry in `~/.pi/agent/mcp.json` so the tools exist even if the extension is disabled.

**Gentle Shell**: `gentle-shell install npm:gentle-vault-pi` into `~/.gentle-shell/agent` (or `--link` home). See `GENTLE_SHELL_EXTENSION.md`.

## Native capture dialog (non-Pi hosts)

`gentle-vault prompt` picks a backend in order of availability, overridable with `GENTLE_VAULT_PROMPT`:

| OS | Backend | Mechanism |
| --- | --- | --- |
| macOS | `osascript` | `display dialog "<name>\n<reason>" default answer "" with hidden answer buttons {"Cancel","Once","Session","Project"}`; the chosen button is the scope |
| Windows | `powershell` | A `-WindowStyle Normal` PowerShell window with `Read-Host -AsSecureString` and a scope selection; value returned to the parent over an anonymous pipe, never via stdout text |
| Linux (desktop) | `zenity --password` / `kdialog --password` | followed by a scope dialog |
| Any | `tty` | opens `/dev/tty` (`CONIN$` on Windows), disables echo, reads value, prints the scope choice menu |

The dialog always shows: secret name, the reason verbatim, the host and session id, the project label (or `global`), and whether the value is **new** or **already stored (grant only)**. When the value is new and `cwd` is inside a repository, the dialog also asks for the layer (`Global` / `This project`). For `secret_manage` the same backends render a confirmation (`prompt --confirm`) with the action, the diff and `Confirm` / `Decline`. Values flow back to the broker over a pipe/fd, never through stdout.

## Deny-list alignment with Gentle AI

When the Gentle AI permissions component is installed, `init`:
1. Reads the existing deny entries for the host.
2. Adds `$GENTLE_VAULT_HOME/**` if missing.
3. Verifies every pre-existing Gentle AI entry is still present after the merge; aborts and restores the snapshot otherwise (PRD R-INS-05).

## Implicit bindings

See `ARCHITECTURE.md` § Implicit binding table. The same `bindings.yaml` is read by the Pi extension, the Claude Code hook and the OpenCode plugin, so behavior is identical.

## Subagents

A subagent is a new session id (Pi subagents and Gentle Agents get their own; Claude Code subagents share `session_id` but hooks receive a distinct `agent_id`, which the hook appends: `claude:<session_id>/<agent_id>`). No grant inheritance (R-GRANT-05). The user sees a separate prompt naming the subagent.
