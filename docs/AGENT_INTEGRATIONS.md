# Agent integrations

One broker, one contract, four hosts. The table shows what each host gets and through which mechanism. "Rich" means the extension/hook path; "MCP" means the portable fallback through `secret_exec`.

| Capability | Pi / Gentle Shell | Claude Code | OpenCode | Codex |
| --- | --- | --- | --- | --- |
| `secret_request` / `secret_list` / `secret_exec` / `secret_manage` tools | extension-registered tools (and MCP since Pi ≥ 0.99) | MCP | MCP | MCP |
| Agent rules (`policy`) known up front | system prompt + `secret_list` | MCP `instructions` + `secret_list` | MCP `instructions` + `secret_list` | MCP `instructions` + `secret_list` |
| Manual entry by the user | `/vault set` (masked, inline) | `qbit-vault set` in a terminal | same | same |
| Masked capture inside the terminal | `ctx.ui.custom` inline | native dialog | native dialog | native dialog |
| Transparent injection into the host's own shell tool | `bash` override | `PreToolUse` hook rewrite | plugin `tool.execute.before` (when available) | no (use `secret_exec`) |
| Output redaction of the host's shell/read tools | `tool_result` hook | `PostToolUse` hook | plugin `tool.execute.after` | n/a (secret_exec output is already redacted) |
| Paste interception | `pi.on("input")` | `UserPromptSubmit` hook | not available | not available |
| Vault dir on read deny list | Gentle AI permissions / Pi settings | `permissions.deny` | OpenCode permissions | Codex sandbox config |
| Audit widget | sidebar | `/vault` skill prints `audit --tail` | none | none |

## MCP server (all hosts)

Started by the host as `qbit-vault mcp`. Exposes exactly four tools with the normative descriptions from `CONTRACT.md`, and the `policy` text as the server `instructions` returned at `initialize`, so hosts that surface MCP instructions give the agent its rules before any call. Input schemas are the `requestReq`, `listReq`, `execReq`, `manageReq` definitions minus the envelope fields, which the server fills in (`session` from `QBIT_VAULT_SESSION` or a generated `mcp:<uuid>`, `cwd` from the server's working directory, which hosts start in the project root).

The MCP server never exposes `grant`. A `grant` envelope arriving on its stdin is answered with `not_model_callable` and audited.

### Registration written by `init`

**Claude Code** (`~/.claude/settings.json`, merged, snapshotted):

```json
{
  "mcpServers": { "qbit-vault": { "command": "qbit-vault", "args": ["mcp"] } },
  "hooks": {
    "PreToolUse":  [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "qbit-vault hook pre-bash" }] }],
    "PostToolUse": [{ "matcher": "Bash|Read", "hooks": [{ "type": "command", "command": "qbit-vault hook post" }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "qbit-vault hook user-prompt" }] }]
  },
  "permissions": { "deny": ["Read(~/.qbit-vault/**)"] }
}
```

Hook semantics (Claude Code hook protocol):
- `pre-bash`: reads `{session_id, tool_input.command, cwd}`; if the command references known secrets or an implicit binding matches, returns `hookSpecificOutput.updatedInput.command = "qbit-vault exec --session claude:<session_id> --secret … -- <cmd>"`. If a referenced secret has no grant, returns `permissionDecision: "deny"` with reason `grant_required: NAME — call secret_request`. Dump-guard violations: deny with `dump_command`.
- `post`: reads `tool_response`; returns it redacted via `updatedResponse`-style output where supported, otherwise appends a `systemMessage` warning if a value was detected (and the user is alerted; this path is a last line of defense, the pre hook is the real control).
- `user-prompt`: scans the prompt for secret-shaped tokens; on match returns `decision: "block"` with a reason telling the user to run `/vault set NAME` (or the native prompt is opened immediately when `config.paste_capture: true`).

**Codex** (`~/.codex/config.toml`, merged):

```toml
[mcp_servers.qbit-vault]
command = "qbit-vault"
args = ["mcp"]
```

Sandbox note: Codex's sandbox may block the native dialog from spawning; `init` sets `env = { QBIT_VAULT_PROMPT = "tty" }` on Linux/macOS when it detects a seatbelt/landlock sandbox config, which makes `request` read from `/dev/tty` with echo off instead.

**OpenCode** (`~/.config/opencode/opencode.json`, merged):

```json
{ "mcp": { "qbit-vault": { "type": "local", "command": ["qbit-vault", "mcp"], "enabled": true } } }
```

plus, when the OpenCode plugin API is present, a plugin file `~/.config/opencode/plugin/qbit-vault.ts` implementing `tool.execute.before` (rewrite bash to exec, dump-guard) and `tool.execute.after` (redaction). Gentle AI v4 manages OpenCode V2 plugins; `init` writes outside Gentle AI's managed set and `doctor` verifies no collision.

**Pi (plain, without Gentle Shell)**: `pi install npm:qbit-vault-pi` for the extension (rich path) and, for Pi ≥ 0.99, an MCP entry in `~/.pi/agent/mcp.json` so the tools exist even if the extension is disabled.

**Gentle Shell**: `gentle-shell install npm:qbit-vault-pi` into `~/.gentle-shell/agent` (or `--link` home). See `GENTLE_SHELL_EXTENSION.md`.

## Native capture dialog (non-Pi hosts)

`qbit-vault prompt`, `set`, `grant` and every other command that asks the user pick a backend in the same order. With `QBIT_VAULT_PROMPT` unset: the platform's **native dialog when a desktop session is available**, otherwise the terminal. `QBIT_VAULT_PROMPT=tty|powershell|osascript|zenity|kdialog` forces one; a named backend that is not installed fails with `prompt backend <name> is unavailable` and never falls back to another one.

| OS | Backend | Mechanism | Used when |
| --- | --- | --- | --- |
| Windows | `powershell` | `powershell.exe -NoProfile -NonInteractive -STA -Command -` with a WinForms script on stdin: a TopMost dialog, masked `TextBox` (`UseSystemPasswordChar`), radio buttons for layer and scope, `Confirm` / `Decline` or `OK` / `Cancel` buttons | the process runs in an interactive session (not session 0) and `powershell.exe` exists at `%SystemRoot%\System32\WindowsPowerShell\v1.0\` |
| macOS | `osascript` | `display dialog ... with hidden answer` for the value, `choose from list` for layer and scope, `display dialog` with `Decline` / `Confirm` buttons; the script is sent on stdin | `/usr/bin/osascript` exists, and the shell is not an SSH session without a GUI (`SSH_CONNECTION` or `SSH_TTY` set and neither `__CFBundleIdentifier` nor `TERM_PROGRAM` set) |
| Linux (desktop) | `zenity` or `kdialog` | zenity: `--entry --hide-text` for the value (`--password` has no text field, so it could not show the request), `--list --radiolist`, `--question`; kdialog: `--password`, `--radiolist`, `--yesno`. zenity is tried first; kdialog renders every text as rich text, so the request is HTML-escaped and its layout lines become `<br>` | `DISPLAY` or `WAYLAND_DISPLAY` is set and one of the two is on `PATH` |
| Any | `tty` | opens `/dev/tty` (`CONIN$` on Windows), disables echo, reads value, prints the scope choice menu | the fallback, or `QBIT_VAULT_PROMPT=tty` |

The dialog always shows: secret name, the reason verbatim (control and bidi characters shown as visible escapes, so a reason cannot add a line or paint over the dialog), the host and session id, the project label (or `global`), and whether the value is **new** or **already stored (it will be replaced)**. When the value is new and `cwd` is inside a repository, the dialog also asks for the layer (`Global` / `This project`). For `secret_manage` the same backends render a confirmation (`prompt --confirm`) with the action, the diff and `Confirm` / `Decline`; closing the dialog or pressing Esc is `Decline`, and on Windows and macOS so is Enter (the default button). A passphrase asked twice (`init`) is two dialogs.

**Several fields in one prompt** (CONTRACT `request` with `fields`, R-CAP-08). The request text, the layer question and the scope choice appear once; every new field gets its own box labelled with its `label` (default the name), masked for `secret` and visible for `text`; stored fields are listed as *already stored* without a box. PowerShell renders one WinForms form with one `TextBox` per field (`UseSystemPasswordChar` only on secret ones; each value comes back as one base64 line on the helper's private stdout); zenity uses one `--forms` dialog (`--add-password` for secret fields, `--add-entry` for text ones, answers split on a control-character separator); osascript and kdialog have no multi-field form, so they show one box per field in a row, each repeating the request header and a `field 2 of 3` line, and cancelling any box cancels the whole capture; the terminal does the same with one line per field (echo off for secret fields, on for text fields). Empty boxes, a cancel or the timeout store nothing (R-CAP-04).

**Remote sync prompts.** `remote register`, `join`, `approve`, `revoke-device`, `recovery-key --rotate`, `resolve`, `restore`, `logout` and `link` ask and display through the same backends: the invite code and the recovery key in a masked box, the pairing and confirmation codes in a visible one, and the recovery key and the confirmation code shown in a dialog (or on the controlling terminal) that is never the command's stdout (`REMOTE_SYNC.md` § 4).

**Showing what the user must keep.** The recovery key and the pairing confirmation code (REMOTE_SYNC.md § 4) are shown out of band, never on stdout, stderr or `--json`. Their text never travels in a helper's argv, because any local user can read a process's command line: PowerShell and osascript get it inside the script on stdin, zenity through `--text-info` reading stdin, the terminal backend writes it to the controlling terminal and waits for Enter. kdialog takes text only as arguments, so it reports `prompt backend unavailable` for these screens; set `QBIT_VAULT_PROMPT=tty` or install zenity. Every line is escaped like any request text.

**Where the helper is found.** `powershell.exe` and `osascript` are run from their fixed system locations and are never looked up on `PATH`, because anything that can put a file earlier on `PATH` could stand in for the dialog and receive the value. On Windows the directory comes from the system API (`GetSystemWindowsDirectory`), with `C:\Windows` as fallback, and the file must exist; from WSL, forcing `powershell` uses `/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe` when it exists. `zenity` and `kdialog` have no single fixed location on Linux, but they are not taken from `PATH` either: they are looked up only in `/usr/bin`, `/bin` and `/usr/local/bin`, in that order, and the backend is unavailable when none holds them. No helper is located through `PATH`.

**Input rules, identical on every backend.** A secret value loses its line terminator and surrounding whitespace (R-CAP-04, the same `bytes.TrimSpace` rule as `set --stdin`). A passphrase loses only its line terminator, never other whitespace, so the same passphrase derives the same key whether it was typed in a dialog, on the terminal or given to `init --passphrase-stdin`. Input longer than the read bound (64 KiB plus margin) is refused with `value too large` and wiped, never truncated.

**How the value comes back.** The value never travels on qbit-vault's own stdout, which the host can read. It comes back on the **helper's** stdout: a private anonymous pipe between the dialog helper and qbit-vault that the agent does not hold. The helper's script or arguments carry the request text only (for PowerShell as base64 data, for AppleScript as escaped literals, for zenity and kdialog as single argv elements), never a value, and the helper's environment is qbit-vault's own with nothing added. qbit-vault reads the pipe as bytes into one buffer and wipes it after copying the value into a `Secret`; a failing or cancelled helper yields only a typed error (`cancelled`, `prompt timed out`, or `prompt backend unavailable`) with none of the helper's output. A dialog that cannot open when it was selected (no display, helper crashed) is the unavailable error, not a silent retry on the terminal.

`prompt --value` hands the value to the host on file descriptor 3, which POSIX hosts can open. Windows does not pass numbered descriptors to child processes, so there `--value` is refused; a Windows host captures with its own prompt (the Pi extension's masked input) or lets `set` open the native dialog, and stores with `set --stdin`.

## Deny-list alignment with Gentle AI

When the Gentle AI permissions component is installed, `init`:
1. Reads the existing deny entries for the host.
2. Adds `$QBIT_VAULT_HOME/**` if missing.
3. Verifies every pre-existing Gentle AI entry is still present after the merge; aborts and restores the snapshot otherwise (PRD R-INS-05).

## Implicit bindings

See `ARCHITECTURE.md` § Implicit binding table. The same `bindings.yaml` is read by the Pi extension, the Claude Code hook and the OpenCode plugin, so behavior is identical.

## Subagents

A subagent is a new session id (Pi subagents and Gentle Agents get their own; Claude Code subagents share `session_id` but hooks receive a distinct `agent_id`, which the hook appends: `claude:<session_id>/<agent_id>`). No grant inheritance (R-GRANT-05). The user sees a separate prompt naming the subagent.
