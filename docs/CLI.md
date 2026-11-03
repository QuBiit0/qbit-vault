# CLI reference

`gentle-vault [global flags] <command> [flags]`

Global flags: `--home <dir>` (default `$GENTLE_VAULT_HOME` or `~/.gentle-vault`), `--json` (machine output, exactly one JSON object on stdout), `--session <id>` (host session; required by `exec`, `set --grant`, `grant`, `revoke --session-only`), `--quiet`, `--no-color`.

Values are **never** accepted as arguments. `set` and `import` read from the masked prompt or stdin.

**Layers.** Every secret is either `global` or belongs to the project (repository) of the current directory. Commands that take `NAME` act on the record that `NAME` resolves to from the current directory (project first, then global); `--global` or `--project` picks a layer explicitly. `--project` outside a repository fails with `no_project` (exit 3).

## Setup

| Command | What it does |
| --- | --- |
| `version [--json]` | Print version, commit and platform. Human: `gentle-vault <version> (<commit>, <os>/<arch>)`. JSON: `{"ok":true,"version":…,"commit":…,"go":…,"os":…,"arch":…}`. |
| `init [--agents claude-code,codex,opencode,pi,gentle-shell] [--no-extension] [--passphrase] [--passphrase-stdin]` | Full one-shot setup. See INSTALL.md. Idempotent. **Until slice 3.6 `init` is vault-only**: it creates the master key and an empty vault and nothing else (no host registration; `--agents` and `--no-extension` do not exist yet). `--passphrase` keeps the key in `key.enc` instead of the OS keychain. Without `--passphrase-stdin` the passphrase is asked twice on the controlling terminal (`/dev/tty`, `CONIN$`; input hidden, never read from stdin); a mismatch is the usage error `passphrases do not match`, Ctrl-C or end of input is `cancelled` (exit 1), a blank one is `empty passphrase`, and none of them creates anything. With no controlling terminal it is the usage error `no controlling terminal available; use --passphrase-stdin`. `--passphrase-stdin` reads the first line of stdin instead. If the vault already exists it exits 0 and reports `initialized: false`. If creating the vault fails, the key just created is removed. |
| `sync` | Re-apply host registrations from `state.json` receipts (after upgrades). |
| `doctor [--json]` | Read-only health report. Exit 0 healthy, 1 warnings, 2 errors. |
| `uninstall [--purge]` | Revert every host change from snapshots, remove the extension. `--purge` also deletes the vault after the user types `purge`. |
| `update [--check]` | Download, verify (Minisign + checksums) and replace the binary. Opt-out of the background check with `config.update_check: false`. |

## Secrets

| Command | What it does |
| --- | --- |
| `set NAME [--global\|--project] [--stdin] [--description D] [--sensitive] [--binaries gh,git] [--hosts api.github.com] [--grant once\|session\|project] [--reason R]` | Store or replace a value. Without `--stdin` it is interactive: inside a repository with neither layer flag it first asks *global or this project (label)* (default global), then shows the request (name, reason `manual entry`, host, session, layer, whether the value is new or already stored) and reads the value from the controlling terminal with echo off (`/dev/tty`, `CONIN$`; never from stdin; nothing is echoed, not even a mask). Blank input is the usage error `empty value`, input over 64 KiB `value too large`, Ctrl-C or end of input at any question is `cancelled` (exit 1, stderr `error: cancelled`); none of them writes anything. With no controlling terminal it is the usage error `no controlling terminal available; use --stdin`. Interactive `--grant once\|session\|project` is the proposed scope: after the value a menu offers the scopes this secret and session allow (`once` only for a sensitive one, `project` only on a project secret, `once` and `session` only with `--session`) plus `no grant (store the value only)`, and choosing one is the confirmation (the grant is audited as `prompt token`); a grant that cannot be made is refused before the value is asked. `--from-prompt-token` is `--stdin` only (usage error `--from-prompt-token needs --stdin`). `--stdin`: read value from stdin (used by hosts). `--grant` also creates a grant for `--session` in the same call (used by the capture flow so first use costs one prompt); because stdin carries the value there is no question to ask, so `--grant` **requires `--from-prompt-token T`** (usage error `--grant requires --from-prompt-token`; `--from-prompt-token` alone is `--from-prompt-token requires --grant`), and the token is checked, and the scope validated (a `sensitive` secret accepts `once` only), **before** anything is stored: a refused grant stores nothing. Replacing the value of an existing secret drops that record's grants (R-API-07). With `--stdin` there is no layer question: inside a repository pass `--global` or `--project`, else usage error `choose --global or --project`; outside one, `set` writes to the global layer. Surrounding whitespace is trimmed, the trimmed value is at most 64 KiB, and a blank value is a usage error (`empty value`) that writes nothing. Replacing a secret keeps the metadata you do not pass again. |
| `rm NAME [--global\|--project] [--yes]` | Delete value and all its grants. Without a layer flag it deletes the record `NAME` resolves to. Without `--yes` it asks `Remove NAME (<layer>)? [y/N]` on the controlling terminal; anything but `y`/`yes`, Ctrl-C or end of input is `cancelled` (exit 1) and removes nothing. With no controlling terminal it is the usage error `confirmation required; pass --yes`. `--yes` never asks (for scripts). |
| `mv NAME --to global\|project [--yes]` | Move a secret between global and the current project. Keeps value and metadata, drops its grants, asks before overwriting a same-named secret in the target: `NAME already exists in <layer>; overwrite? [y/N]` on the controlling terminal (a no or cancel is `cancelled`, exit 1, and nothing moves), or, with no controlling terminal, the usage error `NAME already exists in <layer>; pass --yes to overwrite`. `--yes` overwrites without asking. Outside a repository it fails with `no_project`. |
| `list [--layer here\|global\|project\|all] [--json]` | Names and metadata, never values. `here` (default): what resolves from this directory, marking project overrides. `global`: only the global layer. `project`: only this repository's layer (`no_project` outside one). `all`: every layer including other projects. Human output is a table `NAME  LAYER  DESCRIPTION` (`LAYER` is `global` or `project:<label>`; overrides are marked `(overrides global)`); an empty result prints `no secrets`. |
| `describe NAME [--global\|--project]` | Metadata, layer and active grants for one secret. `grants` lists the active grants of that record only (a grant on the global `NAME` is not shown on the project `NAME`): `{"scope","session","expires_at"}` each; human output shows `none` or `<scope>, for <session>, until <time>` (`until revoked` for `project`). |
| `edit NAME [--global\|--project] [--description] [--sensitive=true\|false] [--binaries] [--hosts]` | Change metadata, never the value. At least one change flag is required (usage error otherwise). Making a secret `sensitive` drops its `session` and `project` grants (a `once` grant stays) in the same operation; the JSON then carries `grants_dropped`. Other edits keep their grants. |
| `relink OLD_ROOT NEW_ROOT` | Repoint a project layer after moving or re-cloning a repository. `OLD_ROOT` must be an existing project layer (it need not exist on disk); `NEW_ROOT` must be a repository root (contains `.git`, else `no_project`) without a layer of its own. **Grants do not follow the layer:** every grant of the old project layer is dropped (relink can only narrow access) and the user grants again for the new root; the output reports `grants_dropped`. |
| `import --from-env NAME[,NAME…]` / `import --from-file PATH [--names A,B]` | Explicit, user-run import from the current environment or a dotenv file. Never run by `init`. Prints what it imported by name and offers to unset/remove the source. |
| `rekey` | Rotate the master key. |
| `lock` / `unlock` | Passphrase mode: drop / refresh the cached master key. |
| `restore [--list] [--from TS]` | Restore the vault from an encrypted backup. |

## Grants

| Command | What it does |
| --- | --- |
| `grant NAME [--global\|--project] --scope once\|session\|project [--ttl 30m] [--from-prompt-token T]` | Grant the record `NAME` resolves to (or the layer named by the flag) after an explicit confirmation. `once` and `session` need `--session` (usage error otherwise); `project` binds to the repository root of the record and needs no session. `--ttl` (session scope only, 1m to 24h, default 30m) is a usage error elsewhere or out of range. A `sensitive` secret accepts `once` only, and `project` scope on a global record has no project to bind to: both are refused as `scope_not_allowed` before any question is asked (the second with the message `project scope needs a project secret`). Confirmation (L5): with `--from-prompt-token` the token must be valid for exactly this name, layer, scope, session and TTL (an omitted `--ttl` means the 30m default, so `--ttl 30m` and no `--ttl` are the same binding; a different `--ttl` is refused and burns the token), and for this record when the token was issued for one; otherwise the question `Grant NAME (<layer>) to <session or "this project">, scope <scope>? [y/N] ` is asked on the controlling terminal (L4; never on stdin, so a pipe cannot answer it); only `y` or `yes` (any case) confirms, anything else, Ctrl-C or end of input is `user_declined`. With no controlling terminal and no token: refusal `not_model_callable` (exit 3, audited as a refusal). The `grant` audit record is written **before** the grant is stored; if it cannot be written the grant is not created (refusal `internal`). A repeat grant replaces the identical one. Human: `granted NAME (<layer>): <scope>, for <session>, until <time>` (`until revoked` for `project`). |
| `revoke NAME [--global\|--project] \| --all \| --session-only` | Revoke grants; no confirmation (it only narrows access) and effective for the next check (R-GRANT-06). Give exactly one of `NAME`, `--all` or `--session-only` (usage error otherwise). `NAME` alone revokes it in every layer, with `--global`/`--project` in that layer only; `--all` also discards pending prompt tokens; `--session-only` revokes the grants of `--session` (project grants have no session and stay). Human: `revoked N grants`. The `revoke` audit record is best effort. |
| `grants [--json]` | Active grants (expired and used `once` grants are purged first): name, layer, scope, session, expiry and time remaining. Human output is a table `NAME  LAYER  SCOPE  SESSION  EXPIRES  REMAINING` (`-` where it does not apply), or `no active grants`. |

If `grants.enc` could not be trusted (corrupt, or older than recorded: a rollback) any command that touches grants prints `warning: grants were reset (store unreadable or rolled back)` on stderr, records an audit `warning` (`grants reset`), and carries on with no grants (`STORAGE.md` § Grants).

### Success output (`--json`)

Every success is exactly one object with `"ok":true`. `project` is `{"root":…,"label":…}` or `null`; `layer` is `"global"` or `"project"`.

| Command | Shape |
| --- | --- |
| `init` | `{"ok":true,"initialized":true,"home":…,"keychain":"<mode>"}`; already initialized: `{"ok":true,"initialized":false,"home":…}` |
| `set` | `{"ok":true,"name":…,"layer":…,"project":…,"replaced":bool}` plus `"grants_dropped":N` when a replacement dropped grants, and `"grant":{…}` (as in `grant`) with `--grant` |
| `rm` | `{"ok":true,"name":…,"layer":…,"removed":true}` plus `"grants_dropped":N` when N > 0 |
| `edit` | `{"ok":true,"name":…,"layer":…,"project":…,"updated":true}` plus `"grants_dropped":N` when N > 0 |
| `describe` | `{"ok":true,"name":…,"layer":…,"project":…,"overrides_global":bool,"description":…,"sensitive":bool,"binaries":[…],"hosts":[…],"created_at":…,"updated_at":…,"grants":[{"scope":…,"session":…|null,"expires_at":…|null}]}` |
| `list` | `{"ok":true,"project":…,"secrets":[{"name":…,"layer":…,"project_label":… (project records only),"overrides_global":bool,"description":…,"sensitive":bool,"binaries":[…],"hosts":[…],"created_at":…,"updated_at":…}]}` (`project` is the project of the current directory) |
| `mv` | `{"ok":true,"name":…,"from":…,"to":…,"project":…}` plus `"grants_dropped":N` when N > 0 |
| `relink` | `{"ok":true,"from":…,"to":…,"secrets":N}` plus `"grants_dropped":N` when N > 0 |
| `grant` | `{"ok":true,"grant":{"name":…,"layer":…,"scope":…,"session":…|null,"expires_at":…|null}}` (`expires_at` is `null` for `project`) |
| `revoke` | `{"ok":true,"revoked":N}` |
| `grants` | `{"ok":true,"grants":[{"name":…,"layer":…,"project":…,"scope":…,"session":…|null,"expires_at":…|null,"remaining":…|null}]}` (`remaining` is a duration such as `29m30s`) |
| `audit` | `{"ok":true,"records":[…]}` |
| `audit --verify` | `{"ok":true,"valid":bool,"records":N}` plus `"problem":{"line":L,"seq":S,"reason":…}` when not valid |

No success output ever contains a value.

### Manual entry (no agent involved)

```
gentle-vault set GITHUB_TOKEN --global       # masked prompt, available everywhere
cd ~/code/shop-api
gentle-vault set DATABASE_URL                 # asks: global or this project (shop-api)?
gentle-vault list                             # GITHUB_TOKEN (global), DATABASE_URL (shop-api)
```

The same flow exists as `/vault set NAME` inside Pi / Gentle Shell. With Claude Code, Codex or OpenCode, run it in any other terminal. The prompt reads the controlling terminal, not stdin, so a pipe cannot answer it. When there is no controlling terminal (for example when launched by a host's shell escape without one) `set` fails with `no controlling terminal available; use --stdin`; opening the native dialog instead (`AGENT_INTEGRATIONS.md` § Native capture dialog) arrives with slice 1.10.

## Exec

```
gentle-vault exec --session S --secret NAME[=ENV] [--secret …] [--timeout 10m] [--shell auto|sh|bash|cmd|pwsh] [--cwd DIR] [--stream] -- <command…>
```

- Each `--secret NAME` injects vault secret `NAME` as env var `NAME`; `--secret GH_TOKEN=GITHUB_TOKEN` injects `GITHUB_TOKEN`'s value as `GH_TOKEN`.
- `--stream`: stdout/stderr forwarded as redacted chunks as they arrive (NDJSON `{"stream":"stdout","chunk":"…"}` with `--json`, raw otherwise), final record carries `exit_code`.
- **Command.** The words after `--` are joined with single spaces and handed to the shell as one command string; they are not re-quoted. At most 16 `--secret` flags; `--timeout` between 1s and 1h; the command is 1 to 16384 bytes.
- **Shell.** `auto` is `/bin/sh -c` on POSIX; on Windows it is `bash -c` when `bash` is on PATH (Git Bash), else `cmd /d /s /c`. `sh`, `bash`, `cmd` and `pwsh` force one; an unavailable shell is a usage error.
- **Order of checks.** (1) resolve every secret from the working directory (`--cwd`, default the current one); (2) grants, looking only; (3) dump-command guard (`dump_command`) over the injected variable names; (4) binary allowlist over every pipeline segment (`scope_binary`); (5) hosts advisory (the audit record notes `hosts warning`, the run goes on); (6) consume `once` grants and append the `started` audit record, fail-closed; (7) run. Any refusal runs nothing.
- **Environment.** The child gets the parent environment minus every variable named like a vault secret (case-insensitive on Windows), plus the granted values. The parent is never modified. The child inherits stdin.
- **Output.** Human mode streams the child's redacted stdout/stderr to ours. `--json` prints one object `{"ok":true,"exit_code":N,"stdout":"…","stderr":"…","duration_ms":N,"redactions":N,"truncated":bool}`; each stream is capped at 1 MiB keeping the tail. `--json --stream` prints NDJSON: `{"stream":"stdout|stderr","chunk":"…"}` lines as output arrives, then a final `{"exit_code":N,"duration_ms":N,"redactions":N}`.
- **Timeout.** On expiry the whole process tree is killed (POSIX process group, Windows job object) and the refusal `timeout` (exit 3) is returned; with `--json` it carries `partial: {stdout, stderr}`, in human mode the partial stdout was already streamed. SIGINT/SIGTERM kill the tree and exit 130.
- **Wrapper flags and allowlists.** Wrappers (`sudo`, `env`, `timeout`, `nice`, `strace`, `xargs`, ...) are resolved with an explicit table of known flags. A flag outside the table, or a short-flag cluster whose letters are not all known, is ambiguous and the command is refused with `scope_binary` when an injected secret has a `binaries` list. Write such commands without the unusual flags, or call the program directly.
- **`--shell cmd` / `pwsh` and allowlists.** The dump guard and the binary allowlist split commands with POSIX grammar, which cmd.exe and PowerShell do not follow. So when the effective shell (after resolving `auto`) is cmd or pwsh and any injected secret has a non-empty `binaries` list, `exec` only accepts a single simple command: one containing none of the characters that shell can use to chain, start or substitute commands (cmd: `& | < > ^ % ! ( ) "` and line breaks; pwsh: `; & | < > ` + "`" + ` $ ( ) { } @ " '` and line breaks), whose first word, wrappers not resolved, is in every list. Anything else is refused with `scope_binary`. In those two shells the dump guard also tests the raw command, split at every separator and ignoring quotes, so it can refuse more than under `sh`/`bash`.
- **Exit code:** the child's. On POSIX a child killed by a signal exits `128+signal` (137 for SIGKILL); on Windows the code is whatever the OS reports. Refusals exit 3 with the typed refusal on stdout (`--json`) or stderr.

## Audit

| Command | What it does |
| --- | --- |
| `audit [--tail N] [--since 24h] [--name NAME] [--event exec] [--json]` | Read the log, oldest first, filters combined, `--tail` (default 50) applied last. `--since` takes a positive Go duration (`90m`, `24h`); `--event` one of the events in STORAGE.md § Audit log; `--name` a valid secret name; anything else is a usage error. Works without unlocking the vault. Human: one line per record, `<ts> <event> <names joined by ,> <layer> <session>` plus `exit=<code>` when present (`-` for empty names or layer); an empty result prints `no audit records`. JSON: `{"ok":true,"records":[…]}` (the records as stored). |
| `audit --verify [--json]` | Validate the hash chain; cannot be combined with the filters. Human: `audit log ok (N records)` (`1 record` for one), exit 0, or `audit log broken at line L (seq S): <reason>`, exit 1, both on stdout. JSON: `{"ok":true,"valid":true,"records":N}` or `{"ok":true,"valid":false,"records":N,"problem":{"line":L,"seq":S,"reason":"…"}}` with exit 1 (`records` counts the records that verified before the problem). Reasons: `bad_json`, `bad_hash`, `bad_prev`, `bad_seq`, `partial_line`, `truncated`, `head_mismatch`. |

Without a vault home both forms fail with `not_initialized` (exit 1). `init`, `set`, `rm`, `edit`, `mv`, `relink` and every typed refusal append a record; if that write fails the command still succeeds (or refuses) as before and prints `warning: audit log write failed` on stderr.

## Host plumbing (not for humans)

| Command | Used by |
| --- | --- |
| `mcp` | Hosts start it as a stdio MCP server. Env: `GENTLE_VAULT_SESSION` (optional). |
| `hook pre-bash` / `hook post-bash` / `hook post-read` / `hook user-prompt` | Claude Code hooks: read the hook JSON on stdin, write the hook decision JSON on stdout. |
| `prompt --name NAME --reason R [--value] [--scopes once,session,project] [--layers global,project]` | The broker's own prompt, **terminal backend only in this release** (native dialogs arrive with slice 1.10; `GENTLE_VAULT_PROMPT` other than `tty` is refused as `prompt backend <name> arrives in a later release`). On the controlling terminal it asks *which layer* (when `--layers` allows both and the working directory is in a repository; default the first listed), shows the request, with `--value` reads the value with echo off, then asks *which scope* (`--scopes` ∩ what the secret and `--session` allow; the last entry is `deny`). It issues a prompt token (2 minutes, single use) and prints `{"ok":true,"token":"…","scope":"…","layer":"…"}` (plus `"value_on_fd":3` with `--value`); the host redeems it with `grant --from-prompt-token` or `set --stdin --grant --from-prompt-token`. Without `--value` the secret must exist and the token is bound to its record; with `--value` it is bound to no record, because the value is stored afterwards. The value is written only to file descriptor 3, never to stdout; `--value` with fd 3 not open is the usage error `--value needs file descriptor 3 to be open`, and **on Windows `--value` is refused** (`--value is not supported on Windows until the native prompt arrives`) until slice 1.10. `deny` is the refusal `user_declined`; Ctrl-C is `cancelled` (exit 1); both leave the vault unchanged. `--reason` is required and at most 1024 bytes; it is shown escaped (control characters and bidi marks become visible escapes). Used internally by `request` on non-Pi hosts. |
| `prompt --confirm --action remove\|edit\|move\|replace --name NAME --layer L --reason R [--diff JSON]` | Opens the native confirmation for a `manage` proposal; prints `{token, confirmed}`. |
| `broker --op <op>` | Raw contract call with the envelope on stdin; used by the Pi extension and by conformance tests. |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (for `exec`: child exited 0) |
| 1 | Generic failure / doctor warnings |
| 2 | Usage error / doctor errors |
| 3 | Typed refusal (see CONTRACT.md) |
| 4 | Vault locked |
| 5 | Vault corrupt / rollback detected |
| N | `exec`: child's exit code when > 5 is ambiguous; `--json` always carries the real `exit_code` |

Typed refusals (exit 3, 4, 5) print the contract envelope `{"ok":false,"refusal":{"type":…,"name":…,"message":…,"retryable":…}}` on stdout with `--json`, and `error: <message>` on stderr otherwise. Operating on a home with no vault is not a refusal: it exits 1 with code `not_initialized` and message `no vault here; run 'gentle-vault init'`. A vault held by another process is the refusal `internal` with `retryable: true` and message `vault is busy` (until the contract has a dedicated type).

Failures that are not typed refusals (usage errors, `not_initialized`, internal errors, panics) never print free-form output in `--json` mode: stdout carries exactly one object `{"ok":false,"error":{"code":"usage"|"not_initialized"|"cancelled"|"internal","message":"…"}}` and nothing else. Without `--json`, stderr gets `error: <message>` (usage errors add `Run 'gentle-vault --help' for usage.`). A usage error includes an invalid `--session` (must match `^[a-z0-9-]+:[A-Za-z0-9._-]{4,128}$`) and running with `--json` but no command. `--help` is always human text with exit 0. The code `cancelled` (exit 1, message `cancelled`) is a user who gave up at a prompt: Ctrl-C, end of input, or a no to a confirmation; nothing was changed. Panics print only `internal error`, never the panic value.

## Environment variables

| Var | Effect |
| --- | --- |
| `GENTLE_VAULT_HOME` | Vault directory |
| `GENTLE_VAULT_SESSION` | Default `--session` |
| `GENTLE_VAULT_PROMPT` | Force a prompt backend: `osascript`, `powershell`, `zenity`, `kdialog`, `tty`. **In this release only `tty` (the default) exists**; the others fail with `prompt backend <name> arrives in a later release` until slice 1.10, and any other value is a usage error naming the variable. |
| `GENTLE_VAULT_NO_UPDATE_CHECK=1` | Disable update check |
| `NO_COLOR` | Honored |
