# CLI reference

`gentle-vault [global flags] <command> [flags]`

Global flags: `--home <dir>` (default `$GENTLE_VAULT_HOME` or `~/.gentle-vault`), `--json` (machine output, exactly one JSON object on stdout), `--session <id>` (host session; required by `exec`, `set --grant`, `grant`, `revoke --session-only`), `--quiet`, `--no-color`.

Values are **never** accepted as arguments. `set` and `import` read from the masked prompt or stdin.

**Layers.** Every secret is either `global` or belongs to the project (repository) of the current directory. Commands that take `NAME` act on the record that `NAME` resolves to from the current directory (project first, then global); `--global` or `--project` picks a layer explicitly. `--project` outside a repository fails with `no_project` (exit 3).

## Setup

| Command | What it does |
| --- | --- |
| `version [--json]` | Print version, commit and platform. Human: `gentle-vault <version> (<commit>, <os>/<arch>)`. JSON: `{"ok":true,"version":…,"commit":…,"go":…,"os":…,"arch":…}`. |
| `init [--agents claude-code,codex,opencode,pi,gentle-shell] [--no-extension] [--passphrase] [--passphrase-stdin]` | Full one-shot setup. See INSTALL.md. Idempotent. **Until slice 3.6 `init` is vault-only**: it creates the master key and an empty vault and nothing else (no host registration; `--agents` and `--no-extension` do not exist yet). `--passphrase` keeps the key in `key.enc` instead of the OS keychain and, until the interactive prompt arrives (slice 1.9), needs `--passphrase-stdin` (first line of stdin). If the vault already exists it exits 0 and reports `initialized: false`. If creating the vault fails, the key just created is removed. |
| `sync` | Re-apply host registrations from `state.json` receipts (after upgrades). |
| `doctor [--json]` | Read-only health report. Exit 0 healthy, 1 warnings, 2 errors. |
| `uninstall [--purge]` | Revert every host change from snapshots, remove the extension. `--purge` also deletes the vault after the user types `purge`. |
| `update [--check]` | Download, verify (Minisign + checksums) and replace the binary. Opt-out of the background check with `config.update_check: false`. |

## Secrets

| Command | What it does |
| --- | --- |
| `set NAME [--global\|--project] [--stdin] [--description D] [--sensitive] [--binaries gh,git] [--hosts api.github.com] [--grant once\|session\|project] [--reason R]` | Store or replace a value. Interactive: masked prompt; inside a repository with neither layer flag it also asks *global or this project*. `--stdin`: read value from stdin (used by hosts). `--grant` also creates a grant for `--session` in the same call (used by the capture flow so first use costs one prompt). **Until slice 1.9, `--stdin` is required** (without it: usage error `interactive capture is not available yet; use --stdin`), the interactive layer question does not exist (inside a repository pass `--global` or `--project`, else usage error `choose --global or --project`; outside one, `set` writes to the global layer), and `--grant` arrives with grants in slice 1.6. Surrounding whitespace is trimmed, the trimmed value is at most 64 KiB, and a blank value is a usage error (`empty value`) that writes nothing. Replacing a secret keeps the metadata you do not pass again. |
| `rm NAME [--global\|--project] [--yes]` | Delete value and all its grants. Without a layer flag it deletes the record `NAME` resolves to. **`--yes` is required** until the interactive confirmation arrives (slice 1.9), on a terminal or not (usage error `confirmation required; pass --yes`). |
| `mv NAME --to global\|project [--yes]` | Move a secret between global and the current project. Keeps value and metadata, drops its grants, asks before overwriting a same-named secret in the target. Until the interactive confirmation arrives, an existing target is a usage error (`NAME already exists in <layer>; pass --yes to overwrite`) unless `--yes` is given. Outside a repository it fails with `no_project`. |
| `list [--layer here\|global\|project\|all] [--json]` | Names and metadata, never values. `here` (default): what resolves from this directory, marking project overrides. `global`: only the global layer. `project`: only this repository's layer (`no_project` outside one). `all`: every layer including other projects. Human output is a table `NAME  LAYER  DESCRIPTION` (`LAYER` is `global` or `project:<label>`; overrides are marked `(overrides global)`); an empty result prints `no secrets`. |
| `describe NAME [--global\|--project]` | Metadata, layer and active grants for one secret. Grants are always `[]` until slice 1.6. |
| `edit NAME [--global\|--project] [--description] [--sensitive=true\|false] [--binaries] [--hosts]` | Change metadata, never the value. At least one change flag is required (usage error otherwise). |
| `relink OLD_ROOT NEW_ROOT` | Repoint a project layer and its `project` grants after moving or re-cloning a repository. `OLD_ROOT` must be an existing project layer (it need not exist on disk); `NEW_ROOT` must be a repository root (contains `.git`, else `no_project`) without a layer of its own. Grants are repointed from slice 1.6. |
| `import --from-env NAME[,NAME…]` / `import --from-file PATH [--names A,B]` | Explicit, user-run import from the current environment or a dotenv file. Never run by `init`. Prints what it imported by name and offers to unset/remove the source. |
| `rekey` | Rotate the master key. |
| `lock` / `unlock` | Passphrase mode: drop / refresh the cached master key. |
| `restore [--list] [--from TS]` | Restore the vault from an encrypted backup. |

## Grants

| Command | What it does |
| --- | --- |
| `grant NAME [--global\|--project] --scope once\|session\|project [--ttl 30m]` | Interactive confirmation then grant. Refuses when stdin is not a TTY unless `--from-prompt-token` is present. |
| `revoke NAME \| --all \| --session-only` | Revoke grants. |
| `grants [--json]` | Active grants with expiry. |

### Success output (`--json`)

Every success is exactly one object with `"ok":true`. `project` is `{"root":…,"label":…}` or `null`; `layer` is `"global"` or `"project"`.

| Command | Shape |
| --- | --- |
| `init` | `{"ok":true,"initialized":true,"home":…,"keychain":"<mode>"}`; already initialized: `{"ok":true,"initialized":false,"home":…}` |
| `set` | `{"ok":true,"name":…,"layer":…,"project":…,"replaced":bool}` |
| `rm` | `{"ok":true,"name":…,"layer":…,"removed":true}` |
| `edit` | `{"ok":true,"name":…,"layer":…,"project":…,"updated":true}` |
| `describe` | `{"ok":true,"name":…,"layer":…,"project":…,"overrides_global":bool,"description":…,"sensitive":bool,"binaries":[…],"hosts":[…],"created_at":…,"updated_at":…,"grants":[]}` |
| `list` | `{"ok":true,"project":…,"secrets":[{"name":…,"layer":…,"project_label":… (project records only),"overrides_global":bool,"description":…,"sensitive":bool,"binaries":[…],"hosts":[…],"created_at":…,"updated_at":…}]}` (`project` is the project of the current directory) |
| `mv` | `{"ok":true,"name":…,"from":…,"to":…,"project":…}` |
| `relink` | `{"ok":true,"from":…,"to":…,"secrets":N}` |

No success output ever contains a value.

### Manual entry (no agent involved)

```
gentle-vault set GITHUB_TOKEN --global       # masked prompt, available everywhere
cd ~/code/shop-api
gentle-vault set DATABASE_URL                 # asks: global or this project (shop-api)?
gentle-vault list                             # GITHUB_TOKEN (global), DATABASE_URL (shop-api)
```

The same flow exists as `/vault set NAME` inside Pi / Gentle Shell. With Claude Code, Codex or OpenCode, run it in any other terminal. When `set` has no TTY attached (for example when launched by a host's shell escape) it opens the native dialog instead (`AGENT_INTEGRATIONS.md` § Native capture dialog), so the value never goes through the host's output and only `{ok}` is printed.

## Exec

```
gentle-vault exec --session S --secret NAME[=ENV] [--secret …] [--timeout 10m] [--shell auto|sh|bash|cmd|pwsh] [--cwd DIR] [--stream] -- <command…>
```

- Each `--secret NAME` injects vault secret `NAME` as env var `NAME`; `--secret GH_TOKEN=GITHUB_TOKEN` injects `GITHUB_TOKEN`'s value as `GH_TOKEN`.
- `--stream`: stdout/stderr forwarded as redacted chunks as they arrive (NDJSON `{"stream":"stdout","chunk":"…"}` with `--json`, raw otherwise), final record carries `exit_code`.
- Exit code: the child's. Refusals exit 3 with the typed refusal on stdout (`--json`) or stderr.

## Audit

| Command | What it does |
| --- | --- |
| `audit [--tail N] [--since 24h] [--name NAME] [--event exec] [--json]` | Read the log. |
| `audit --verify` | Validate the hash chain. |

## Host plumbing (not for humans)

| Command | Used by |
| --- | --- |
| `mcp` | Hosts start it as a stdio MCP server. Env: `GENTLE_VAULT_SESSION` (optional). |
| `hook pre-bash` / `hook post-bash` / `hook post-read` / `hook user-prompt` | Claude Code hooks: read the hook JSON on stdin, write the hook decision JSON on stdout. |
| `prompt --name NAME --reason R [--value] [--scopes once,session,project] [--layers global,project]` | Opens the native capture dialog; prints `{token, scope, layer, value_on_fd:3}`; used internally by `request` on non-Pi hosts. |
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

Failures that are not typed refusals (usage errors, `not_initialized`, internal errors, panics) never print free-form output in `--json` mode: stdout carries exactly one object `{"ok":false,"error":{"code":"usage"|"not_initialized"|"internal","message":"…"}}` and nothing else. Without `--json`, stderr gets `error: <message>` (usage errors add `Run 'gentle-vault --help' for usage.`). A usage error includes an invalid `--session` (must match `^[a-z0-9-]+:[A-Za-z0-9._-]{4,128}$`) and running with `--json` but no command. `--help` is always human text with exit 0. Panics print only `internal error`, never the panic value.

## Environment variables

| Var | Effect |
| --- | --- |
| `GENTLE_VAULT_HOME` | Vault directory |
| `GENTLE_VAULT_SESSION` | Default `--session` |
| `GENTLE_VAULT_PROMPT` | Force a prompt backend: `osascript`, `powershell`, `zenity`, `kdialog`, `tty` |
| `GENTLE_VAULT_NO_UPDATE_CHECK=1` | Disable update check |
| `NO_COLOR` | Honored |
