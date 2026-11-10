# Contract: `qbit-vault.secrets-broker/v1`

Status: **draft 1.0.0-draft.2** (draft.2: `request` takes several typed fields; `list` reports `kind` and `unlinked_match`; `capabilities` reports field kinds and sync). Frozen on the first stable release; afterwards only additive changes under the same major, published as capability rows (`capabilities: 1.1`, `1.2`, ...). Consumers MUST refuse envelopes whose `contract` major they do not implement.

This contract defines the only surface through which a host (an agent runtime, its hooks or its extension) talks to the broker. It is transport-independent: the same JSON objects travel over MCP tool calls and over the CLI (`broker --op`, `--json`); the Pi extension (planned, Phase 4) would use the CLI form. The Claude Code hooks do not carry contract traffic.

## Envelope

Every request and response carries:

```json
{ "contract": "qbit-vault.secrets-broker/v1", "op": "request", "v": 1, "session": "pi:2f1c…", "cwd": "/home/me/repo", ... }
```

| Field | Req | Description |
| --- | --- | --- |
| `contract` | yes | Literal `qbit-vault.secrets-broker/v1` |
| `op` | yes | One of `request`, `list`, `exec`, `manage`, `grant`, `revoke`, `capabilities` |
| `v` | yes | Operation schema version, integer, currently `1` for all ops |
| `session` | yes | Opaque host session id, `^[a-z0-9-]+:[A-Za-z0-9._-]{4,128}$` (prefix = host: `pi`, `claude`, `codex`, `cli`; the MCP server generates `mcp`) |
| `cwd` | yes | Absolute path of the working directory; used to resolve the repository root for the project layer and the `project` scope |
| `host` | no | `{ "name": "gentle-shell", "version": "3.7.0" }` for audit |

Responses carry `ok: true` with the op's payload, or `ok: false` with a **refusal** (see below). No other error shape exists.

## Layers

Every secret lives in one **layer**: `global`, or `project` (the repository that contains `cwd`). In requests, `layer: "project"` always means *the project of this envelope's `cwd`*; the model never names another repository, so it cannot reach another project's secrets. A name resolves to the project secret when one exists, else to the global one (`STORAGE.md` § Layers). Grants bind to the resolved layer.

## Operations

### `request` — ask for one or several secret handles (model-callable)

Request, one secret:
```json
{ "op": "request", "name": "GITHUB_TOKEN", "reason": "gh release create v1.2.0", "suggested_scope": "once", "suggested_layer": "global" }
```

Request, several fields in one prompt:
```json
{ "op": "request", "reason": "run the shop-api migrations against staging",
  "fields": [ { "name": "DB_HOST", "kind": "text", "label": "Host" },
              { "name": "DB_USER", "kind": "text", "label": "User" },
              { "name": "DB_PASSWORD", "label": "Password", "description": "staging db password" } ],
  "suggested_scope": "once", "suggested_layer": "project" }
```

| Field | Req | Rules |
| --- | --- | --- |
| `name` | one of `name`, `fields` | `^[A-Z][A-Z0-9_]{0,63}$`; shorthand for `fields: [{name}]` |
| `fields[]` | one of `name`, `fields` | 1–8 entries, names unique (a duplicate is `invalid_name`). Each `{name, kind?, label?, description?}`: `kind` `secret` (default; masked) or `text` (visible while typed); `label` ≤ 40 chars shown next to the box (default the name); `description` ≤ 200 chars, stored on a new record. Labels and descriptions are shown escaped, like `reason` |
| `reason` | yes | 8–200 chars, shown verbatim to the user; MUST NOT be empty or generic (`"needed"` is refused with `reason_too_vague` by a minimal heuristic: < 3 words) |
| `suggested_scope` | no | `once` \| `session` \| `project`; a hint only, the user chooses |
| `suggested_layer` | no | `global` \| `project`; a hint only, the user chooses. `project` outside a repository → `no_project` |

Behavior: the broker opens **one user-facing prompt** (host UI or native) for all fields. A field whose name resolves for `cwd` is shown as *already stored* and gets no box; every other field gets a box (masked for `secret`, visible for `text`). The prompt asks the layer once for the new values (when `cwd` is in a repository) and one scope for all fields, offering only scopes every field allows (a `sensitive` one limits all to `once`). It is all-or-nothing: a blank box, a cancel or a timeout stores nothing and grants nothing. On confirmation every new value is stored and every field's record is granted with the chosen scope. The model is not told which fields were already stored. A name in its cooldown makes the whole request `rate_limited` (naming it); a decline starts the cooldown for every name in the request. With sync enabled the broker pulls first (bounded, `REMOTE_SYNC.md` § 7.1), so a secret stored on another machine is found.

Response:
```json
{ "ok": true,
  "refs": [ { "name": "DB_HOST", "ref": "secret://DB_HOST", "layer": "project" },
            { "name": "DB_USER", "ref": "secret://DB_USER", "layer": "project" },
            { "name": "DB_PASSWORD", "ref": "secret://DB_PASSWORD", "layer": "project" } ],
  "grant": { "scope": "session", "expires_at": "2026-10-16T09:12:00Z" } }
```

A single-`name` request also carries `ref` and `layer` of that one field, so draft.1 callers keep working. `layer` is per field because a field already stored keeps its own layer. `expires_at` is `null` for `project`. For `once`, each field's grant is consumed by the next `exec` in the same session that references that name.

### `list` — enumerate handles (model-callable)

Request: `{ "op": "list" }`

Response:
```json
{ "ok": true,
  "project": { "root": "/home/me/shop-api", "label": "shop-api" },
  "secrets": [
  { "name": "GITHUB_TOKEN", "layer": "global", "overrides_global": false, "kind": "secret",
    "description": "GitHub PAT, repo scope", "sensitive": false,
    "binaries": ["gh", "git"], "hosts": ["api.github.com"],
    "created_at": "…", "updated_at": "…",
    "grant": { "scope": "session", "expires_at": "…" } },
  { "name": "DATABASE_URL", "layer": "project", "overrides_global": true, "…": "…", "grant": null } ],
  "unlinked_match": null,
  "policy": { "…": "see below" } }
```

`grant` is the grant `exec` would accept for this secret from `cwd` and this session (the same check, run without spending a `once` grant): `null` when none applies. A grant that exists but does not apply here is never shown as active. In that case the optional `grant_note` says why and what to do: `a project grant exists for another directory; call secret_request` (a project grant of a global secret covers only the repository it was approved in) or `the grant is for an earlier value of this secret; call secret_request` (the value was replaced). The field is absent when there is nothing to say; clients that do not know it ignore it (added in 1.1.0, additive, issue #42).

Returns the secrets that resolve from `cwd`: every secret of the current project layer, plus every global secret not overridden by it. `project` is `null` outside a repository. Other projects' secrets are never listed. Never values. `unlinked_match` is `{ "label": "shop-api" }` when sync brought a project layer from another device whose origin URL matches this repository but the user has not linked it here (`REMOTE_SYNC.md` § 7.5): the agent may suggest that the user run `qbit-vault link shop-api`; it cannot link it itself. Otherwise `null`.

`policy` tells the agent everything it may and may not do. Its strings are normative (hosts ship them verbatim) and the same text is the MCP server's `instructions`:

```json
{ "can": [
    "List secret names and metadata visible from this directory with secret_list.",
    "Ask the user for one or several secrets (up to 8 fields, each secret or plain text) with a concrete reason using secret_request; the user types them outside the chat.",
    "Run commands with granted secrets using secret_exec or the shell tool; output comes back redacted.",
    "Propose removing, editing, moving (global <-> this project) or replacing a secret using secret_manage; the user confirms or declines." ],
  "cannot": [
    "Read, print, copy or receive any secret value.",
    "Create or widen a grant; only the user grants access.",
    "Apply any change without the user's confirmation.",
    "Reach the secrets of another project.",
    "Print the environment (env, printenv, set, /proc/*/environ, ...) while secrets are injected.",
    "Use a secret with a binary outside its allowlist.",
    "Re-ask for a name the user declined during its cooldown.",
    "Configure sync, pair or revoke devices, or link a project layer; only the user can." ],
  "layers": ["global", "project"],
  "scopes": ["once", "session", "project"],
  "cooldowns": [ { "name": "AWS_SECRET_ACCESS_KEY", "until": "…" } ] }
```

### `exec` — run a command with injected secrets (model-callable)

Request:
```json
{ "op": "exec",
  "command": "gh release create v1.2.0 --notes-file CHANGELOG.md",
  "secrets": [ { "name": "GITHUB_TOKEN" }, { "name": "GH_TOKEN", "from": "GITHUB_TOKEN" } ],
  "timeout_ms": 600000,
  "shell": "auto" }
```

| Field | Req | Rules |
| --- | --- | --- |
| `command` | yes | 1–16 KiB; executed through the platform shell (`/bin/sh -c`, `cmd /c` or `pwsh -c` per `shell`) |
| `secrets[]` | yes | Each `{name, from?}`: inject vault secret `from` (default = `name`) as env var `name`. Max 16. |
| `timeout_ms` | no | 1 s – 1 h, default 600 000 |
| `shell` | no | `auto` \| `sh` \| `bash` \| `cmd` \| `pwsh` |

Behavior (normative, see PRD R-EXEC-*): resolve every `from` for `cwd` to its layer → check grants for that name and layer → dump-guard → binary allowlist → build env (parent env minus any var named like a vault secret, plus injected) → run in own process group with timeout → stream stdout/stderr through the redactor → audit → return. A `once` grant is spent only if the child process is created: a refusal at any earlier step, or a command that cannot start, leaves it usable; a child that starts and exits non-zero spends it. On Windows a bare `bash` or `sh` in `command` never resolves to WSL; with no Git for Windows it is an `internal` refusal with a fixed message.

Response:
```json
{ "ok": true, "exit_code": 0, "stdout": "…redacted…", "stderr": "…redacted…",
  "duration_ms": 1830, "redactions": 2, "truncated": false }
```

`stdout`/`stderr` are capped at 1 MiB each (`truncated: true`, tail kept). Hosts with streaming (Pi) receive chunks over the CLI's `--stream` mode with the same redaction guarantees.

### `manage` — propose a change to the vault (model-callable, user-confirmed)

The agent proposes; the user decides. Every action opens the user-facing prompt (same channel as `request`) showing the action, name, layer, the change and the reason. Nothing is applied without that confirmation.

Request:
```json
{ "op": "manage", "action": "move", "name": "DATABASE_URL", "layer": "global", "to": "project",
  "reason": "this URL is the shop-api staging db, not a global one" }
```

| Field | Req | Rules |
| --- | --- | --- |
| `action` | yes | `remove` \| `edit` \| `move` \| `replace` |
| `name` | yes | Secret name; must exist in `layer` for `cwd`, else `unknown_secret` |
| `layer` | yes | `global` \| `project` (the project of `cwd`) |
| `reason` | yes | Same rules as `request.reason` |
| `to` | `move` only | The other layer. If the name already exists there, the prompt asks the user whether to overwrite |
| `changes` | `edit` only | Any of `description`, `binaries`, `hosts`, `sensitive`. The prompt shows a before/after diff |

- `remove`: deletes the record and its grants.
- `edit`: metadata only, never the value. Clearing `sensitive` or emptying `binaries` widens access, so the prompt marks it as **widening**.
- `move`: keeps value and metadata, drops the record's grants (R-LAYER-05).
- `replace`: one decision, then the masked capture for the new value. The decision offers `Replace, allow once` (preselected) and, where the record allows it, `Replace, always in this project` (never a session answer), then `Replace, but ask me before each use` and `Don't replace` (a decline). The old grants are dropped; the picked scope, if any, becomes a new prompt-token grant on the new value for this envelope's session, so the agent's next `exec` needs no second permission dialog.

Except for the grant the user picks in a `replace` decision, `manage` never creates a grant. Declines start the same per-name cooldown as `request`.

Response:
```json
{ "ok": true, "applied": true, "action": "move", "name": "DATABASE_URL", "layer": "project" }
```

`layer` is the record's layer after the action (`null` after `remove`).

### `grant` — create or widen a grant (**user-UI only, never model-callable**)

Only the host UI (the planned Pi extension prompt, or the native dialog) may send it, and only as the result of a user interaction. The MCP server does not expose it as a tool. The CLI accepts it only from an interactive TTY or with `--from-prompt-token <t>` issued by the broker's own prompt.

Request: `{ "op": "grant", "name": "GITHUB_TOKEN", "layer": "global", "scope": "session", "ttl_ms": 43200000 }`
Response: `{ "ok": true, "grant": { "scope": "session", "expires_at": "…" } }`

### `revoke` — drop grants (user-callable)

Request: `{ "op": "revoke", "name": "GITHUB_TOKEN" }` or `{ "op": "revoke", "all": true }` or `{ "op": "revoke", "session_only": true }`
Response: `{ "ok": true, "revoked": 2 }`

### `capabilities` — negotiate

Request: `{ "op": "capabilities" }`
Response:
```json
{ "ok": true, "contract": "qbit-vault.secrets-broker/v1", "capabilities": "1.0",
  "ops": ["request","list","exec","manage","grant","revoke","capabilities"],
  "layers": ["global","project"],
  "prompt_backends": ["pi-ui","osascript","powershell","zenity","kdialog","tty"],
  "field_kinds": ["secret","text"], "max_fields": 8,
  "keychain": "secret-service", "streaming": true, "sync": false }
```

## Refusals

A refusal is `{ "ok": false, "refusal": { "type": "<type>", "name": "<secret name or null>", "message": "<human text, no values>", "retryable": true|false } }`.

| `type` | When | `retryable` | Expected host behavior |
| --- | --- | --- | --- |
| `grant_required` | `exec` references a name with no active grant. When a grant exists but does not apply (another directory, or an earlier value) the `message` says so, e.g. `NAME has a project grant for another directory; call secret_request` | yes | Open the grant prompt; retry once |
| `unknown_secret` | `exec` or `manage` references a name that does not resolve from `cwd` (in neither this project nor global) | yes | Model should call `request` |
| `user_declined` | User cancelled the prompt | no (60 s cooldown) | Tell the model the user declined; do not re-ask |
| `rate_limited` | Re-request inside the cooldown | no | Back off |
| `reason_too_vague` | `request.reason` fails the heuristic | yes | Model rephrases with a concrete reason |
| `invalid_name` | Name fails the regex, or appears twice in `fields` | no | Fix the name |
| `scope_not_allowed` | `project`/`session` asked for a `sensitive` secret | no | Offer `once` |
| `scope_binary` | Command's binary not in the secret's `binaries` | no | Tell the user; user may edit the allowlist |
| `no_project` | `layer: "project"` or `suggested_layer: "project"` while `cwd` is not inside a repository | no | Use `global`, or run from the repository |
| `dump_command` | Command matches the dump-guard list | no | Tell the model the command is refused while secrets are injected |
| `not_model_callable` | `grant` arrived over MCP or without a prompt token | no | Log; this is an attack signal |
| `vault_locked` | Keychain unavailable and no cached passphrase | yes | Prompt for passphrase |
| `vault_corrupt` | AEAD tag or envelope check failed | no | Point to `qbit-vault restore` |
| `timeout` | `exec` exceeded `timeout_ms` | yes | Child killed; partial redacted output returned in `partial` |
| `contract_mismatch` | Unsupported `contract` or `v` | no | Upgrade |
| `internal` | Anything else | maybe | Message never contains values |

Messages MUST be built from the secret **name** and fixed strings only.

Every refusal answered to a request with a valid envelope, over the host or the model transport, is appended to the audit log as a `refusal` record: the `type`, the `name` when there is one, and the envelope's `session`. The record never holds the command, the reason or a value.

## Model-facing tool definitions (normative text)

These descriptions are shipped verbatim to every host so models see the same contract.

**`secret_request`** — "Ask the user for permission to use one or several named secrets (e.g. GITHUB_TOKEN, or DB_HOST, DB_USER and DB_PASSWORD together) in later commands. Ask for everything one task needs in a single call: up to 8 fields, each 'secret' (masked) or 'text' (visible, for non-secret values such as a hostname). The user will type or approve them outside the chat. You NEVER receive the values; you receive references and a grant. Give a concrete reason (what command, what for). Do not request secrets you do not need for the current task. If the user declines, do not ask again."

**`secret_list`** — "List the secrets available from this directory (global ones and this project's), and the rules for what you can and cannot do with them. Values are never returned. Call this first when you need a credential."

**`secret_manage`** — "Propose a change to a secret: remove it, edit its metadata, move it between global and this project, or replace its value. The user confirms or declines outside the chat; nothing changes without that. You never see values and you cannot grant access. Give a concrete reason."

**`secret_exec`** — "Run a shell command with named secrets injected as environment variables for that process only. Output is returned with secret values redacted. Commands that print the environment or a secret are refused; to use only a length, write ${#NAME}. Prefer this over asking the user to paste credentials."

## Conformance

A host adapter is conformant when it passes the conformance harness (`internal/conformance` and `TestContractConformance` in `internal/cli`, see `docs/TESTING.md`): every op, every refusal, the no-value invariant on every byte returned, and the `grant`-over-MCP rejection.
