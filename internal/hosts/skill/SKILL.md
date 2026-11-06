---
name: qbit-vault
description: Use credentials (API keys, tokens, passwords, connection strings) without ever seeing them, through the qbit-vault MCP tools. Use whenever a command, script, test, deploy or API call needs a credential, when the user mentions a token, key, secret, password or .env value, or when you would otherwise ask the user to paste one.
---
<!-- Managed by qbit-vault: 'qbit-vault sync' rewrites this file when a new version changes it. Do not edit it; to use your own text instead, replace this file and remove this line. -->

# qbit-vault

qbit-vault is the user's local secrets broker. You can run commands that need a credential, but the value never reaches you: it is injected into one child process and every output is redacted. Use it instead of `.env` files, exported variables or pasted values.

## When to use it

- A command needs a credential: `gh`, `git push` over HTTPS, `curl` with a token, a database client, a cloud CLI, a deploy, an integration test.
- The user says "use my token", "the API key is in qbit-vault", or names a variable such as `GITHUB_TOKEN` or `DATABASE_URL`.
- You are about to ask the user to paste a secret, write it into a file, or export it. Do not; use the tools below.

## How to use it

1. `secret_list` first. It returns the names visible from this directory (global ones and this project's), their metadata and the rules you must follow. It never returns values.
2. Missing a name, or need permission for one: `secret_request` with every name the task needs in one call (up to 8 fields) and a concrete reason ("run `gh release create` for v1.2", not "needed"). The user types new values or approves existing ones in a dialog outside the chat. You get references and a grant, never the value.
3. Run the command with `secret_exec`: the command plus `secrets: [{name}]`; each secret becomes an environment variable of that one process. Reference it the way the shell expects (`$GITHUB_TOKEN`, `%GITHUB_TOKEN%`, `$env:GITHUB_TOKEN`).
4. Read the redacted output. `[REDACTED:NAME]` in it is expected; never try to recover what is behind it.
5. To change a secret (remove it, edit its metadata, move it between global and this project, or replace its value) use `secret_manage` with a concrete reason; the user confirms outside the chat. A replace also lets the user set the new value's permission in the same dialog, so retry `secret_exec` right after it.

## When a service rejects the credential

An `exec` that runs but gets `401`, `403`, "invalid token" or "authentication failed" back means the stored value is wrong for that service, not that qbit-vault failed. Do not loop:

1. Check presence only: `${#NAME}` prints the length. Never print, echo, dump, encode or hash the value to inspect it (that is refused as `dump_command`, and it would leak it).
2. Tell the user what the service expects, as precisely as you can: the credential type (for Cloudflare an API Token, not the Global API Key), the scopes or permissions, the account or zone.
3. Propose **one** `secret_manage` replace with that in the reason. qbit-vault points out pasted quotes or invisible characters before saving, which is a common cause.
4. If the new value is rejected too, stop and report what the service answered; do not ask again.

## Rules

- Never print, echo, copy, encode or write a secret value, and never ask the user to paste one into the chat.
- Never print the environment (`env`, `printenv`, `set`, `/proc/*/environ`) while secrets are injected: it is refused. To check that a value is present use its length only: `${#NAME}`.
- You cannot grant access and you cannot use another project's secrets; only the user grants, in the dialog.
- Ask only for what the current task needs.

## Refusals and what to do

| Refusal | What to do |
| --- | --- |
| `grant_required` | Call `secret_request` for that name (the user approves it), then retry `secret_exec` once. |
| `unknown_secret` | The name does not exist here: call `secret_request` so the user can store it. |
| `user_declined` | Stop asking for it; tell the user what could not be done. Do not re-ask during the cooldown. |
| `reason_too_vague` | Rephrase the reason: what command, what for. |
| `dump_command` | The command would print a secret or the environment. Rewrite it so it does not. |
| `scope_binary` | The secret is limited to other programs. Tell the user; they can change its allowlist. |
| `scope_not_allowed` | The secret is sensitive: only a one-time (`once`) grant is possible. |
| `vault_locked` | Ask the user to run `qbit-vault unlock` in their terminal. |

If the qbit-vault tools are not available in this session, tell the user to run `qbit-vault doctor` and restart the agent; do not fall back to asking for the value.
