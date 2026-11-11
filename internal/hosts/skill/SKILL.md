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

1. `secret_list` first. It returns the names visible from this directory (global ones and this project's), their metadata and the rules you must follow. It never returns values. A secret's `grant` is what `secret_exec` will accept from this directory; `null` means it will refuse. When `grant_note` is present a grant exists but does not apply here (another directory, or an earlier value): call `secret_request`.
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

## Background jobs, scripts and subagents

A background job, a script or a subagent command that uses a credential runs through `secret_exec`, so its output and the notification when it ends are redacted. A job that prints a stored value directly (a plain shell command, not `secret_exec`) makes the host drop its completion notice, and the user sees a block naming the secret.

## When qbit-vault replaces an output or blocks an edit

The host runs qbit-vault over what your built-in tools return and over the files you write, not only over `secret_exec`:

- `[REDACTED:NAME]` in the output of a shell command, a file read or a search is a stored value that was removed. Expected; do not try to recover it.
- `output withheld: qbit-vault could not check it for secrets (<reason>)` replaces a tool output that could not be checked. The command ran but its output is not shown. Do not retry the same command to see it. With `vault locked`, tell the user to run `qbit-vault unlock` in their own terminal (or call `secret_request`, which unlocks); with `output too large`, ask for less output; with `internal error`, tell the user to run `qbit-vault doctor`. If the command needs a credential, run it through `secret_exec`, which redacts instead of withholding.
- `This edit would write the value of the stored secret NAME to a file, so qbit-vault blocked it` means the content you tried to write holds a stored value. Do not write it in any form. Put the name where the value would go (an environment variable the program reads, or a placeholder) and run the command that needs the value with `secret_exec`.
- `qbit-vault could not check this edit for secrets (<reason>)` blocks a write the same way when the vault cannot be checked. With `vault locked`, tell the user to run `qbit-vault unlock`, then write again.

## Rules

- Never print, echo, copy, encode or write a secret value, and never ask the user to paste one into the chat.
- Never print the environment (`env`, `printenv`, `set`, `/proc/*/environ`) while secrets are injected: it is refused. To check that a value is present use its length only: `${#NAME}`.
- You cannot grant access and you cannot use another project's secrets; only the user grants, in the dialog.
- Ask only for what the current task needs.

## Refusals and what to do

| Refusal | What to do |
| --- | --- |
| `grant_required` | Call `secret_request` for that name (the user approves it), then retry `secret_exec` once. The message may say the grant is for another directory or an earlier value: the same answer, and run the command from the directory the grant was approved in if you can. |
| `unknown_secret` | The name does not exist here: call `secret_request` so the user can store it. |
| `user_declined` | Stop asking for it; tell the user what could not be done. Do not re-ask during the cooldown. |
| `reason_too_vague` | Rephrase the reason: what command, what for. |
| `dump_command` | The command would print a secret or the environment. Rewrite it so it does not. |
| `scope_binary` | The secret is limited to other programs. Tell the user; they can change its allowlist. |
| `scope_not_allowed` | The secret is sensitive: only a one-time (`once`) grant is possible. |
| `rate_limited` | You asked again too soon after a decline. Back off; do not retry now, tell the user what is blocked. |
| `invalid_name` | The name is not valid (capital letters, digits and `_`, starting with a letter) or appears twice. Fix it and call again. |
| `no_project` | You asked for the project layer outside a repository. Use the global layer, or work from the repository. |
| `not_model_callable` | That operation is not yours to call. Stop and tell the user; do not try another route to the same effect. |
| `vault_locked` | `secret_request` and `secret_manage` ask the user for the passphrase in a dialog that names you and the secret, so a locked vault is not a reason to stop. `secret_exec` and `secret_list` never ask: when one answers this, call `secret_request` for the name (it unlocks, then asks for the permission as usual) and retry. A wrong passphrase also answers this; calling again asks again. Only when `secret_request` itself answers this (no dialog is possible here, or the user turned it off) ask the user to run `qbit-vault unlock` in their terminal. |
| `vault_corrupt` | The vault failed its integrity check. Stop; tell the user to run `qbit-vault restore`. |
| `timeout` | The command ran past `timeout_ms` and was killed; the redacted output so far is in `partial`. Raise `timeout_ms` or run something shorter. |
| `contract_mismatch` | This server and the tools disagree on the contract version. Tell the user to run `qbit-vault sync` and restart the agent. |
| `internal` | A malformed argument, a missing prompt, or a call cancelled before the user answered (the message says which). Fix the arguments and retry once; otherwise tell the user. Nothing was stored or granted. |

If the qbit-vault tools are not available in this session, tell the user to run `qbit-vault doctor` and restart the agent; do not fall back to asking for the value.
