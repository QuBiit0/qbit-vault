# qbit-vault-pi

A [Pi](https://pi.dev) / Gentle Shell extension for [QBit Vault](https://github.com/qbitdevz/qbit-vault). It adds what the MCP tools cannot: commands you run yourself, without the model, and the vault state in the footer.

- `/vault list [global|project|all]` — secret names, layers, descriptions and active grants.
- `/vault set NAME [global|project]` — stores a secret; the value is asked in QBit Vault's own dialog.
- `/vault rm NAME [global|project]`, `/vault revoke NAME|--all`, `/vault audit [--tail N]`, `/vault doctor`.
- Footer status: `🔐 <n> grants`, `🔐 vault`, or `🔒 locked`; nothing when there is no vault.
- Paste interception: a message you type or paste into the chat that contains something shaped like a secret (GitHub, OpenAI, Anthropic, AWS, Slack, Stripe, Google, npm and Vercel tokens, JWTs, private keys, database URLs with a password, `KEY=<high-entropy value>`) is not sent as typed. You are asked `This looks like a <kind>. Store it in QBit Vault?` and choose `Store as NAME (all projects)`, `Store as NAME (this project)` (inside a repository), `Store under another name…` or `Don't store, drop the message`. A stored value is replaced by `secret://NAME` in the message the model gets; a drop, a refusal (name taken, vault locked) or a session with no interactive UI sends nothing. Storing runs `qbit-vault set NAME --global|--project --stdin --json` with the value on stdin and creates no grant. Only text you type is scanned (`source === "interactive"`); the patterns are `secret-patterns.yaml`, a copy of `defaults/secret-patterns.yaml` that a Go test keeps identical.
- When the Pi session ends, its `session` grants are revoked (best effort; the grant TTL is the backstop).

The agent keeps using QBit Vault through its MCP tools (`secret_request`, `secret_list`, `secret_exec`, `secret_manage`). This package does not replace them.

## Requirements

The `qbit-vault` binary on `PATH` (see the [QBit Vault install guide](https://github.com/qbitdevz/qbit-vault)), and a vault created with `qbit-vault init`.

## Install

Once it is published to npm, install it with Pi's package command for npm sources (`npm:qbit-vault-pi`), or with `gentle-shell install npm:qbit-vault-pi` in Gentle Shell. Check the Pi documentation for the exact command of your version.

To try a local build without installing anything:

```sh
npm install
npm run build
pi -e ./dist/index.js
```

## What it never does with a value

- It never opens the vault. Every operation runs the `qbit-vault` binary with `--json`, without a shell, with an argument array.
- No secret value is ever an argument, a log line, a notification, a status text, a session entry or a message to the model. Output goes to the terminal UI only (`ctx.ui`), never through `pi.sendMessage` or `pi.appendEntry`.
- A `NAME` that is not a valid secret name is rejected before anything runs and is not echoed, in case it was a pasted value.
- Messages shown to you are fixed texts or the binary's own error message, which names secrets by name only.

## Development

```sh
npm run build       # tsc to dist/
npm test            # vitest, with a fake qbit-vault script
npm run typecheck   # src and tests
```

`QBIT_VAULT_BIN` overrides the binary path and must be absolute (the tests point it at a fake). A path ending in `.js`, `.mjs` or `.cjs` runs through the current Node. Without it the binary is looked up only in absolute `PATH` entries and the installers' default locations, never in the current directory, so a repository cannot plant its own `qbit-vault`.

## Publishing

The maintainer publishes from this directory while logged in to npm, with the `publish` command of npm and `--access public`. The `prepublishOnly` script runs the typecheck, the build and the tests first, so the package always ships a fresh `dist/`.
