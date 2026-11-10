# qbit-vault-pi

A [Pi](https://pi.dev) / Gentle Shell extension for [QBit Vault](https://github.com/qbitdevz/qbit-vault). It adds what the MCP tools cannot: commands you run yourself, without the model, and the vault state in the footer.

- `/vault list [global|project|all]` — secret names, layers, descriptions and active grants.
- `/vault set NAME [global|project]` — stores a secret; the value is asked in QBit Vault's own dialog.
- `/vault rm NAME [global|project]`, `/vault revoke NAME|--all`, `/vault audit [--tail N]`, `/vault doctor`.
- Footer status: `🔐 <n> grants`, `🔐 vault`, or `🔒 locked`; nothing when there is no vault.
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

`QBIT_VAULT_BIN` overrides the binary path (the tests point it at a fake). A path ending in `.js`, `.mjs` or `.cjs` runs through the current Node.
