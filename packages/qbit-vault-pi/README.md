# qbit-vault-pi

A [Pi](https://pi.dev) / Gentle Shell extension for [QBit Vault](https://github.com/qbitdevz/qbit-vault). It adds what the MCP tools cannot: commands you run yourself, without the model, and the vault state in the footer. Since 0.2.0 it also guards what the agent's built-in tools show and write.

- `/vault list [global|project|all]` — secret names, layers, descriptions and active grants.
- `/vault set NAME [global|project]` — stores a secret; the value is asked in QBit Vault's own dialog.
- `/vault rm NAME [global|project]`, `/vault revoke NAME|--all`, `/vault audit [--tail N]`, `/vault doctor`.
- Footer status: `🔐 <n> grants`, `🔐 vault`, `🔒 locked`, or `🔐 update qbit-vault` when your qbit-vault is older than 1.4.0 (run `qbit-vault update`); nothing when there is no vault.
- Paste interception: a message you type or paste into the chat that contains something shaped like a secret (GitHub, OpenAI, Anthropic, AWS, Slack, Stripe, Google, npm and Vercel tokens, JWTs, private keys, database URLs with a password, `KEY=<high-entropy value>`) is not sent as typed. You are asked `This looks like a <kind>. Store it in QBit Vault?` and choose `Store as NAME (all projects)`, `Store as NAME (this project)` (inside a repository), `Store under another name…` or `Don't store, drop the message`. A stored value is replaced by `secret://NAME` in the message the model gets; a drop, a refusal (name taken, vault locked) or a session with no interactive UI sends nothing. Storing runs `qbit-vault set NAME --global|--project --stdin --json` with the value on stdin and creates no grant. Only text you type is scanned (`source === "interactive"`); the patterns are `secret-patterns.yaml`, a copy of `defaults/secret-patterns.yaml` that a Go test keeps identical.
- Output and write guard (0.2.0): the result of the built-in `bash`, `powershell`, `read`, `grep`, `find` and `ls` tools goes to `qbit-vault hook post-bash|post-read --host pi` (over stdin), and every stored value in it is replaced by `[REDACTED:NAME]` before the model sees it; the structured copy of the result is dropped. A `write` whose `content`, or an `edit` whose `edits[].newText`, carries a stored value is blocked with `This edit would write the value of the stored secret NAME to a file, so qbit-vault blocked it. Give the value to the command that needs it with secret_exec instead.` With no `qbit-vault` binary, no vault or nothing to redact, everything passes unchanged and nothing is shown. If the binary is there but cannot check (timeout after 30 s, a locked vault, a crash, an answer it cannot read), the output is replaced by `output withheld: qbit-vault could not check it for secrets (<reason>)` and the edit is blocked with `qbit-vault could not check this edit for secrets (<reason>)`, with the fixed reasons `vault locked`, `output too large`, `edit too large`, `timeout` or `internal error`. Unlock with `qbit-vault unlock`. Not covered: streaming partial output while a command runs, a value split across two results, and MCP tool output.
- When the Pi session ends, its `session` grants are revoked (best effort; the grant TTL is the backstop).

The agent keeps using QBit Vault through its MCP tools (`secret_request`, `secret_list`, `secret_exec`, `secret_manage`). This package does not replace them.

## Requirements

The `qbit-vault` binary on `PATH` (see the [QBit Vault install guide](https://github.com/qbitdevz/qbit-vault)), and a vault created with `qbit-vault init`.

## Install

The package is not published to npm. It is distributed as an immutable git tag of the QBit Vault repository: `pi-v<version>` points to a commit that holds only this package, already built, so installing needs no build and pulls no dev dependency (Pi runs `npm install --omit=dev` for git packages, and never installs the peers).

In Gentle Shell (it passes everything after `--` to Pi):

```sh
gentle-shell -- install git:github.com/qbitdevz/qbit-vault@pi-v0.2.3
```

In plain Pi:

```sh
pi install git:github.com/qbitdevz/qbit-vault@pi-v0.2.3
```

To try it for one run without installing it, load the same source with `-e`:

```sh
gentle-shell -- -e git:github.com/qbitdevz/qbit-vault@pi-v0.2.3
pi -e git:github.com/qbitdevz/qbit-vault@pi-v0.2.3
```

To update, install the newer tag (for example `@pi-v0.3.0`): a tag is pinned, so Pi never moves a configured ref by itself. Tags are never moved or reused. `qbit-vault init` and `sync` print the install line for the version that matches your `qbit-vault` binary, for you to run.

To try a local build without installing anything:

```sh
npm install
npm run build
pi -e ./dist/index.js
```

## What it never does with a value

- It never opens the vault. Every operation runs the `qbit-vault` binary with `--json`, without a shell, with an argument array.
- A tool result or an edit goes to the binary over stdin only, for that one call; the extension keeps nothing.
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

The maintainer runs the `pi-extension-release` workflow (Actions tab, on `main`). It reads the version from `package.json`, stops if the tag `pi-v<version>` already exists, runs `npm ci`, the typecheck, the build and the tests, and assembles the tree with `node scripts/assemble-dist.mjs --out <empty dir>`: a `package.json` without `devDependencies` and `scripts`, `dist/`, `secret-patterns.yaml`, `README.md` and `LICENSE`. That tree is committed with no parent the first time, and with the previous head of the branch `pi-extension` as parent afterwards (fast-forward only, never forced), and the annotated tag `pi-v<version>` is pushed with it. To publish a new version, raise `version` in `package.json` and `ExtensionVersion` in `internal/hosts/pi` (a test keeps both equal). Run the script by hand after `npm run build` to see the tree before publishing.
