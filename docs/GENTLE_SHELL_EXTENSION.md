# Gentle Shell / Pi extension: `qbit-vault-pi`

**Status: built (Phase 4 v1), distributed as a git tag, not on npm.** The package lives in `packages/qbit-vault-pi`, is tested in CI (`pi-extension` job) and is published by the maintainer running the `pi-extension-release` workflow, which pushes the immutable tag `pi-v<version>`. The install commands below work once that tag exists. `qbit-vault init` and `sync` print them as a suggestion when the Pi host is registered, and never run them.

The extension adds what MCP cannot: commands the user runs without the model, a vault status in the footer, and paste interception so a token typed or pasted into the chat never reaches the model. The four MCP tools (`secret_request`, `secret_list`, `secret_exec`, `secret_manage`), the native dialogs and `exec` redaction stay exactly as they are; the extension does not register tools of its own.

It is written in TypeScript against the Pi extension API and peer-depends on `@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui` and `typebox` (never bundled). Dev dependencies are `typescript`, `vitest` and the Pi packages (for types only).

## Install

The user installs it from the git tag (`init` never does: AGENTS.md invariant 8). The owner has no npm account, so the package is not on npm. A git source is installed as the repository root of that ref, and the tag `pi-v<version>` points to a commit that holds only the built package (`package.json`, `dist/`, `secret-patterns.yaml`, `README.md`, `LICENSE`):

- Gentle Shell (it passes everything after `--` to Pi): `gentle-shell -- install git:github.com/qbitdevz/qbit-vault@pi-v0.1.0`.
- Pi: `pi install git:github.com/qbitdevz/qbit-vault@pi-v0.1.0`.
- One run only, nothing installed: `gentle-shell -- -e git:github.com/qbitdevz/qbit-vault@pi-v0.1.0` or `pi -e git:github.com/qbitdevz/qbit-vault@pi-v0.1.0`.
- Update: install the newer tag, for example `@pi-v0.2.0`. Pi pins a tag and does not move a configured ref by itself.

What Pi does with a git package (Pi 1.5, `docs/packages.md` and its package manager): it clones the source, checks out the ref and runs `npm install --omit=dev --legacy-peer-deps` (pnpm and Bun have their own production flags) when the package has a `package.json`; it never installs peer dependencies for git packages. So the published `package.json` has no `devDependencies`, no `scripts` and only the three `peerDependencies` (`*`, provided by Pi), and nothing is built on the user's machine. `node packages/qbit-vault-pi/scripts/assemble-dist.mjs --out <empty dir>` builds that tree locally (after `npm run build`); the workflow commits it with no parent the first time and with the previous `pi-extension` head as parent afterwards, so the branch only moves forward, and pushes the annotated tag. The `v*` tags of the binary release are a different filter: a `pi-v*` tag does not start `release.yml`.

Requirements: the `qbit-vault` binary on `PATH` and a vault created with `qbit-vault init`.

## Try it from a checkout

```sh
cd packages/qbit-vault-pi
npm ci
npm run build
pi -e ./dist/index.js
```

`pi -e <path>` loads the extension for that run only and installs nothing. Pi can also load a local package path through its package sources, and an extension copied to `<agent dir>/extensions/` is picked up after `/reload`; see the Pi documentation for your version. `QBIT_VAULT_BIN` overrides the binary path (the tests point it at a fake).

## What v1 does

- **Commands** (the user's manual path; output goes to the terminal UI only, never to the model):
  - `/vault list [global|project|all]`: names, layers, descriptions and active grants.
  - `/vault set NAME [global|project]`: runs `qbit-vault set`, so the value is asked in QBit Vault's own dialog.
  - `/vault rm NAME [global|project]`, `/vault revoke NAME|--all`, `/vault audit [--tail N]`, `/vault doctor`.
  - A missing `NAME` or an unknown subcommand shows a one-line usage notice; subcommands complete with Tab.
- **Status** in the footer (`ctx.ui.setStatus`): `🔐 <n> grants`, `🔐 vault` with none, `🔒 locked`, or nothing without a vault. Refreshed on session start, after every `/vault` command and after a QBit Vault MCP tool result.
- **Paste interception** (`input` event, text the user typed or pasted only): the text is scanned with `secret-patterns.yaml`, a copy of `defaults/secret-patterns.yaml` that a Go test keeps identical. On a match the message is not sent as typed; the user is asked `This looks like a <kind>. Store it in QBit Vault?` and chooses `Store as NAME (all projects)`, `Store as NAME (this project)` (inside a repository), `Store under another name…` or `Don't store, drop the message`. A stored value is replaced by `secret://NAME` in the message the model gets; a drop, a refusal (name taken, vault locked) or a session with no interactive UI sends nothing. Storing runs `qbit-vault set NAME --global|--project --stdin --json` with the value on stdin and creates no grant. Several matches are handled one after another; text with no match passes through untouched, with no prompt and no child process.
- **Session end**: `qbit-vault revoke --session-only --session pi:<id>`, best effort and never blocking the exit; the grant TTL is the backstop.

## What it never does with a value

- It never opens the vault. Every operation runs the `qbit-vault` binary with `--json`, without a shell (an argument array), passing `--session pi:<id>`.
- A value only travels over stdin to `qbit-vault set --stdin`, lives for that one call, and is never an argument, a log line, a notification, a status text, a session entry or a message to the model. The extension uses `ctx.ui` for output and never `pi.sendMessage` or `pi.appendEntry` for vault data.
- A `NAME` that is not a valid secret name is rejected before anything runs and is not echoed, in case it was a pasted value.
- Messages shown to the user are fixed texts or the binary's own error, which names secrets by name only.
- A missing binary or a locked vault is reported once with the fix (`qbit-vault init`, `qbit-vault unlock`); nothing else breaks.

The tests (vitest, a mocked `ExtensionAPI` and a fake `qbit-vault` script) assert this with a `TESTSECRET_` fixture that matches a pattern: the value never appears in any notification, status, transformed text, session entry, message or argv.

## Not in v1

- **Capture inside the terminal.** `/vault set` and the paste flow use QBit Vault's native dialog. An extension cannot answer an MCP tool call: Pi's `tool_call` event can only block a call or change its input, so a `secret_request` from the agent is answered by the MCP server's own dialog, not by the extension. A masked in-terminal input for the user's own commands is possible but was deferred by the owner.
- **Bash override.** Injecting secrets into Pi's own `bash` tool by wrapping it. Agents use `secret_exec` instead.
- **Read/write guard.** Redacting `read` results and blocking `write`/`edit` inputs that contain an active value while a grant exists.
- **Sidebar entry.** No Gentle Shell integrations or sidebar entry point for extensions was found in its documentation, so the footer status is the v1 indicator. Revisit if Gentle Shell exposes one.
- Also not built: extension-registered tools, the `policy` block in the system prompt, `/vault mv` and `/vault edit`, and the CLI pieces they assumed (`set --reason`, `set --stdin --fields`, `prompt --field`, `prompt --confirm`, a `redact` command).

See `docs/ROADMAP.md` § Phase 4 and `odd/tasks/pi-extension.md`.
