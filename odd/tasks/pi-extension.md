# Pi / Gentle Shell extension `qbit-vault-pi`, v1

A TypeScript extension for Pi / Gentle Shell that adds what MCP cannot: `/vault` commands the user runs without the model, a vault status in the footer, and paste interception so a token typed or pasted into the chat never reaches the model. The four MCP tools and the native dialogs stay as they are. Design: `docs/GENTLE_SHELL_EXTENSION.md` (to be rewritten to what v1 ships).

## Specs

- S1. User (verbatim, 2026-11-10): "si" to "¿Arranco con la extensión de Pi / Gentle Shell, que es la que más le suma a la comunidad de gentle-ai?".
- S2. Owner decisions (verbatim choices):
  - Scope v1: "Comandos /vault + estado en el sidebar (recomendado)", "Intercepción de pegado (recomendado)", "Captura dentro de la terminal"; then, for the terminal capture: "Dejarla para después (recomendado)" — capture stays in the native dialog; deferred.
  - Docs: "Sí, leé esa carpeta" (read-only, the installed Pi docs and types).
  - Publishing: "La armo y testeo; vos publicás en npm (recomendado)" — the package is built and tested here; the owner publishes it to npm.
- S3. Package (from the T0 research of the installed Pi 1.5.0):
  - S3.1 `packages/qbit-vault-pi/`: `package.json` with `"pi": {"extensions": ["./dist/index.js"]}`, keyword `pi-package`, MIT, `peerDependencies` `@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui`, `typebox` as `"*"` (never bundled); dev dependencies only `typescript` and a test runner (`vitest`), each named in the PR with why; `npm test` and `npm run build` (tsc to `dist/`); `dist/` is not committed.
  - S3.2 The extension never opens the vault and never holds a value longer than one call: every operation runs the `qbit-vault` binary with `--json`, without a shell (`node:child_process` `spawn`/`execFile`, argv array), values only over stdin, `--session pi:<session id>` from `ctx.sessionManager.getSessionId()`. A missing binary or a locked vault is reported once with the fix (`qbit-vault init`, `qbit-vault unlock`) and nothing else breaks.
- S4. `/vault` commands (`pi.registerCommand`), the user's manual path, no model involved; output only to the UI (`ctx.ui.notify` or a `ctx.ui.custom` view), never `pi.sendMessage` (that enters the model context):
  - `/vault list [global|project|all]` — names, layers, descriptions, grants (from `qbit-vault list --json`).
  - `/vault set NAME [global|project]` — runs `qbit-vault set NAME --global|--project` so the value is asked in the native dialog (the terminal capture is deferred, S2).
  - `/vault rm NAME [global|project]`, `/vault revoke NAME|--all`, `/vault audit [--tail N]`, `/vault doctor` — each the matching CLI command; confirmations stay in the CLI's native dialog.
  - Unknown subcommand or missing NAME: a one-line usage notice; argument completion for the subcommands.
- S5. Status: `ctx.ui.setStatus("qbit-vault", …)` shows `🔐 <n> grants` (or `🔐 vault` with none), `🔒 locked`, or nothing without a vault; refreshed on `session_start`, after every `/vault` command and after a QBit Vault MCP tool result (`tool_result` for tools whose name ends in `secret_request`, `secret_exec`, `secret_manage`). If Gentle Shell exposes an integrations/sidebar entry point to extensions, use it in addition; otherwise the footer status is the v1 indicator.
- S6. Paste interception (`pi.on("input")`, `source === "interactive"` only):
  - S6.1 The text is scanned with the patterns of `defaults/secret-patterns.yaml`; the package carries a byte-identical copy and a Go test fails when they differ (like the dumpguard copy).
  - S6.2 On a match the input is never sent as typed: the user is asked (`ctx.ui.select`) `This looks like a <pattern label>. Store it in QBit Vault?` with `Store as <SUGGEST> (all projects)`, `Store as <SUGGEST> (this project)` (inside a repository only), `Store under another name…` (then `ctx.ui.input` for the name, validated `^[A-Z][A-Z0-9_]{0,63}$`) and `Don't store, drop the message`; the value itself is never shown, logged, notified or kept after the call.
  - S6.3 Store = `qbit-vault set NAME --global|--project --stdin --json` with the value on stdin; then the input is transformed: every occurrence of the value replaced by `secret://NAME` (`{action: "transform"}`), and a notice says `stored as NAME`. A refusal (`exists`, invalid name, locked) shows its message and the input is dropped (`{action: "handled"}`), never sent with the value.
  - S6.4 Drop = `{action: "handled"}` with the notice `message not sent: it contained a secret`.
  - S6.5 Several matches in one message are handled one after another; text with no match passes through unchanged with no prompt and no child process.
- S7. `session_shutdown`: `qbit-vault revoke --session-only --session pi:<id>` (best effort, never blocks the exit).
- S8. Tests (vitest, mocked ExtensionAPI and a fake `qbit-vault` binary script): every S4-S7 behavior, exact texts; leak assertions with a `TESTSECRET_`-shaped fixture that matches a pattern: the value never appears in any notify, status, transformed text, appendEntry, sendMessage call or the fake binary's argv (only its stdin). The Go parity test of S6.1.
- S9. CI: a job in `.github/workflows/ci.yml` (Node LTS, actions pinned by SHA like the others) running `npm ci`, `npm run build`, `npm test` in `packages/qbit-vault-pi`; the pin test keeps passing.
- S10. Docs: `docs/GENTLE_SHELL_EXTENSION.md` describes what v1 ships and lists what is deferred (terminal capture, bash override, read/write guard); `AGENT_INTEGRATIONS.md` (Pi section), `README.md` (one line + install command `gentle-shell install npm:qbit-vault-pi` / Pi's local or npm source, verified against the docs), `AGENTS.md` layout (`packages/qbit-vault-pi` exists; peer dependency names updated from `@mariozechner/*` to `@earendil-works/*`), `docs/ROADMAP.md`, CHANGELOG [Unreleased]. `qbit-vault init` prints no install line until the package is published (AGENTS.md invariant 8).
- S11. Verified by the owner in Gentle Shell from the local package before publishing: `/vault list`, the status, and a pasted test token caught and stored.

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T0 | research | explorer | | done |
| T1 | S3, S4, S5, S7, S8 (their tests) | worker | f3f252b | done |
| T2 | S6, S8 (paste tests), S6.1 parity | worker | 768f1a6 | done |
| T3 | S9, S10 | worker | 25ed0fd | done |
| T4 | review, PR, owner check S11, release note | parent + owner | | pending |

## Log

- L1. User (verbatim): "si" — start the Pi / Gentle Shell extension.
- L2. Owner choices: v1 = /vault commands + status, paste interception, terminal capture (then "Dejarla para después (recomendado)"); read the installed Pi docs; owner publishes to npm.
- L3. T0 research (installed `@earendil-works/pi-coding-agent` 1.5.0): manifest `"pi": {"extensions": [...]}`; peers `@earendil-works/pi-ai`, `pi-agent-core`, `pi-coding-agent`, `pi-tui`, `typebox` as `"*"`; `pi.registerCommand(name, {description, getArgumentCompletions, handler(args, ctx)})`; `ctx.ui.notify`, `ctx.ui.custom`, `ctx.ui.setStatus(key, text)`, `setWidget`, `setFooter`; `pi.sendMessage` enters the LLM context (never use it for vault output); `pi.on("input")` with `{action: "continue"|"transform"|"handled"}` and `source`; `ctx.sessionManager.getSessionId()`; `session_start` / `session_shutdown`; MCP tools surface as `mcp__<server>__<tool>`; `tool_call` can only block or mutate input, so an extension cannot answer an MCP tool (why the terminal capture is deferred); local test with `pi -e <path>` or `<agent-dir>/extensions/` and `/reload`; no documented Gentle Shell sidebar entry point (unverified); `pi.exec` has no documented stdin, so values go through `node:child_process` with a pipe. Examples: `examples/extensions/` (`input-transform.ts`, `custom-footer.ts`, `qna.ts`).
- L4. T1 done (uncommitted): `packages/qbit-vault-pi/` built (spawn wrapper, `/vault` list/set/rm/revoke/audit/doctor with completions, footer status, session_shutdown revoke, `input` left free for T2); peers added as dev dependencies at 1.5.0 (type-checked against the real Pi types, no local declarations); 78 vitest tests pass, `npm run build` and `npm run typecheck` clean; smoke: real Pi 1.5.1 loaded `dist/index.js` with `pi -e` (RPC `get_commands` lists `vault`, footer status set on session_start).
- L5. T2 done (uncommitted): paste interception in `packages/qbit-vault-pi` (`src/patterns.ts` reads the package copy of `secret-patterns.yaml` with its own small YAML reader and RE2→JS converter; `src/paste.ts` is the `input` handler); Go parity test `TestExtensionSecretPatternsEqualDefaults` in `internal/hosts/pi`; 129 vitest tests pass (51 new), build and typecheck clean.
- L6. T3 done (uncommitted): CI job `pi-extension` (checkout v7.0.1 3d3c42e5…, setup-node v7.1.0 949feb24…, `lts/*`, npm cache, `npm ci`/typecheck/build/test); docs rewritten to what v1 ships (GENTLE_SHELL_EXTENSION, AGENT_INTEGRATIONS, README, AGENTS layout and peer names, ROADMAP Phase 4, CLI.md, CHANGELOG); `init` unchanged (no install line until published).
- L7. T4 follow-ups from the three native reviews (all approved): the binary is resolved only from absolute PATH entries and the installers' default locations, never the cwd, and QBIT_VAULT_BIN must be absolute (R1-cwd-binary-planting); a failed pattern load keeps chat flowing but shows a paste-guard-off status and one warning (R1/R3 fail-open); the one-time locked/missing notice no longer depends on refresh order; only QBit Vault's own MCP tools refresh the status; prepublishOnly runs typecheck, build and tests; CI pins Node 24; docs say deferred. The worker stalled on a host guard prompt (its bash mentioned the npm publish command); the parent verified nothing was published (npm 404) and finished the package.json, README, CI and docs edits. 155 tests.
- L8. Native review of the four commits (risk + reliability/readability): all approved. The branch was rebuilt as feat/pi-extension-v1 (same final tree) so no commit holds a token-shaped literal that the prompt hook blocks; the old branch feat/pi-extension stays until merge. Open advisories after v1: R3-flush-fixed-sleep (status.test.ts:16), R3-grant-tool-name-assumption (index.ts:14; the MCP server name qbit_vault is confirmed by the harness tool names), R3-relative-win-path-literal (binary.test.ts:88).
