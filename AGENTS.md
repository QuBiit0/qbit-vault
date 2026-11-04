# AGENTS.md — instructions for the coding agent building gentle-vault

You are implementing gentle-vault from the specification in this repository. Read this file first, then `docs/PRD.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md` and `contracts/secrets-broker/v1/CONTRACT.md` before writing code (and `docs/REMOTE_SYNC.md` before touching sync or the server). The spec is the authority; when code and spec disagree, fix the code or open a spec change, never silently diverge.

## Non-negotiables (security invariants)

These are tested, not just documented. A PR that breaks one is rejected regardless of what else it does.

1. **No secret value ever crosses the model boundary.** No tool result, MCP response, hook stdout, log line, error message, panic, or debug output may contain a secret value. Errors mention the secret **name** only.
2. **No secret value ever touches disk unencrypted.** Not in temp files, not in shell history, not in crash dumps you control, not in the audit log.
3. **Install and host registration (`init`, `sync`) never ask for, read, or store a secret.** `init` creates an empty vault. It never reads `process.env` or the shell environment for values. Remote sync is a separate, explicit user action (`gentle-vault remote …`).
4. **Injection is per child process.** Values go into the environment of exactly one `exec` child (or a pipe/file descriptor when the tool supports it). Never into the agent process, never exported to the parent shell, never inherited by subagents without their own grant.
5. **All output is redacted before return.** stdout, stderr, and any file content the agent reads while a grant is active, for every active value and its common encodings.
6. **Every capture and every grant is an explicit user action.** No auto-approval paths in v1. No "remember forever" without the user choosing it in the prompt.
7. **Every mutation of a user config file is snapshotted first and written atomically.**
8. **No postinstall scripts. No network calls except downloading the signed binary during install, the optional update check (opt-out), and the sync server the user configured (opt-in), which only ever receives data sealed on the device and public keys.** No key that decrypts a vault object ever leaves the device; `exec` never uses the network.
9. **The sync server is untrusted.** Every object downloaded from it is verified (AEAD, AAD account/generation/version, signatures) before use; it never stores or logs anything but ciphertext, public keys, counters and timestamps. Recovery keys and pairing confirmation codes are shown and read only through the prompt backend, never on stdout, stderr, `--json`, logs or arguments.

## Repository layout (target)

```
gentle-vault/
├── cmd/gentle-vault/           Go main: CLI entry
├── cmd/gentle-vault-server/    Go main: optional self-hosted sync server
├── deploy/                     server Dockerfile and compose.yaml (Dokploy)
├── internal/
│   ├── vault/                  encrypted store, envelope format, atomic writes
│   ├── keychain/               OS keychain + passphrase fallback
│   ├── grants/                 grant store, TTL, scope evaluation
│   ├── exec/                   child process runner, env injection, dump-command guard
│   ├── redact/                 streaming redaction (raw, base64, url-encoded, JSON-escaped)
│   ├── audit/                  hash-chained JSONL audit log
│   ├── prompt/                 out-of-band capture: tty, osascript, powershell, zenity
│   ├── broker/                 contract v1 handlers (request/grant/exec/list/revoke)
│   ├── mcp/                    stdio MCP server exposing the broker
│   ├── adapters/               per-agent config writers (claude, codex, opencode, pi)
│   ├── filemerge/              snapshot + atomic merge (mirror gentle-ai semantics)
│   ├── merge/                  three-way per-record merge for sync (pure)
│   ├── remote/                 sync client: keys, pairing, envelopes, rounds, anchors
│   ├── server/                 gentle-vault-server: zero-knowledge store and HTTP API
│   └── doctor/                 read-only health report
├── contracts/secrets-broker/v1/ CONTRACT.md + schema (byte-pinned once released)
├── packages/
│   ├── gentle-vault/           npm launcher: resolves platform binary, `init` entrypoint
│   └── gentle-vault-pi/        TypeScript Pi / Gentle Shell extension
├── scripts/install.sh, install.ps1
├── docs/
└── e2e/                        docker-based leak tests and cross-agent battery
```

## Conventions

- Go 1.25+, module `github.com/<owner>/gentle-vault`. Standard library first; allowed third-party: `golang.org/x/crypto` (chacha20poly1305, argon2), `github.com/zalando/go-keyring`, an MCP SDK (`github.com/modelcontextprotocol/go-sdk`), `github.com/spf13/cobra`. Anything else needs a line in the PR explaining why.
- TypeScript extension: peer-depends on `@mariozechner/pi-coding-agent`, `@mariozechner/pi-tui`, `@sinclair/typebox`; never bundles them. No hardcoded `~/.pi/agent` paths; use the paths Pi provides.
- Conventional Commits. Branch `feat/...`, `fix/...`. PRs ≤ 400 changed lines; split into chained PRs otherwise (see `docs/ROADMAP.md` for the pre-sliced plan).
- Work-unit commits: code + tests + docs for one behavior together.
- Every refusal is typed (`contracts/.../CONTRACT.md` § Refusals). Never return a free-text error where a typed refusal exists.
- Secrets in tests are fixtures with the prefix `TESTSECRET_` so a leak in CI output is greppable. The leak test (`docs/TESTING.md` § Leak tests) greps every captured byte of every tier for those fixtures.

## Definition of done for any feature

- [ ] Behavior matches the spec section it implements (cite it in the PR).
- [ ] Unit tests, including the negative/refusal cases.
- [ ] Leak test extended if the feature touches exec, redact, prompt, mcp or hooks.
- [ ] `gentle-vault doctor` reflects the new state if it changes config.
- [ ] Docs updated in the same PR.
- [ ] AI-assistance disclosed in the PR body.

## What not to build in v1

Team sharing, third-party backends (1Password, Infisical, Vault), browser-based capture, a client daemon, secret rotation, auto-approval policies. gentle-vault's own sync server (`docs/REMOTE_SYNC.md`) **is** in v1. Keep the `Backend` interface so these can come later. See `docs/PRD.md` § Non-goals.
