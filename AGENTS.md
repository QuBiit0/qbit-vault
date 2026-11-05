# AGENTS.md — instructions for the coding agent building QBit Vault (`qbit-vault`)

You are implementing qbit-vault from the specification in this repository. Read this file first, then `docs/PRD.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md` and `contracts/secrets-broker/v1/CONTRACT.md` before writing code (and `docs/REMOTE_SYNC.md` before touching sync or the server). The spec is the authority; when code and spec disagree, fix the code or open a spec change, never silently diverge.

## Non-negotiables (security invariants)

These are tested, not just documented. A PR that breaks one is rejected regardless of what else it does.

1. **No secret value ever crosses the model boundary.** No tool result, MCP response, hook stdout, log line, error message, panic, or debug output may contain a secret value. Errors mention the secret **name** only.
2. **No secret value ever touches disk unencrypted.** Not in temp files, not in shell history, not in crash dumps you control, not in the audit log.
3. **Install and host registration (`init`, `sync`) never ask for, read, or store a secret.** `init` creates an empty vault. It never reads `process.env` or the shell environment for values. Remote sync is a separate, explicit user action (`qbit-vault remote …`).
4. **Injection is per child process.** Values go into the environment of exactly one `exec` child (or a pipe/file descriptor when the tool supports it). Never into the agent process, never exported to the parent shell, never inherited by subagents without their own grant.
5. **All output is redacted before return.** stdout, stderr, and any file content the agent reads while a grant is active, for every active value and its common encodings.
6. **Every capture and every grant is an explicit user action.** No auto-approval paths in v1. No "remember forever" without the user choosing it in the prompt.
7. **Every mutation of a user config file is snapshotted first and written atomically.**
8. **No postinstall scripts. No network calls except downloading the signed binary during install, the optional update check (opt-out), and the sync server the user configured (opt-in), which only ever receives data sealed on the device and public keys.** No key that decrypts a vault object ever leaves the device; `exec` never uses the network.
9. **The sync server is untrusted.** Every object downloaded from it is verified (AEAD, AAD account/generation/version, signatures) before use; it never stores or logs anything but ciphertext, public keys, counters and timestamps. Recovery keys and pairing confirmation codes are shown and read only through the prompt backend, never on stdout, stderr, `--json`, logs or arguments.

## Repository layout

What exists on `feat/cli-skeleton`. Items marked *planned* do not exist yet (`docs/ROADMAP.md`).

```
qbit-vault/                     (module github.com/QuBiit0/qbit-vault)
├── cmd/qbit-vault/             Go main: CLI entry
├── cmd/qbit-vault-server/      Go main: optional self-hosted sync server (serve, invite, health)
├── deploy/                     server Dockerfile and compose.yaml (Dokploy)
├── defaults/                   bindings.yaml (not loaded yet), dumpguard.yaml (embedded copy in
│                               internal/dumpguard, kept equal by a test), secret-patterns.yaml
├── internal/
│   ├── vault/                  encrypted store, layers, envelope users, atomic writes, backups,
│   │                           schema 2 body, restore, rekey, sync state files
│   ├── envelope/               AEAD envelope shared by vault.enc, grants.enc and remote files
│   ├── keychain/               OS keychain + passphrase fallback, unlock cache
│   ├── perm/                   owner-only permissions (POSIX modes, Windows DACL)
│   ├── lockfile/               cross-process lock files
│   ├── secret/                 Secret type that redacts on every output path
│   ├── refusal/, exitcode/     typed contract refusals and exit codes
│   ├── grants/                 grant model, TTL, scope evaluation, prompt tokens
│   ├── runner/                 child process runner: env injection, shell choice, tree kill, caps
│   ├── dumpguard/              dump-command guard and wrapper/segment parser
│   ├── redact/                 streaming redaction (raw, base64, url-encoded, JSON-escaped, ...)
│   ├── audit/                  hash-chained JSONL audit log
│   ├── prompt/                 out-of-band capture: tty, osascript, powershell, zenity, kdialog
│   │                           (scripted backend only in -tags e2eprompt builds)
│   ├── broker/                 contract v1 handlers (request/list/exec/manage/grant/revoke)
│   ├── mcp/                    stdio MCP server exposing the broker
│   ├── conformance/            contract schema validation (tests only)
│   ├── hook/                   Claude Code hooks: pre-bash, post-bash, post-read, user-prompt
│   ├── hosts/                  Adapter interface, step runner, receipts; adapters in
│   │                           claude/, codex/, pi/ (fake/ is test-only)
│   ├── filemerge/              snapshot + atomic JSON/TOML merge and 3-way revert
│   ├── doctor/                 read-only health report
│   ├── dotenv/                 dotenv parser for import
│   ├── merge/                  three-way per-record merge for sync (pure)
│   ├── remote/                 sync client: keys, pairing, envelopes, rounds, anchors
│   ├── server/                 qbit-vault-server: zero-knowledge store and HTTP API
│   └── cli/                    cobra commands, prompts, session and sync plumbing
├── contracts/secrets-broker/v1/ CONTRACT.md + JSON schema (byte-pinned once released)
├── docs/                       PRD, ARCHITECTURE, CLI, STORAGE, REMOTE_SYNC, THREAT_MODEL, TESTING,
│                               AGENT_INTEGRATIONS, GENTLE_SHELL_EXTENSION, INSTALL, ROADMAP, PROPOSAL
├── e2e/                        Docker batteries: docker-test.sh (sync), hosts-test.sh (hosts),
│                               plus leakscan/, mcpclient/, proxy/ helpers
├── tools/leakgrep/             CI leak grep over captured test output
├── odd/tasks/                  work logs (what was built, decisions, commits)
├── .github/workflows/ci.yml    build, vet, test on Linux/macOS/Windows, leak grep
├── packages/qbit-vault-pi/     planned (Phase 4): TypeScript Pi / Gentle Shell extension
├── packages/qbit-vault/        planned (Phase 5): npm launcher
└── scripts/install.sh, install.ps1   planned (Phase 5)
```

## Conventions

- Go 1.26 (`go.mod`), module `github.com/QuBiit0/qbit-vault`. Standard library first; allowed third-party: `golang.org/x/crypto` (chacha20poly1305, argon2), `golang.org/x/sys` (Windows ACLs) and `golang.org/x/term` (echo-off terminal input), `github.com/zalando/go-keyring`, an MCP SDK (`github.com/modelcontextprotocol/go-sdk`), `github.com/spf13/cobra`. Anything else needs a line in the PR explaining why. The MCP SDK (v1.8.0) compiles in, transitively: `github.com/google/jsonschema-go` (tool input schemas), `github.com/segmentio/asm` and `github.com/segmentio/encoding` (its JSON), `github.com/yosida95/uritemplate/v3`, `golang.org/x/oauth2` (its `auth` package, imported by `mcp` though qbit-vault uses no OAuth), `golang.org/x/sync` and `golang.org/x/time`. `github.com/google/jsonschema-go` is also imported directly, only by `internal/conformance`, which only tests import (it is not in the binary).
- TypeScript extension: peer-depends on `@mariozechner/pi-coding-agent`, `@mariozechner/pi-tui`, `@sinclair/typebox`; never bundles them. No hardcoded `~/.pi/agent` paths; use the paths Pi provides.
- Conventional Commits. Branch `feat/...`, `fix/...`. PRs ≤ 400 changed lines; split into chained PRs otherwise (see `docs/ROADMAP.md` for the pre-sliced plan).
- Work-unit commits: code + tests + docs for one behavior together.
- Every refusal is typed (`contracts/.../CONTRACT.md` § Refusals). Never return a free-text error where a typed refusal exists.
- Secrets in tests are fixtures with the prefix `TESTSECRET_` so a leak in CI output is greppable. The leak test (`docs/TESTING.md` § Leak battery) greps every captured byte of every tier for those fixtures.

## Definition of done for any feature

- [ ] Behavior matches the spec section it implements (cite it in the PR).
- [ ] Unit tests, including the negative/refusal cases.
- [ ] Leak test extended if the feature touches exec, redact, prompt, mcp or hooks.
- [ ] `qbit-vault doctor` reflects the new state if it changes config.
- [ ] Docs updated in the same PR.
- [ ] AI-assistance disclosed in the PR body.

## What not to build in v1

Team sharing, third-party backends (1Password, Infisical, Vault), browser-based capture, a client daemon, secret rotation, auto-approval policies. qbit-vault's own sync server (`docs/REMOTE_SYNC.md`) **is** in v1. Keep the `Backend` interface so these can come later. See `docs/PRD.md` § Non-goals.
