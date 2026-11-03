# Testing

Three tiers, mirroring Gentle AI, plus a leak battery that runs on every tier.

## Tier 1 — unit (`go test ./...`, `pnpm test` in packages)

| Package | Must cover |
| --- | --- |
| `vault` | layer resolution (project overrides global, global fallback, outside a repo, worktrees, case-folded roots on Windows/macOS); `mv` keeps value and metadata; envelope round-trip; tag failure → `vault_corrupt`; rollback counter; atomic write survives SIGKILL mid-write (temp file left, target intact) |
| `keychain` | backend selection; passphrase mode KDF params; cached key TTL expiry |
| `grants` | (name, layer) binding: a global grant never injects a project override and the reverse; `mv`/`replace`/`rm` drop grants; each scope; expiry purge; `once` consumed exactly once; project root resolution incl. worktrees; no inheritance across sessions |
| `exec` | env scrubbing (same-named parent var removed); injection present in child, absent in parent after; dump-guard list (every entry, plus negative cases like `env | grep PATH` being *allowed* when no secret is injected); binary allowlist with wrappers (`sudo`, `npx`, `uv run`); timeout kills the process group; exit code passthrough |
| `redact` | raw, base64 std/url ±padding, percent (query/path/strict/Python `quote`/JS `encodeURIComponent`, either hex case), JSON-escaped (incl. `\/`), quoted; multi-line values (LF/CRLF translation, each line ≥ 16 bytes alone, whole PEM, interleaved with other output); base64 inner-substring at all three byte alignments (Basic auth `base64(user:value)`, 0–8 byte prefixes, ±padding, std/url); chunk boundaries at every offset of a value and one-byte writes; short-value warning and still redacted; overlapping values (longest wins), shared prefixes, adjacent occurrences; fail-closed after `Wipe`; never printed via `fmt`. `BenchmarkRedact` / `BenchmarkRedactStream` track 1 MiB against 16 secrets (about 130 MB/s on a Ryzen 7 7435HS) |
| `prompt` | each backend behind an interface with a fake; cancel/blank/whitespace paths; value never in argv or stdout |
| `audit` | hash chain; verify detects an edited middle line, a deleted line, a truncated file |
| `broker` | every op; every refusal type reachable; `grant` or `manage` without prompt token → `not_model_callable`; every `manage` action applies only after confirmation and leaves the vault and grants byte-identical on decline; `manage` never creates a grant; `list` never shows another project; `policy` strings match `CONTRACT.md` verbatim; existence not disclosed in `request` responses |
| `adapters` | golden files for each host config before/after; Gentle AI deny entries preserved; idempotency; uninstall restores byte-identical snapshot |
| `gentle-vault-pi` (vitest) | tool results never contain the fixture value; bash override pass-through for commands without references; input transform for each secret pattern; cancel drops input |

Fixture values all start with `TESTSECRET_` and end with a 24-char random suffix.

## Tier 2 — E2E in Docker (`cd e2e && ./docker-test.sh`)

Isolated images for Ubuntu (with and without Secret Service), Alpine (passphrase mode), and a Windows job in CI (native runner). Each runs:

1. `npx gentle-vault init` from the packed npm tarball; assert zero prompts with keychain, exactly one without.
2. `set` via stdin, `list`, `describe`, `exec` with a script that prints `$NAME` in every encoding the redactor knows and several it does not (hex, reversed) — the latter are expected leaks and are reported, not failed, to track R2.
3. Hooks: feed recorded Claude Code hook JSON to `hook pre-bash`/`post`; assert rewrites, denials and redactions.
4. MCP: drive `gentle-vault mcp` with a minimal MCP client; assert the four tools, their descriptions, the `policy` text as server `instructions`, refusal on `grant`.
5. Leaked directory: after storing fixtures in global and project layers, copy `$GENTLE_VAULT_HOME`; assert no file except `audit.jsonl` contains any fixture value, secret name or project root (R-VAULT-09), and `audit.jsonl` contains no value.
6. `uninstall`: configs byte-identical to the pre-init snapshot.

## Tier 3 — cross-agent battery (`scripts/cross-agent-battery.sh`, out of CI)

Spawns real hosts in sandboxed HOMEs with a mock LLM provider that replays scripted tool calls:

- Pi / Gentle Shell: `gentle-shell --mode rpc` with the extension; script: request → capture (driven through RPC UI events) → bash with `$GITHUB_TOKEN` → read of a file containing the value.
- Claude Code: `claude -p` with hooks and MCP; script: Bash referencing the token before and after `secret_request`.
- Codex: `codex exec` with MCP.
- OpenCode: `opencode run` with MCP + plugin.

Costs real host sessions; run before merging anything touching exec/redact/prompt/mcp/hooks/extension.

## Leak battery (every tier)

`exec` leak test (`TestExecLeakBattery`, `internal/cli`): a child prints its secret in raw, base64, base64url, percent, JSON-escaped and split-across-writes form on stdout and stderr; the test runs it in human, `--stream`, `--json` and `--json --stream` modes plus a dump attempt, then scans all captured output and every file under the vault home for the value in the raw, base64, base64url and percent encodings.

After each test, every byte that could reach a model is captured: tool results, MCP responses, hook stdout, host session files (`~/.pi/agent/sessions/**`, `~/.claude/projects/**`, Codex/OpenCode logs), gentle-vault's own stdout/stderr, the audit log, `backups/`, core dumps if any. The battery greps all of it for `TESTSECRET_` and for the base64/percent/JSON encodings of every fixture. **Any hit fails the run.** CI blocks merges on it; a PR touching the listed packages without adding a leak case is rejected by a path-based check.

In CI, `tools/leakgrep` (`go run ./tools/leakgrep PATH...`) runs over `ci-logs/`, which holds the verbose (`-v`) stdout and stderr of every `go test` run on each OS, so output printed by passing tests is scanned too. It scans recursively for `TESTSECRET_` raw, percent-encoded and JSON-escaped, and for base64 (standard and URL-safe) at all three byte alignments. It reports `path:offset: encoding` and never the surrounding bytes; any hit fails the job.

## Contract conformance (`e2e/contract-conformance`)

A host adapter is conformant when, against the JSON schema in `contracts/secrets-broker/v1/`:
- every request it emits validates;
- every response it accepts validates;
- it handles every refusal type (table in CONTRACT.md) with the documented behavior;
- a `grant` sent over its model-facing transport is refused.

Run with `go test ./e2e/contract-conformance -host <name>`.

## Property and fuzz targets

- `redact`: `FuzzRedactStream` — random values, random chunking, random surrounding bytes; invariant: output never contains the value in any modeled encoding.
- `internal/dumpguard`: `FuzzDumpGuard` — mutated known dump commands (prefixes, wrappers, quoting, subshells) must still be refused, and arbitrary text must never panic `Match`, `Segments` or `Binaries`. Every default pattern also has a positive and a negative case, and the embedded `default.yaml` must stay byte-identical to `defaults/dumpguard.yaml`.
- `vault`: `FuzzEnvelope` — corrupted envelopes never decrypt to anything, never panic.
