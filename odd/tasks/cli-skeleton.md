# Feature: roadmap slice 1.1, repository skeleton

First code slice of `docs/ROADMAP.md` Phase 1. Go module, cobra CLI with global flags, `--json`,
exit codes, the redacting `Secret` type, and CI with the leak grep. Branch `feat/cli-skeleton`.

## Specs

- S1. ROADMAP 1.1: "Repo skeleton, cobra CLI, `--json`, exit codes, `Secret` type with redacting `String/Format/MarshalJSON`, CI with leak grep"
- S2. Module path: user answered "mi cuenta personal" for the GitHub owner; `gh api user` reports `QuBiit0`, so the module is `github.com/QuBiit0/gentle-vault`.
- S3. CLI.md global flags: "`--home <dir>` (default `$GENTLE_VAULT_HOME` or `~/.gentle-vault`), `--json` (machine output, exactly one JSON object on stdout), `--session <id>` (host session; required by `exec`, `set --grant`, `grant`, `revoke --session-only`), `--quiet`, `--no-color`."
- S4. CLI.md exit codes: "0 Success", "1 Generic failure / doctor warnings", "2 Usage error / doctor errors", "3 Typed refusal (see CONTRACT.md)", "4 Vault locked", "5 Vault corrupt / rollback detected".
- S5. AGENTS.md invariant 1: "No tool result, MCP response, hook stdout, log line, error message, panic, or debug output may contain a secret value." THREAT_MODEL L14: "Values are held in a `Secret` type whose `String()`/`Format()`/`MarshalJSON` return `[REDACTED]`".
- S6. AGENTS.md: "Secrets in tests are fixtures with the prefix `TESTSECRET_` so a leak in CI output is greppable."

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T0 | - | inline | Import the existing specification as the first commit | | pending |
| T1 | S5, S6 | inline | `internal/secret`: `Secret` type, redacting formatters, wipe, tests | | pending |
| T2 | S1-S4 | inline | `go.mod`, `cmd/gentle-vault`, `internal/cli`, `internal/exitcode`: root, global flags, `version`, JSON output, usage errors; tests; CLI.md | | pending |
| T3 | S1, S6 | inline | `.github/workflows/ci.yml`, `scripts/leak-grep.sh`: build, vet, test, leak grep over every captured byte | | pending |

## Log

- L1. User: "mi cuenta personal. continuemos"
- L2. Decision: in `--json` mode a non-refusal CLI failure (usage error, generic failure) prints `{"ok":false,"error":{"code":"usage"|"internal","message":"..."}}`. Contract refusals keep their own shape and exit 3. Documented in CLI.md.
