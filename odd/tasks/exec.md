# Feature: roadmap slice 1.8, exec

`gentle-vault exec`: run one command with granted secrets injected into that child only, after
the grant check, the dump-command guard and the binary allowlist; stream its output through the
redactor; enforce a timeout on the whole process tree; audit it. Branch `feat/cli-skeleton`.

## Specs

- S1. ROADMAP 1.8: "`exec`: env build/scrub, dump-guard from `dumpguard.yaml`, binary allowlist, timeout, pgroup, `--stream`" (R-EXEC-*).
- S2. R-EXEC-01: "run `<command>` as a child process whose environment is the parent environment **minus** any variable already named like a vault secret, **plus** the granted values. The value MUST NOT be exported to the parent."
- S3. R-EXEC-03: "While any secret is injected, the command MUST be refused (typed refusal `dump_command`) if it matches the dump-command list ... The list MUST be a data file, not code, so it can be extended without a release." defaults/dumpguard.yaml header: "Patterns are RE2, matched against each pipeline segment after shell-word normalization. `{NAME}` expands to every injected name. User-extendable; never shortened by `sync`."
- S4. R-EXEC-04/05: output streamed through the redactor; child exit code propagated unchanged. R-EXEC-06: audit session, secret names, command (redacted), cwd, exit code, duration. R-EXEC-07: "When the secret's `binaries` allowlist is non-empty, the first token of the command (after resolving `sudo`, `env`, `npx`, `pnpm exec`, `uv run`) MUST be in the list; otherwise typed refusal `scope_binary`." R-EXEC-08: hosts advisory warning. R-EXEC-09: "wall-clock timeout (default 10 min, flag `--timeout`) and kill the process group on expiry."
- S5. docs/CLI.md § Exec usage line, `--secret NAME[=ENV]`, `--stream` NDJSON, "Exit code: the child's. Refusals exit 3". CONTRACT.md § exec response `{ ok, exit_code, stdout, stderr, duration_ms, redactions, truncated }`, 1 MiB cap per stream keeping the tail, refusal `timeout` with `partial`.
- S6. STORAGE.md § Grants evaluation; slice 1.6 note: `Check` expects a case-folded cwd root on Windows.
- S7. AGENTS.md invariants 1, 2, 4, 5.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S3, S4 | worker | `internal/dumpguard`: data-file parser, embedded default + user extension, shell-word segmentation, `{NAME}` expansion, wrapper resolution for the allowlist | feat(dumpguard) | done |
| T2 | S2, S4, S7 | worker | `internal/runner`: env build/scrub, shell selection, process tree kill on timeout (POSIX process group, Windows job object), redacted capture and streaming, caps | feat(runner) | done |
| T3 | S1, S4-S7 | worker | CLI `exec`: resolution, grant check/consume, guard, allowlist, hosts advisory, two-phase audit, outputs; docs | feat(cli) exec | done |

## Log

- L1. User: "continua" (proceed with slice 1.8; the agent's recommendation of fail-closed audit for exec was stated before and not objected to).
- L2. Decision: audit is fail-closed for exec in two phases: an `exec` record with `outcome: "started"` (names, layer, session, redacted command, cwd) is appended before the child starts; if it fails, exec is refused (`internal`) and nothing runs. After the child ends, a second `exec` record with `outcome: "finished"` carries exit code, duration and redactions (best-effort, stderr warning on failure). PRD R-EXEC-06 is reworded accordingly.
- L3. Decision: the binary allowlist applies to every pipeline/sequence segment of the command, not only the first token, because the injected environment reaches every process the shell starts.
- L4. Decision: the YAML data files are parsed by a small purpose-built reader for their fixed shape (`format:` plus a `patterns:` list of quoted strings with optional trailing comments); no YAML dependency. The default `dumpguard.yaml` is embedded; `$GENTLE_VAULT_HOME/dumpguard.yaml`, when present, adds patterns and can never remove a default one.
- L5. Decision: `--shell auto` is `/bin/sh -c` on POSIX; on Windows it is `bash -c` when `bash` is on PATH (Git Bash, which agents use), else `cmd /d /s /c`.
- L6. Decision: the child inherits stdin; values reach the child only through its environment (Go's os/exec needs strings, so those copies cannot be wiped; accepted and documented, like the GC note in STORAGE.md).
- L7. Decision: `once` grants are consumed before the child starts, so a failed run still uses up the grant.
- L8. First worker was interrupted (session limit) with T1/T2 complete and T3 nearly done; a second worker audited every T1-T3 item against the spec, added the missing end-to-end leak battery (`TestExecLeakBattery`, passed first run, no RED), and fixed `TestExecBinaryAllowlist`, which was a test bug: the test binary itself was outside both allowlists, so the first secret correctly refused (L3 checks every segment). All checks green incl. FuzzDumpGuard 20 s (~320k execs) and POSIX vet.
