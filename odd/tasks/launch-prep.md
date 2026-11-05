# Feature: launch preparation

Get the private GitHub repo QuBiit0/qbit-vault ready for a future public launch with the community: green CI, every document current, a tidy repository, community health files. The repo stays private for now. Branch `chore/launch-prep`, one PR to `main` at the end.

## Specs

- S1. User (verbatim): "si ya esta todo listo y funcional podrias actualizar todos los documentos ordenar el repo y dejar todo listo para la presentacion en un futuro de mi repo de github? por ahora lo dejamos privado pero quiero tenerlo listo para el lanzamiento formal con la comunidad. cuando tengas todo esto listo avisame, renombro la carpeta y lo voy a instalar en mi ecosistema para probarlo en mi dia a dia"
- S2. "Funcional" includes the GitHub CI: it failed on the PR and on main (Linux and Windows) while every local run was green. It must be green on ubuntu, macos and windows.
- S3. Every document matches the code (README, docs/*, AGENTS.md, contracts), with no claim of anything unbuilt; planned items labeled planned.
- S4. Tidy repository: no stray or tool-generated files tracked, clear layout, internal development logs placed where they do not confuse a newcomer.
- S5. Community health files for a launch: LICENSE (user's choice), CONTRIBUTING, SECURITY (private vulnerability reporting), CODE_OF_CONDUCT, issue and PR templates, CHANGELOG; repository description and topics.
- S6. Ready to install day to day: a clear install path from the private repo for the user, documented.

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T1 | S2 | inline | | in progress |
| T2 | S5 | inline | | pending |
| T3 | S3, S4, S6 | worker | | pending |
| T4 | S2, S5 | inline | | pending |

- T1: fix the CI failures (JSON redaction of invalid UTF-8 under Go 1.26; Windows-only host path tests on POSIX); CI also tests the Go version go.mod names and the latest stable.
- T2: community files (needs the user's license choice).
- T3: documentation and repository tidy-up.
- T4: PR, CI green on the three OSes, repository metadata, report.

## Log

- L1. User request verbatim in S1.
- L2. CI on PR #1 and main failed: `internal/redact` TestJSONEscapeMatchesEncodingJSON and FuzzRedactStream/seed#3 on ubuntu and windows, `internal/hosts/claude` TestWindowsPathsAreEscaped and `internal/hosts/codex` TestWindowsPathsRenderAsValidTOML on ubuntu; macos cancelled. Cause: local Go is 1.27.3, CI installs Go 1.26 (go.mod `go 1.26.0`). For invalid UTF-8 bytes Go 1.26 encoding/json writes the escape `\ufffd`, Go 1.27 the literal U+FFFD; the redactor modeled only 1.27, so a value mixing literal non-ASCII text with an invalid byte, JSON-encoded by Go 1.26, survived redaction (the bytes around the invalid one would reach the agent). RED: TestJSONFormsOfInvalidUTF8AreReplaced failed on the Go 1.26 form. Fix: values with invalid UTF-8 also register the escaped variant (internal/redact/redact.go, encode.go jsonEscapeInvalid); TestJSONEscapeMatchesEncodingJSON accepts either real form. The host tests check Windows path escaping and now skip off Windows (on POSIX a `C:\` path is correctly refused as not absolute). GREEN: internal/redact with go1.26.4 and go1.27.3 on Windows, internal/redact and internal/hosts/... with go1.26.10 on Linux (Docker).
