# A visible `text` entry does not block a prompt

The `UserPromptSubmit` hook blocks a message that carries the value of any stored entry, `kind: text` included. A `text` entry (a URL, a host, a region) is stored so commands can use it, not because it is secret, and the person types it in the chat all the time, so every such message is blocked. Output redaction keeps covering it; only the prompt block skips it.

## Specs

- S1. Owner, verbatim: "estaria bueno que guarde porque muchas veces se necesita que este almacenado". A `text` entry stays stored, injected by `exec` and redacted by `post-bash` / `post-read` exactly as today.
- S2. `hook user-prompt` does not block a prompt whose only stored match is the value of a `kind: text` entry (any encoding): it prints nothing and exits 0, as for a clean prompt.
- S3. A prompt that also carries the value of a `kind: secret` entry is still blocked, and the reason names only the `secret` entries (`This message contains the value of the stored secret API_KEY, so qbit-vault blocked it. ...`); a `text` entry is never named.
- S4. Well-known secret shapes still block whatever the entry kind (a `text` value shaped like a GitHub token still blocks).
- S5. Docs: PRD R-VAULT-06 and R-CAP-06, AGENT_INTEGRATIONS.md § user-prompt, THREAT_MODEL L34, CLI.md hook row if it describes the block, CHANGELOG [Unreleased] ### Fixed.

## Tasks

| ID | Specs | Route | Commit | Status |
|----|-------|-------|--------|--------|
| T1 | S1-S5 | inline | 84926ed | done |
| T2 | S1-S4 verify | gentle-ai-verify | 84926ed | done |
| T3 | S2-S4 edge tests | inline | b5b3b35 | done |
| T4 | release 1.2.1 | parent | see L6 | in progress |

## Log

- L1. Owner (2026-11-11): every prompt was blocked with "This message contains the value of the stored secret DOKPLOY_URL, so qbit-vault blocked it." DOKPLOY_URL is `kind: text`, `sensitive: false`. Skipping `sensitive: false` was rejected (it is the default for every credential). Owner chose to keep `text` entries stored and stop them from blocking prompts: "y yo creo que estaria bueno que guarde porque muchas veces se necesita que este almacenado".
- L2. T1: RED observed (TestHookUserPromptLetsTextEntriesThrough blocked PANEL_URL), then GREEN: `user-prompt` uses `promptSource`, which skips `Kind == "text"` (an empty kind stays secret); post hooks keep `hookSource`. Docs: PRD R-VAULT-06/R-CAP-06, AGENT_INTEGRATIONS, THREAT_MODEL L34, CLI hook row, CHANGELOG, record.go comment. `go vet ./...` and `go test ./...` green (internal/cli needs the CI `-timeout 30m`; the default 10m timed out). Commit 84926ed.
- L3. T2: the independent verifier was not admitted; checked inline that `Kind` is only set from a validated `text` field or import/export, legacy empty kinds still block, and a prompt with text and secret names only the secret. Native assess: medium, reviewDue false.
- L4. gentle-ai-verify (Risk: item 2) passed S1-S5; gaps: shaped-token case not exact stdout, no project-layer text test, no text/secret shared-value test, no legacy empty-kind test. Owner: "si" to adding them.
- L5. T3: TestHookUserPromptTextKindEdges (project-layer text, from inside and outside the repository; text sharing a secret's value; empty-kind record blocks) and exact stdout for the shaped case. Mutation check: skipping every non-`secret` kind fails it (entries made by `set` have an empty kind), and disabling the filter fails it.
- L6. Picked up from the session that built T1-T3 (owner handoff, 2026-11-11: "Abrí el PR de fix/hook-text-kind contra main y prepará la release"). CHANGELOG [1.2.1] (patch: fixes only, this one and the unreleased grant-note fix of PR #48). The tag is pushed after the merge.
