## What and why

<!-- The behavior this changes and the spec section it implements (docs/PRD.md, CONTRACT.md, ...). -->

## Checklist

- [ ] Tests first, including the negative and refusal cases
- [ ] Leak test extended if this touches exec, redact, prompt, mcp, hooks or the TUI
- [ ] `go vet ./...` and `go test ./...` pass; Docker batteries run when relevant
- [ ] Docs and `--help` text updated
- [ ] No secret value in code, tests, logs or this description (fixtures use `TESTSECRET_`)
- [ ] About 400 changed lines or less (split bigger work into a chain)

## AI assistance

<!-- Say whether and how AI tools were used. -->
