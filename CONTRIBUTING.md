# Contributing to QBit Vault

Thanks for helping. QBit Vault is a secrets broker, so the bar is correctness and safety first.

## Before you start

1. Read [AGENTS.md](AGENTS.md): the security invariants there are tested and non-negotiable.
2. Read the spec for the area you touch: [docs/PRD.md](docs/PRD.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [contracts/secrets-broker/v1/CONTRACT.md](contracts/secrets-broker/v1/CONTRACT.md). When code and spec disagree, fix the code or propose a spec change in the same pull request.
3. For anything bigger than a small fix, open an issue first so the approach can be agreed.

Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Development

Requirements: Go (the version in `go.mod` or newer), git, and Docker for the end-to-end batteries.

```sh
git clone https://github.com/QuBiit0/qbit-vault.git
cd qbit-vault
go build ./...
go vet ./...
go test ./...
```

End-to-end batteries (Docker; they never touch your real home or keychain):

```sh
bash e2e/install-test.sh   # install from scratch and the whole agent flow
bash e2e/docker-test.sh    # sync between devices through qbit-vault-server
bash e2e/hosts-test.sh     # host registration, hooks and MCP
```

Never run the `qbit-vault` binary against your real home while developing: tests isolate it, and the batteries run in containers. Test fixtures that stand for secrets start with `TESTSECRET_`, so a leak is easy to find.

See [docs/TESTING.md](docs/TESTING.md) for the test tiers.

## Pull requests

- Test first: a failing test for the behavior, then the change. Include the negative and refusal cases.
- Every refusal is typed (contract § Refusals); errors name a secret, never its value.
- Keep a pull request to about 400 changed lines; split bigger work into a chain.
- One behavior per commit, with its tests and docs; [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, ...).
- Update the docs and `--help` text of anything you change.
- Disclose AI assistance in the pull request description.
- CI must be green on Linux, macOS and Windows.

## How contributions are reviewed

1. **Issues** start with the `needs-triage` label. The maintainer (often with a coding agent's help) adds a type and an `area:*` label, asks for missing data, or closes duplicates. Bug reports without the output of `qbit-vault doctor` usually need one more round.
2. **Pull requests** run CI on Linux, macOS and Windows. A first-time contributor's run starts once the maintainer approves it.
3. The maintainer reviews, possibly with a coding agent that follows [.agents/skills/contribution-review/SKILL.md](.agents/skills/contribution-review/SKILL.md): it tests the change in a container and checks it against the invariants in AGENTS.md. **The agent recommends; the maintainer decides** what is approved, changed or declined, and merges.
4. `main` is protected: changes land through a pull request with green CI.

You can run the same review on your own branch before opening a pull request: ask your agent to follow that skill. It is also installed for Claude Code at `.claude/skills/contribution-review/`, and Codex and Pi read `.agents/skills/` directly.

## Dependencies

Standard library first. The allowed third-party modules are listed in AGENTS.md § Conventions; a new one needs a line in the pull request explaining why.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
