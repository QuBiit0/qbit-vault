# Security policy

QBit Vault holds secrets, so security reports get priority over everything else.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository (GitHub private vulnerability reporting).

Please include:

- what an attacker can do (read a value, approve a grant, bypass redaction, corrupt the vault, ...);
- the steps or a proof of concept, using fake values only (for example `TESTSECRET_...`), never a real secret;
- the QBit Vault version (`qbit-vault version`), OS and coding-agent host involved.

You will get an acknowledgement within 7 days. Fixes for confirmed issues are released as soon as they are ready, and the report is credited in the changelog unless you prefer otherwise.

## Scope

In scope: anything that breaks an invariant in [AGENTS.md](AGENTS.md) or the threat model in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), in particular:

- a secret value reaching a model, a tool result, a log, the audit log, the TUI or an error message;
- a secret value written to disk unencrypted;
- a grant created or approved without the user's explicit action;
- redaction bypasses for a value injected into a command;
- the sync server learning a value or forging a change (`qbit-vault-server` is zero-knowledge and untrusted by design).

Out of scope: attacks that need the user's unlocked OS account or root on the machine, and a user who deliberately types a secret into a non-secret field (a description, a commit message).

## Supported versions

Only the latest release is supported: fixes ship in a new release and older versions, including the 0.1.0 betas, do not get them. Upgrade by re-running the install command.
