# Feature: qbit-vault agent skill, installed and kept current by init and sync

Ship a `qbit-vault` skill that tells agents when and how to use the broker, install it as one more host step, and rewrite it on every upgrade only when its text changed.
Branch `feat/agent-skill`.

## Specs

- S1. User (verbatim): "agregalo y que la skill simepre se vaya actualizando en cada version que vayamos haciendo y mejorando."
- S2. User (verbatim): "la instalacion de la skill siempre y cuando sea necesaria no..."
- S3. Rule kept from an earlier request (verbatim): "recuerda siempre no overraidear las versiones y mantener los manifestos en la instalacion, actualizacion, etc.."
- S4. Agreed shape (assistant proposal, accepted by S1): an optional skill that `init` installs in agents that support skills and `uninstall` removes; it never writes the user's CLAUDE.md or AGENTS.md.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| K1 | S2, S3, S4 | inline | filemerge owned-file write/revert/check (snapshot first, atomic, marker, refuses a foreign file) | | pending |
| K2 | S1, S2, S4 | inline | embedded SKILL.md; `skill` step for claude-code (~/.claude/skills), codex and pi (shared ~/.agents/skills); shared-file revert; tests; docs | | pending |

## Log

- L1. User request verbatim in S1, S2.
- L2. Skill locations checked 2026-11-05. Claude Code: `~/.claude/skills/<name>/SKILL.md`. Codex: user skills in `~/.agents/skills` (`~/.codex/skills` is the legacy name; openai/codex#10437, #14337). Pi: `~/.pi/agent/skills` and also `~/.agents/skills` (pi-coding-agent docs/skills.md: "Name collisions keep the first discovered skill and produce a warning"). Decision: Codex and Pi share one file, `~/.agents/skills/qbit-vault/SKILL.md`, so Pi never sees a duplicate; it is removed only when no other registered host still records it.
- L3. "Only when necessary" (S2) means: only for registered hosts that read skills; written only when the bytes differ from the embedded skill (no file, snapshot or receipt change otherwise); the skill text carries no version string, so a release that does not change it rewrites nothing. "Always updated" (S1): `sync` rewrites a stale skill and the install scripts run `sync` after every upgrade; `doctor` reports a stale one as drift.
