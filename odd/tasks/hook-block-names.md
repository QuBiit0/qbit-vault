# Issue #45: a blocked message says what matched and what to do

The `UserPromptSubmit` hook blocks a whole message that carries a stored value or a well-known secret shape. Harness notifications (a background job that finished, a subagent report) arrive through the same hook and are blocked too, with a reason that names nothing. Claude Code cannot rewrite a prompt from this hook (documented: "UserPromptSubmit: can't replace the prompt; it only injects additionalContext alongside it"; no input field tells a typed prompt from an automated one), and letting it through would send the value to the model, so the block stays; the fix makes it useful and removes the cause.

## Specs

- S1. Issue #45 (QuBiit0), verbatim expectations: "For messages that are not typed by the person (task or job notifications, tool-result relays), redact the matched value (for example `[REDACTED:NAME]`, the same style as the exec tool output) and let the rest through, instead of blocking the whole message. In every case, name the entry that matched (name only, never the value)." The first half is not possible with this hook (see above; the reply on the issue explains it); the second half is S2-S3.
- S2. A message blocked for a stored value names every matching entry, by name only, sorted and without repeats, at most 5 names then `and N more`: `This message contains the value of the stored secret GITHUB_TOKEN, so qbit-vault blocked it.` (plural: `of the stored secrets A, B`). A `[REDACTED:X]` text already present in the message is not reported as a match. The reason never contains the message, the value or any part of it.
- S3. A message blocked for a well-known shape names the kind, never the text: GitHub token, GitHub fine-grained token, AWS access key, Slack token, Stripe live key, API key (`sk-` keys), private key, JWT; for example `This message looks like it contains a GitHub token, so qbit-vault blocked it.`
- S4. Both reasons then say what to do, in fixed words: `If you typed or pasted it, store it with 'qbit-vault set NAME' in your own terminal and refer to it by name. If it came from a background job or another agent's report, the command printed the value: run it through qbit-vault (secret_exec), which redacts its output.`
- S5. The agent skill (internal/hosts/skill/SKILL.md) says: a background job, a script or a subagent command that uses a credential runs through `secret_exec`, so its output and the notification when it ends are redacted; a job that prints a stored value directly makes the host drop its completion notice, and the person sees a block naming the secret.
- S6. Docs: AGENT_INTEGRATIONS.md § user-prompt (the new reasons, why the hook cannot redact), CLI.md hook row, THREAT_MODEL L34 if its wording changes, CHANGELOG [Unreleased] ### Fixed (#45).

## Tasks

| ID | Specs | Route | Commit | Status |
|----|-------|-------|--------|--------|
| T1 | S2-S6 | worker | | done (uncommitted) |
| T2 | review, PR, CI, merge, reply on #45, release 1.2.0 | parent | | pending |

## Log

- L1. Issue #45, "UserPromptSubmit hook blocks harness-generated notifications, so the agent never receives the event" (QuBiit0, 2026-11-10). Owner: "corrige el bug o issue reportado tambien", then "haz todo hasta finalizar ... te autorizo a todo".
- L2. T1 done, uncommitted: user-prompt reasons name the stored entries (derived from the redacted output, token count above the input's) or the shape kind, both ending in the S4 advice (`BlockAdvice`); `BlockStoredReason`/`BlockShapeReason` replaced by `storedReason`/`shapeReason`; skill section "Background jobs, scripts and subagents"; AGENT_INTEGRATIONS, CLI, CHANGELOG updated; THREAT_MODEL L34 wording unchanged (still accurate).
