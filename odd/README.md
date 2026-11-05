# odd/: development logs

These are the working records of how QBit Vault was built, one file per feature in `odd/tasks/`. They are **not user documentation**. To use the tool, start at the [README](../README.md) and [docs/](../docs/).

## What a task file holds

| Section | Content |
| --- | --- |
| Specs (`S1`, `S2`, ...) | What was asked, with the author's words quoted verbatim, and the requirements it maps to |
| Tasks | A table of task IDs, which specs they serve, how each was routed, its commit and its status |
| Log (`L1`, `L2`, ...) | Decisions, discoveries, test evidence (RED/GREEN), review outcomes and commit hashes |

## Why they are in the repository

- They are the evidence behind the statuses in [docs/ROADMAP.md](../docs/ROADMAP.md) (the commit hashes come from here).
- They record why a choice was made when the code alone does not say.
- They are history: a file keeps the wording of its time (branch names such as `feat/cli-skeleton`, the earlier product name in `rename-qbit.md`). When a task file and the code disagree, the code and `docs/` win.

## Where to look

| If you want to know | Read |
| --- | --- |
| How the product works | [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md), [docs/CLI.md](../docs/CLI.md) |
| What is built and what is planned | [docs/ROADMAP.md](../docs/ROADMAP.md), [docs/PRD.md](../docs/PRD.md) § 0 |
| Why the sync design is what it is | `tasks/remote-sync-spec.md`, then [docs/REMOTE_SYNC.md](../docs/REMOTE_SYNC.md) |
| Why the product is called QBit Vault | `tasks/rename-qbit.md` |
| The latest work (TUI, polish, launch preparation) | `tasks/tui.md`, `tasks/polish.md`, `tasks/launch-prep.md` |

Contributors do not need to add a file here. A maintainer may open one for a larger feature.
