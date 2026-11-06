# Gentle Shell / Pi extension: `qbit-vault-pi`

**Status: design only (Phase 4, pending).** `packages/qbit-vault-pi` does not exist and nothing below is built. What works today for Pi and Gentle Shell: `qbit-vault init` registers the `qbit-vault` MCP entry in Pi's `mcp.json` (`AGENT_INTEGRATIONS.md`), so the four tools, the native dialogs and `exec` redaction are available; the bash override, paste interception, `/vault` commands and the sidebar need this extension. This document is the target design. It assumes CLI pieces that do not exist yet, noted where they appear: `set --reason`, `set --stdin --fields`, `prompt --field`, `prompt --confirm` and a `redact` command.

npm package `qbit-vault-pi`. Installed by the user: `qbit-vault init` only registers the MCP entry; while the package is unpublished it prints no install line (when it is published the user installs it, `init` never does: AGENTS.md invariant 8); with Gentle Shell, `gentle-shell install npm:qbit-vault-pi` (isolated home). Written in TypeScript against the Pi extension API; peer-depends on `@mariozechner/pi-coding-agent`, `@mariozechner/pi-tui`, `@sinclair/typebox`.

The extension never opens the vault. Every operation shells out to the `qbit-vault` binary with `--json` (or `broker --op`), passing the Pi session id as `--session pi:<id>` and values over stdin.

## Responsibilities

1. **Tools**: register `secret_request`, `secret_list`, `secret_exec`, `secret_manage` with TypeBox schemas mirroring the contract. Descriptions are the normative texts from `CONTRACT.md`; the `policy` block from `secret_list` is also appended to the system prompt once per session (`before_agent_start`), so the agent knows its rules before its first call.
2. **Masked capture**: `secret_request` opens a `ctx.ui.custom()` component: title with name and reason, a masked `Input` (rendered as `●`), a `SelectList` for layer (`Global / This project (<label>)`, shown only inside a repository), a `SelectList` for scope (`Once: only the next command` preselected / `Always: in this project, until you revoke it`, inside a repository only / `Don't allow`), the same answers as the native dialog; an agent request is never offered a session answer, Esc to cancel. On submit: spawn `qbit-vault set NAME --global|--project --stdin --session pi:<id> --grant <scope> --reason "<reason>" --json`, write the value to stdin, close stdin. If the broker reports the value already exists, the component is shown in **grant-only** mode (no input field) — the extension learns this from `qbit-vault describe NAME --json` before rendering, which is fine because the extension is trusted; the model still only sees `{ok, ref, grant}`.
2a. **Management confirmation**: `secret_manage` opens a `ctx.ui.custom()` confirmation showing action, name, layer, the before/after diff (widening changes highlighted) and the reason, with `Confirm` / `Decline`. `replace` reuses the masked input. On confirm the extension calls `qbit-vault broker --op manage` with the prompt token; the model only receives `{ok, applied, …}` or `user_declined`.
3. **Bash override**: `pi.registerTool({ name: "bash", … })` wrapping Pi's built-in bash. Before execution: scan the command for `$NAME`, `${NAME}`, `{{secret:NAME}}` and for implicit bindings (`bindings.yaml`). For each referenced name: `qbit-vault grants --json` → if no grant, open the grant component (same UI, grant-only), then run `qbit-vault exec --session pi:<id> --secret … --stream --json -- <command>` and stream redacted chunks into the tool result. Commands with no secret references fall through to the original bash tool untouched (zero overhead on the common path).
4. **Read/write guard** (`tool_call` and `tool_result` hooks): while any grant is active for the session, `read` results pass through `qbit-vault redact --session … --stdin` (a command to be added with this extension); `write`/`edit` inputs that contain an active value are blocked with a notification and the model is told to use `{{secret:NAME}}` or `$NAME` instead.
5. **Paste interception** (`pi.on("input")`): detect secret-shaped text (patterns in `secret-patterns.yaml`, shared with the Go side); open the capture component pre-filled with the detected value (masked), ask for a name (suggested from the pattern, e.g. `GITHUB_TOKEN` for `ghp_`), store it, and `transform` the input to replace the literal with `secret://NAME`. If the user cancels, the input is **dropped**, not sent (safe default), with a notification.
6. **Commands** (the user's manual path, no model involved): `/vault list [global|project|all]`, `/vault set NAME [global|project]`, `/vault rm NAME`, `/vault mv NAME global|project`, `/vault edit NAME`, `/vault revoke [NAME|--all]`, `/vault audit [--tail N]`, `/vault doctor`. `/vault set` opens the same masked capture as `secret_request` without a reason field; the typed value goes to `qbit-vault set --stdin` and never into the chat or the session file. All render in a fullscreen view consistent with Gentle Shell (`/gentle:*` look and feel; reuse its Kanagawa theme tokens when present).
7. **Sidebar widget** (Gentle Shell only, feature-detected): a "Vault" frame showing the current project label, active grants with their layer and remaining TTL, and the last three audit events. Registered through Gentle Shell's extension points when available; otherwise a `ctx.ui.setStatus("qbit-vault", "🔐 2 grants")` footer status.
8. **Subagents**: Gentle Agents children get `pi:<child-session-id>`; the override runs in each child's extension instance, so grants do not leak across.

## Session lifecycle

- `session_start`: `qbit-vault doctor --json`; if the binary is missing or the vault is locked, notify once with the fix (`qbit-vault init` / `qbit-vault unlock`), and register the tools in **degraded mode** (every call returns `vault_locked`).
- `session_end` / `shutdown`: `qbit-vault revoke --session-only --session pi:<id>` so `session` grants never outlive the Pi process (the TTL is the backstop).
- Compaction: no state to preserve; grants live in the broker.

## Files

```
packages/qbit-vault-pi/
├── package.json          { "pi": { "extensions": ["./dist/index.js"] }, peerDependencies: … }
├── src/
│   ├── index.ts          registers tools, override, hooks, commands
│   ├── broker.ts         spawn wrapper: run(op, envelope, stdinValue?) → typed result
│   ├── ui/capture.tsx    masked input + scope select (pi-tui)
│   ├── ui/vault-view.ts  fullscreen list/audit views
│   ├── scan.ts           reference + binding + secret-pattern scanning (pure, unit-tested)
│   ├── redact-stream.ts  chunk re-assembly for --stream output
│   └── types.ts          TypeBox schemas = contract v1
├── secret-patterns.yaml  shared with Go via a generated test ensuring parity
└── test/                 vitest; mocks ExtensionAPI; leak assertions on every tool result
```

## Minimal `index.ts` shape

```ts
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";
import { broker } from "./broker";
import { scanReferences } from "./scan";
import { CaptureView } from "./ui/capture";

export default function (pi: ExtensionAPI) {
  const session = () => `pi:${pi.sessionId}`;

  pi.registerTool({
    name: "secret_request",
    label: "Request secret",
    description: "<normative text from CONTRACT.md>",
    parameters: Type.Object({
      name: Type.String({ pattern: "^[A-Z][A-Z0-9_]{0,63}$" }),
      reason: Type.String({ minLength: 8, maxLength: 200 }),
      suggested_scope: Type.Optional(Type.Union([Type.Literal("once"), Type.Literal("session"), Type.Literal("project")])),
    }),
    async execute(args, ctx) {
      if (!ctx.hasUI) return broker.refusal("user_declined", args.name, "no UI to prompt");
      const existing = await broker.describe(args.name);
      const choice = await ctx.ui.custom(new CaptureView({ ...args, grantOnly: existing.ok }));
      if (!choice) return broker.refusal("user_declined", args.name, "cancelled");
      return existing.ok
        ? broker.grant(session(), args.name, choice.scope, choice.token)
        : broker.set(session(), args.name, choice.value, choice.scope, args.reason);  // value → stdin
    },
  });

  // secret_list, secret_exec, bash override, hooks, commands: see sections above
}
```

The important property of this file is what it does **not** contain: no code path that returns `choice.value` to the model, no logging of `choice`, and the `CaptureView` wipes its buffer on close.

## Compatibility

- Pi ≥ 0.99 (MCP native) and Gentle Shell ≥ 3.7. Degrades to tools-only on older Pi.
- Does not conflict with Gentle Shell's owned tool names (`ask_user_question`, `ask_user_choice`); the bash override is the only built-in it replaces, and it delegates to the original for commands without references.
- Honors `gentle-shell --link` vs isolated home: the extension asks Pi for its paths; nothing is hardcoded.
