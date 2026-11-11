import { completeArguments, createVaultHandler } from "./commands.js";
import { createGuard } from "./guard.js";
import { createPasteHandler } from "./paste.js";
import { loadPatterns } from "./patterns.js";
import { run } from "./qbitvault.js";
import { sessionId } from "./session.js";
import { createStatusRefresher } from "./status.js";
/**
 * MCP tools of the QBit Vault server whose result may change the grants. `init` registers the server
 * as `qbit-vault`; Pi names its tools `mcp__<server>__<tool>` with the server name's `-` turned into `_`.
 * Another server's `secret_request` is not ours.
 */
const GRANT_TOOL = /^mcp__qbit[-_]vault__(secret_request|secret_exec|secret_manage)$/;
const SHUTDOWN_TIMEOUT_MS = 3_000;
export default function qbitVaultPi(pi) {
    const status = createStatusRefresher();
    pi.registerCommand("vault", {
        description: "QBit Vault: list, set, rm, revoke, audit, doctor",
        getArgumentCompletions: completeArguments,
        handler: createVaultHandler(status),
    });
    pi.on("session_start", async (_event, ctx) => {
        // Show a broken paste guard up front, not only when the first message goes through it.
        try {
            loadPatterns();
        }
        catch {
            status.guardOff(ctx);
        }
        await status.refresh(ctx, { announce: true });
    });
    // Output and write guard (output-guard S6). Registered before the footer handler below, so the check
    // of a result never waits for or depends on the status refresh.
    const guard = createGuard();
    pi.on("tool_result", guard.onToolResult);
    pi.on("tool_call", guard.onToolCall);
    pi.on("tool_result", async (event, ctx) => {
        if (!GRANT_TOOL.test(event.toolName))
            return;
        // Fire and forget: the footer must never delay the tool result.
        void status.refresh(ctx).catch(() => { });
    });
    pi.on("session_shutdown", async (event, ctx) => {
        // A reload keeps the same session running, so its grants stay.
        if (event.reason === "reload")
            return;
        try {
            await run(["revoke", "--session-only", "--session", sessionId(ctx)], {
                timeoutMs: SHUTDOWN_TIMEOUT_MS,
                cwd: ctx.cwd,
            });
        }
        catch {
            // Best effort: the grant TTL is the backstop.
        }
    });
    // Paste interception: a secret typed into the chat is stored or dropped, never sent (S6).
    pi.on("input", createPasteHandler((ctx) => status.guardOff(ctx)));
}
