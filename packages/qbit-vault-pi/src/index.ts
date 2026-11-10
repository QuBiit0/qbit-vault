import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { completeArguments, createVaultHandler } from "./commands.js";
import { createPasteHandler } from "./paste.js";
import { run } from "./qbitvault.js";
import { sessionId } from "./session.js";
import { createStatusRefresher } from "./status.js";

/** MCP tools of the QBit Vault server whose result may change the grants. */
const GRANT_TOOL_SUFFIXES = ["secret_request", "secret_exec", "secret_manage"];
const SHUTDOWN_TIMEOUT_MS = 3_000;

export default function qbitVaultPi(pi: ExtensionAPI): void {
	const status = createStatusRefresher();

	pi.registerCommand("vault", {
		description: "QBit Vault: list, set, rm, revoke, audit, doctor",
		getArgumentCompletions: completeArguments,
		handler: createVaultHandler(status),
	});

	pi.on("session_start", async (_event, ctx) => {
		await status.refresh(ctx, { announce: true });
	});

	pi.on("tool_result", async (event, ctx) => {
		if (!GRANT_TOOL_SUFFIXES.some((suffix) => event.toolName.endsWith(suffix))) return;
		// Fire and forget: the footer must never delay the tool result.
		void status.refresh(ctx).catch(() => {});
	});

	pi.on("session_shutdown", async (event, ctx) => {
		// A reload keeps the same session running, so its grants stay.
		if (event.reason === "reload") return;
		try {
			await run(["revoke", "--session-only", "--session", sessionId(ctx)], {
				timeoutMs: SHUTDOWN_TIMEOUT_MS,
				cwd: ctx.cwd,
			});
		} catch {
			// Best effort: the grant TTL is the backstop.
		}
	});

	// Paste interception: a secret typed into the chat is stored or dropped, never sent (S6).
	pi.on("input", createPasteHandler());
}
