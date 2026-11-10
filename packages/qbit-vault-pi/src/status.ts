import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { LOCKED, NOT_INSTALLED } from "./messages.js";
import { runJson } from "./qbitvault.js";
import { sessionId } from "./session.js";

export const STATUS_KEY = "qbit-vault";
const STATUS_TIMEOUT_MS = 10_000;

export function statusText(grants: number | null): string {
	if (grants === null) return "🔒 locked";
	if (grants === 0) return "🔐 vault";
	return `🔐 ${grants} ${grants === 1 ? "grant" : "grants"}`;
}

export type StatusRefresher = {
	/** Re-reads the grants and updates the footer. `announce` also reports a missing binary or a locked vault, once. */
	refresh(ctx: ExtensionContext, options?: { announce?: boolean }): Promise<void>;
};

export function createStatusRefresher(): StatusRefresher {
	let latest = 0;
	const announced = new Set<"not_installed" | "locked">();

	return {
		async refresh(ctx, options = {}) {
			if (!ctx.hasUI) return;
			const mine = ++latest;
			const outcome = await runJson(["grants"], { timeoutMs: STATUS_TIMEOUT_MS, cwd: ctx.cwd });
			if (mine !== latest) return; // a newer refresh owns the footer

			let text: string | undefined;
			let problem: "not_installed" | "locked" | undefined;
			if (outcome.ok) {
				const list = Array.isArray(outcome.data.grants) ? outcome.data.grants : [];
				const own = sessionId(ctx);
				const count = list.filter((g) => {
					const session = (g as { session?: unknown } | null)?.session;
					return session === null || session === undefined || session === own;
				}).length;
				text = statusText(count);
				announced.delete("locked");
			} else if (outcome.reason === "not_installed") {
				problem = "not_installed";
			} else if (outcome.error?.code === "vault_locked") {
				text = statusText(null);
				problem = "locked";
			}

			try {
				ctx.ui.setStatus(STATUS_KEY, text);
				if (options.announce && problem && !announced.has(problem)) {
					announced.add(problem);
					ctx.ui.notify(problem === "locked" ? LOCKED : NOT_INSTALLED, "warning");
				}
			} catch {
				// The context can be stale after a session switch; the footer is best effort.
			}
		},
	};
}
