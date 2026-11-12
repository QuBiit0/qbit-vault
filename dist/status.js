import { LOCKED, NOT_INSTALLED } from "./messages.js";
import { runJson } from "./qbitvault.js";
import { sessionId } from "./session.js";
export const STATUS_KEY = "qbit-vault";
const STATUS_TIMEOUT_MS = 10_000;
export function statusText(grants) {
    if (grants === null)
        return "🔒 locked";
    if (grants === 0)
        return "🔐 vault";
    return `🔐 ${grants} ${grants === 1 ? "grant" : "grants"}`;
}
const GUARD_OFF = "⚠ paste guard off";
export const PATTERNS_UNAVAILABLE = "qbit-vault-pi could not load its secret patterns; pasted secrets are not caught. Reinstall the extension.";
export function createStatusRefresher() {
    let latest = 0;
    const announced = new Set();
    let pasteGuardOff = false;
    let guardWarned = false;
    let base; // the vault part of the footer, as of the last refresh
    const compose = () => [base, pasteGuardOff ? GUARD_OFF : undefined].filter(Boolean).join(" · ") || undefined;
    return {
        guardOff(ctx) {
            pasteGuardOff = true;
            if (!ctx.hasUI)
                return;
            try {
                ctx.ui.setStatus(STATUS_KEY, compose());
                if (!guardWarned) {
                    guardWarned = true;
                    ctx.ui.notify(PATTERNS_UNAVAILABLE, "warning");
                }
            }
            catch {
                // A stale context: the guard stays off and the next refresh shows it.
            }
        },
        async refresh(ctx, options = {}) {
            if (!ctx.hasUI)
                return;
            const mine = ++latest;
            // --no-prompt: the footer reads the grants quietly; only a tool or a /vault command may open the unlock dialog.
            const outcome = await runJson(["grants", "--no-prompt"], { timeoutMs: STATUS_TIMEOUT_MS, cwd: ctx.cwd });
            let text;
            let problem;
            if (outcome.ok) {
                const list = Array.isArray(outcome.data.grants) ? outcome.data.grants : [];
                const own = sessionId(ctx);
                const count = list.filter((g) => {
                    const session = g?.session;
                    return session === null || session === undefined || session === own;
                }).length;
                text = statusText(count);
                if (mine === latest)
                    announced.delete("locked");
            }
            else if (outcome.reason === "not_installed") {
                problem = "not_installed";
            }
            else if (outcome.error?.code === "vault_locked") {
                text = statusText(null);
                problem = "locked";
            }
            try {
                // A newer refresh owns the footer, but a one-time announcement is not its to drop.
                if (mine === latest) {
                    base = text;
                    ctx.ui.setStatus(STATUS_KEY, compose());
                }
                if (options.announce && problem && !announced.has(problem)) {
                    announced.add(problem);
                    ctx.ui.notify(problem === "locked" ? LOCKED : NOT_INSTALLED, "warning");
                }
            }
            catch {
                // The context can be stale after a session switch; the footer is best effort.
            }
        },
    };
}
