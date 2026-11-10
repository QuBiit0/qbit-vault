import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

/** The session id the broker sees: `pi:<Pi session id>`. */
export function sessionId(ctx: Pick<ExtensionContext, "sessionManager">): string {
	return `pi:${ctx.sessionManager.getSessionId()}`;
}
