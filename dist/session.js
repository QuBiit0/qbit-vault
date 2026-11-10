/** The session id the broker sees: `pi:<Pi session id>`. */
export function sessionId(ctx) {
    return `pi:${ctx.sessionManager.getSessionId()}`;
}
