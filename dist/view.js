const MAX_ROWS = 200;
function clip(line, width) {
    return line.length > width ? `${line.slice(0, Math.max(0, width - 1))}…` : line;
}
/**
 * Shows plain lines to the user. A single line, or a UI that cannot host a
 * component, goes through notify; otherwise a small closable view. Nothing here
 * reaches the model: no sendMessage, no session entry.
 */
export async function present(ctx, title, lines, level = "info") {
    if (lines.length <= 1 || ctx.mode !== "tui") {
        ctx.ui.notify(lines.join("\n"), level);
        return;
    }
    const shown = lines.length > MAX_ROWS ? [...lines.slice(0, MAX_ROWS), `… ${lines.length - MAX_ROWS} more`] : lines;
    await ctx.ui.custom((_tui, theme, _keys, done) => ({
        render(width) {
            const rule = "─".repeat(Math.max(1, Math.min(width, 80)));
            return [
                "",
                clip(theme.fg("accent", title), width),
                theme.fg("dim", rule),
                ...shown.map((line) => clip(line, width)),
                theme.fg("dim", rule),
                theme.fg("dim", "Esc, Enter or q to close"),
                "",
            ];
        },
        handleInput(data) {
            if (data === "\u001b" || data === "\r" || data === "\n" || data === "q" || data === "Q")
                done();
        },
        invalidate() { },
    }));
}
