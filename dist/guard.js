import { run } from "./qbitvault.js";
/**
 * Output and write guard (odd/tasks/output-guard.md S6). The built-in tools' output is redacted for every
 * stored value by `qbit-vault hook post-bash|post-read --host pi`, and a file write or edit that carries
 * one is blocked by `hook pre-write --host pi`. The extension never holds a value beyond one call: the
 * event goes to the binary over stdin only, and what it prints is the only thing shown.
 *
 * Fail mode (S2): no binary means no vault, so everything passes. A binary that is there but cannot
 * answer in time, crashes or answers something unexpected withholds the output / blocks the edit,
 * with a fixed reason; the reason never comes from an error text.
 */
const GUARD_TIMEOUT_MS = 30_000;
// A tool result can carry up to 1 MiB of structuredContent next to the content; the answer holds both.
const MAX_ANSWER_BYTES = 16 * 1024 * 1024;
const SHELL_TOOLS = new Set(["bash", "powershell"]);
const READ_TOOLS = new Set(["read", "grep", "find", "ls"]);
export const withheldText = (reason) => `output withheld: qbit-vault could not check it for secrets (${reason})`;
export const uncheckedEditText = (reason) => `qbit-vault could not check this edit for secrets (${reason})`;
function isRecord(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}
/** Runs one hook and reduces what happened to pass, the parsed answer, or a failure with a fixed reason. */
async function check(sub, event, ctx, timeoutMs) {
    const result = await run(["hook", sub, "--host", "pi"], {
        stdin: JSON.stringify(event),
        timeoutMs,
        cwd: ctx.cwd,
        maxOutputBytes: MAX_ANSWER_BYTES,
    });
    if (result.kind === "not_installed")
        return { kind: "pass" };
    if (result.kind === "timeout")
        return { kind: "failed", reason: "timeout" };
    if (result.kind === "failed_to_start")
        return { kind: "failed", reason: "internal error" };
    if (result.code !== 0 || result.text === undefined)
        return { kind: "failed", reason: "internal error" };
    if (result.text.trim() === "")
        return { kind: "pass" };
    if (!isRecord(result.json))
        return { kind: "failed", reason: "internal error" };
    return { kind: "answer", json: result.json };
}
function specific(json) {
    return isRecord(json.hookSpecificOutput) ? json.hookSpecificOutput : undefined;
}
function isText(block) {
    return block.type === "text" && typeof block.text === "string";
}
/** The text blocks replaced by one block holding `text`, at the place of the first; images stay. */
function withText(content, text) {
    const out = [];
    let placed = false;
    for (const block of content) {
        if (!isText(block)) {
            out.push(block);
        }
        else if (!placed) {
            placed = true;
            out.push({ type: "text", text });
        }
    }
    if (!placed)
        out.unshift({ type: "text", text });
    return out;
}
export function createGuard(options = {}) {
    const timeoutMs = options.timeoutMs ?? GUARD_TIMEOUT_MS;
    // Dropping structuredContent (not returning it) is deliberate: Pi removes it when `content` is replaced,
    // and the copy the binary checked is not kept, so no unredacted copy can reach the model.
    const replaced = (content, text) => ({ content: withText(content, text) });
    async function onToolResult(event, ctx) {
        const sub = SHELL_TOOLS.has(event.toolName) ? "post-bash" : READ_TOOLS.has(event.toolName) ? "post-read" : undefined;
        if (sub === undefined)
            return undefined;
        try {
            const texts = event.content.filter(isText).map((b) => b.text);
            const structured = event.structuredContent;
            if (texts.every((t) => t === "") && structured === undefined)
                return undefined;
            const stdout = texts.join("\n");
            const verdict = await check(sub, {
                hook_event_name: "PostToolUse",
                tool_name: event.toolName,
                cwd: ctx.cwd,
                tool_response: structured === undefined ? { stdout } : { stdout, structuredContent: structured },
            }, ctx, timeoutMs);
            if (verdict.kind === "pass")
                return undefined;
            if (verdict.kind === "failed")
                return replaced(event.content, withheldText(verdict.reason));
            const updated = specific(verdict.json)?.updatedToolOutput;
            if (isRecord(updated) && typeof updated.stdout === "string")
                return replaced(event.content, updated.stdout);
            return replaced(event.content, withheldText("internal error"));
        }
        catch {
            // A handler that throws is skipped by Pi, which would let the output through. The content may be
            // what threw, so the replacement does not read it.
            return { content: [{ type: "text", text: withheldText("internal error") }] };
        }
    }
    async function onToolCall(event, ctx) {
        const block = (reason) => ({ block: true, reason });
        try {
            const edited = writtenStrings(event);
            if (edited === undefined || edited.every((s) => s === ""))
                return undefined;
            const verdict = await check("pre-write", {
                hook_event_name: "PreToolUse",
                tool_name: event.toolName,
                cwd: ctx.cwd,
                tool_input: event.toolName === "write" ? { content: edited[0] } : { edits: edited.map((newText) => ({ newText })) },
            }, ctx, timeoutMs);
            if (verdict.kind === "pass")
                return undefined;
            if (verdict.kind === "failed")
                return block(uncheckedEditText(verdict.reason));
            const out = specific(verdict.json);
            if (out?.permissionDecision === "deny" && typeof out.permissionDecisionReason === "string") {
                return block(out.permissionDecisionReason);
            }
            return block(uncheckedEditText("internal error"));
        }
        catch {
            return block(uncheckedEditText("internal error"));
        }
    }
    return { onToolResult, onToolCall };
}
/** What a write or edit would put in a file: [content] or every edit's newText. Other tools: undefined. */
function writtenStrings(event) {
    const input = event.input;
    if (!isRecord(input))
        return undefined;
    if (event.toolName === "write")
        return typeof input.content === "string" ? [input.content] : undefined;
    if (event.toolName === "edit" && Array.isArray(input.edits)) {
        return input.edits.flatMap((e) => (isRecord(e) && typeof e.newText === "string" ? [e.newText] : []));
    }
    return undefined;
}
