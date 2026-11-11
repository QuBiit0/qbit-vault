import { spawn } from "node:child_process";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createGuard } from "../src/guard.js";
import { cleanupFake, everythingShown, FIXTURE, mockCtx, mockPi, ok, useFake } from "./helpers.js";

// A pass-through spy: "not spawned" is checked right after the handler returns.
vi.mock("node:child_process", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:child_process")>();
	return { ...actual, spawn: vi.fn(actual.spawn) };
});

afterEach(() => {
	cleanupFake();
	vi.mocked(spawn).mockClear();
});

const REDACT = { hook: { mode: "redact" as const } };
const none = { hook: { raw: "" } };
const withheld = (reason: string) => `output withheld: qbit-vault could not check it for secrets (${reason})`;
const unchecked = (reason: string) => `qbit-vault could not check this edit for secrets (${reason})`;
const DENY =
	"This edit would write the value of the stored secret API_KEY to a file, so qbit-vault blocked it. Give the value to the command that needs it with secret_exec instead.";
const text = (t: string) => ({ type: "text", text: t });
const image = { type: "image", data: "aGk=", mimeType: "image/png" };

function resultEvent(toolName: string, content: unknown[], extra: Record<string, unknown> = {}) {
	return { type: "tool_result", toolCallId: "c1", toolName, input: {}, content, isError: false, ...extra };
}
const callEvent = (toolName: string, input: unknown) => ({ type: "tool_call", toolCallId: "c1", toolName, input });

describe("S6 tool_result guard: which tools and which subcommand", () => {
	it.each([
		["bash", "post-bash"],
		["powershell", "post-bash"],
		["read", "post-read"],
		["grep", "post-read"],
		["find", "post-read"],
		["ls", "post-read"],
	])("%s is checked with hook %s --host pi", async (tool, sub) => {
		const fake = useFake(REDACT);
		const pi = mockPi();
		const { ctx } = mockCtx();
		await pi.emit("tool_result", resultEvent(tool, [text(`k=${FIXTURE}`)]), ctx);
		const calls = fake.calls();
		expect(calls).toHaveLength(1);
		expect(calls[0]!.argv).toEqual(["hook", sub, "--host", "pi"]);
	});

	it.each(["edit", "write", "mcp__other__thing", "custom"])("%s is not checked", async (tool) => {
		const fake = useFake(REDACT);
		const pi = mockPi();
		const { ctx } = mockCtx();
		expect(await pi.emit("tool_result", resultEvent(tool, [text(`k=${FIXTURE}`)]), ctx)).toBeUndefined();
		expect(fake.calls()).toEqual([]);
		expect(vi.mocked(spawn)).not.toHaveBeenCalled();
	});

	it("does not spawn for a result with nothing to check", async () => {
		useFake(REDACT);
		const pi = mockPi();
		const { ctx } = mockCtx();
		expect(await pi.emit("tool_result", resultEvent("bash", [image]), ctx)).toBeUndefined();
		expect(await pi.emit("tool_result", resultEvent("bash", [text("")]), ctx)).toBeUndefined();
		expect(vi.mocked(spawn)).not.toHaveBeenCalled();
	});
});

describe("S6 tool_result guard: the answer", () => {
	it("replaces the text with the redacted text, keeps images, drops structuredContent, value only on stdin", async () => {
		const fake = useFake(REDACT);
		const pi = mockPi();
		const { ctx, ui, views } = mockCtx();
		const result = await pi.emit(
			"tool_result",
			resultEvent("bash", [text(`k=${FIXTURE}\n`), image], {
				structuredContent: { output: `k=${FIXTURE}\n`, exit_code: 0 },
			}),
			ctx,
		);
		expect(result).toEqual({ content: [text("k=[REDACTED:API_KEY]\n"), image] });
		expect("structuredContent" in result).toBe(false);

		const [call] = fake.calls();
		expect(call!.argv.join(" ")).not.toContain(FIXTURE);
		const sent = JSON.parse(call!.stdin);
		expect(sent).toMatchObject({ hook_event_name: "PostToolUse", tool_name: "bash", cwd: ctx.cwd });
		expect(call!.stdin).toContain(FIXTURE); // the value goes over stdin, nowhere else

		expect(JSON.stringify(result)).not.toContain(FIXTURE);
		expect(everythingShown(ui, views)).not.toContain(FIXTURE);
		expect(pi.pi.sendMessage).not.toHaveBeenCalled();
		expect(pi.pi.sendUserMessage).not.toHaveBeenCalled();
		expect(pi.pi.appendEntry).not.toHaveBeenCalled();
	});

	it("redacts a value that is only in structuredContent and still drops that copy", async () => {
		useFake(REDACT);
		const pi = mockPi();
		const { ctx } = mockCtx();
		const result = await pi.emit(
			"tool_result",
			resultEvent("bash", [text("tail only")], { structuredContent: { output: `head ${FIXTURE}` } }),
			ctx,
		);
		expect(result).toEqual({ content: [text("tail only")] });
		expect(JSON.stringify(result)).not.toContain(FIXTURE);
	});

	it("leaves a clean result unchanged", async () => {
		useFake(none);
		const pi = mockPi();
		const { ctx } = mockCtx();
		expect(await pi.emit("tool_result", resultEvent("grep", [text("all good")], { structuredContent: { a: 1 } }), ctx)).toBeUndefined();
	});

	it("passes when qbit-vault is not installed", async () => {
		useFake(REDACT);
		process.env.QBIT_VAULT_BIN = process.platform === "win32" ? "C:\\no\\such\\qbit-vault.exe" : "/no/such/qbit-vault";
		const pi = mockPi();
		const { ctx } = mockCtx();
		expect(await pi.emit("tool_result", resultEvent("bash", [text(`k=${FIXTURE}`)]), ctx)).toBeUndefined();
	});

	it("shows the withheld text the binary answers (locked vault) and drops structuredContent", async () => {
		const answer = {
			hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: { stdout: withheld("vault locked"), structuredContent: { output: "" } } },
		};
		useFake({ hook: { stdout: answer } });
		const pi = mockPi();
		const { ctx } = mockCtx();
		const result = await pi.emit(
			"tool_result",
			resultEvent("bash", [text(`k=${FIXTURE}`), text("more")], { structuredContent: { output: FIXTURE } }),
			ctx,
		);
		expect(result).toEqual({ content: [text(withheld("vault locked"))] });
	});

	it.each([
		["a crash with no output", { hook: { code: 3, raw: "" } }, "internal error"],
		["output that is not JSON", { hook: { raw: `oops ${FIXTURE}` } }, "internal error"],
		["JSON with no updated output (the binary's own fail-open warning)", { hook: { stdout: { systemMessage: "qbit-vault hook failed" } } }, "internal error"],
		["an updated output of another shape", { hook: { stdout: { hookSpecificOutput: { updatedToolOutput: 7 } } } }, "internal error"],
	])("withholds on %s", async (_name, responses, reason) => {
		useFake(responses);
		const pi = mockPi();
		const { ctx, ui, views } = mockCtx();
		const result = await pi.emit("tool_result", resultEvent("read", [text(`k=${FIXTURE}`), image], { structuredContent: { output: FIXTURE } }), ctx);
		expect(result).toEqual({ content: [text(withheld(reason)), image] });
		expect(JSON.stringify(result)).not.toContain(FIXTURE);
		expect(everythingShown(ui, views)).not.toContain(FIXTURE);
	});

	it("withholds with the reason timeout when the binary does not answer in time", async () => {
		useFake(REDACT, { FAKE_QV_SLEEP_MS: "5000" });
		const guard = createGuard({ timeoutMs: 200 });
		const { ctx } = mockCtx();
		const result = await guard.onToolResult(resultEvent("bash", [text(`k=${FIXTURE}`)]) as any, ctx as any);
		expect(result).toEqual({ content: [text(withheld("timeout"))] });
	});

	it("never lets a failure inside the guard pass the output through", async () => {
		useFake(REDACT);
		const guard = createGuard();
		const { ctx } = mockCtx();
		const broken = { ...resultEvent("bash", [text(`k=${FIXTURE}`)]), get structuredContent(): never { throw new Error(FIXTURE); } };
		const result = await guard.onToolResult(broken as any, ctx as any);
		expect(result).toEqual({ content: [text(withheld("internal error"))] });
	});
});

describe("S6 the footer status handler keeps working next to the guard", () => {
	it("guards first, and a grant tool result still refreshes the status", async () => {
		const fake = useFake({ ...REDACT, grants: ok({ ok: true, grants: [] }) });
		const pi = mockPi();
		const { ctx, ui } = mockCtx();
		const guarded = await pi.emit("tool_result", resultEvent("bash", [text(`k=${FIXTURE}`)]), ctx);
		expect(guarded).toEqual({ content: [text("k=[REDACTED:API_KEY]")] });
		expect(fake.calls().map((c) => c.argv[0])).toEqual(["hook"]); // no status refresh for bash

		const grant = await pi.emit("tool_result", resultEvent("mcp__qbit_vault__secret_exec", [text("done")]), ctx);
		expect(grant).toBeUndefined();
		await vi.waitFor(() => expect(ui.setStatus).toHaveBeenCalled());
		expect(fake.calls().map((c) => c.argv[0])).toEqual(["hook", "grants"]);
	});
});

describe("S6 tool_call write guard", () => {
	it("blocks a write whose content carries a stored value, with the binary's exact reason", async () => {
		const fake = useFake(REDACT);
		const pi = mockPi();
		const { ctx, ui, views } = mockCtx();
		const result = await pi.emit("tool_call", callEvent("write", { path: "a.env", content: `K=${FIXTURE}` }), ctx);
		expect(result).toEqual({ block: true, reason: DENY });
		const [call] = fake.calls();
		expect(call!.argv).toEqual(["hook", "pre-write", "--host", "pi"]);
		expect(call!.argv.join(" ")).not.toContain(FIXTURE);
		expect(JSON.parse(call!.stdin)).toMatchObject({ hook_event_name: "PreToolUse", tool_name: "write", tool_input: { content: `K=${FIXTURE}` }, cwd: ctx.cwd });
		expect(JSON.stringify(result)).not.toContain(FIXTURE);
		expect(everythingShown(ui, views)).not.toContain(FIXTURE);
		expect(pi.pi.sendMessage).not.toHaveBeenCalled();
	});

	it("blocks an edit when any newText carries a value, and sends only the newTexts", async () => {
		const fake = useFake(REDACT);
		const pi = mockPi();
		const { ctx } = mockCtx();
		const input = {
			path: "a.txt",
			edits: [
				{ oldText: "OLD_ONE", newText: "fine" },
				{ oldText: "OLD_TWO", newText: `x ${FIXTURE}` },
			],
		};
		expect(await pi.emit("tool_call", callEvent("edit", input), ctx)).toEqual({ block: true, reason: DENY });
		const [call] = fake.calls();
		expect(JSON.parse(call!.stdin).tool_input).toEqual({ path: "a.txt", edits: [{ newText: "fine" }, { newText: `x ${FIXTURE}` }] });
		expect(call!.stdin).not.toContain("OLD_");
	});

	it("allows a clean write and edit", async () => {
		useFake(none);
		const pi = mockPi();
		const { ctx } = mockCtx();
		expect(await pi.emit("tool_call", callEvent("write", { path: "a", content: "hello" }), ctx)).toBeUndefined();
		expect(await pi.emit("tool_call", callEvent("edit", { path: "a", edits: [{ oldText: "a", newText: "b" }] }), ctx)).toBeUndefined();
	});

	it("allows when qbit-vault is not installed", async () => {
		useFake(REDACT);
		process.env.QBIT_VAULT_BIN = process.platform === "win32" ? "C:\\no\\such\\qbit-vault.exe" : "/no/such/qbit-vault";
		const pi = mockPi();
		const { ctx } = mockCtx();
		expect(await pi.emit("tool_call", callEvent("write", { path: "a", content: FIXTURE }), ctx)).toBeUndefined();
	});

	it("does not spawn for other tools, an empty write or a malformed input", async () => {
		useFake(REDACT);
		const pi = mockPi();
		const { ctx } = mockCtx();
		expect(await pi.emit("tool_call", callEvent("bash", { command: `echo ${FIXTURE}` }), ctx)).toBeUndefined();
		expect(await pi.emit("tool_call", callEvent("read", { path: "a" }), ctx)).toBeUndefined();
		expect(await pi.emit("tool_call", callEvent("write", { content: "" }), ctx)).toBeUndefined();
		expect(await pi.emit("tool_call", callEvent("edit", { edits: [] }), ctx)).toBeUndefined();
		expect(vi.mocked(spawn)).not.toHaveBeenCalled();
	});

	it("checks the file name too, so an empty write to a file named by a value is blocked", async () => {
		const fake = useFake(REDACT);
		const pi = mockPi();
		const { ctx } = mockCtx();
		const input = { path: `dir/${FIXTURE}.txt`, content: "" };
		expect(await pi.emit("tool_call", callEvent("write", input), ctx)).toEqual({ block: true, reason: DENY });
		const [call] = fake.calls();
		expect(JSON.parse(call!.stdin).tool_input).toEqual(input);
		expect(call!.argv.join(" ")).not.toContain(FIXTURE);
	});

	it.each([
		["a crash with no output", { hook: { code: 3, raw: "" } }],
		["output that is not JSON", { hook: { raw: "nope" } }],
		["JSON that is neither a deny nor empty", { hook: { stdout: { systemMessage: "qbit-vault hook failed" } } }],
	])("blocks on %s", async (_name, responses) => {
		useFake(responses);
		const pi = mockPi();
		const { ctx } = mockCtx();
		expect(await pi.emit("tool_call", callEvent("write", { path: "a", content: FIXTURE }), ctx)).toEqual({
			block: true,
			reason: unchecked("internal error"),
		});
	});

	it("blocks with the reason timeout when the binary does not answer in time", async () => {
		useFake(REDACT, { FAKE_QV_SLEEP_MS: "5000" });
		const guard = createGuard({ timeoutMs: 200 });
		const { ctx } = mockCtx();
		const result = await guard.onToolCall(callEvent("write", { path: "a", content: FIXTURE }) as any, ctx as any);
		expect(result).toEqual({ block: true, reason: unchecked("timeout") });
	});
});

// The binary cannot be started, exits non-zero or answers more than the cap: the guard fails closed with
// the fixed reason, never with the answer, and never with what the failing process printed.
describe("S10.6 the guard's failure branches", () => {
	const OVER_CAP = String(16 * 1024 * 1024 + 1);
	const redactAnswer = {
		hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: { stdout: "k=[REDACTED:API_KEY]" } },
	};
	const denyAnswer = {
		hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: DENY },
	};

	it("withholds the output when the binary cannot be started (a relative QBIT_VAULT_BIN)", async () => {
		useFake(REDACT);
		process.env.QBIT_VAULT_BIN = "./qbit-vault";
		const pi = mockPi();
		const { ctx } = mockCtx();
		const result = await pi.emit("tool_result", resultEvent("bash", [text(`k=${FIXTURE}`)]), ctx);
		expect(result).toEqual({ content: [text(withheld("internal error"))] });
		expect(vi.mocked(spawn)).not.toHaveBeenCalled();
	});

	it("blocks the edit when the binary cannot be started", async () => {
		useFake(REDACT);
		process.env.QBIT_VAULT_BIN = "./qbit-vault";
		const pi = mockPi();
		const { ctx } = mockCtx();
		const result = await pi.emit("tool_call", callEvent("write", { path: "a", content: FIXTURE }), ctx);
		expect(result).toEqual({ block: true, reason: unchecked("internal error") });
		expect(vi.mocked(spawn)).not.toHaveBeenCalled();
	});

	it("withholds the output on a non-zero exit even when stdout holds a valid answer", async () => {
		useFake({ hook: { code: 1, stdout: redactAnswer } });
		const pi = mockPi();
		const { ctx } = mockCtx();
		const result = await pi.emit("tool_result", resultEvent("bash", [text(`k=${FIXTURE}`)]), ctx);
		expect(result).toEqual({ content: [text(withheld("internal error"))] });
	});

	it("blocks the edit on a non-zero exit even when stdout holds a deny", async () => {
		useFake({ hook: { code: 1, stdout: denyAnswer } });
		const pi = mockPi();
		const { ctx } = mockCtx();
		const result = await pi.emit("tool_call", callEvent("write", { path: "a", content: FIXTURE }), ctx);
		expect(result).toEqual({ block: true, reason: unchecked("internal error") });
	});

	it("withholds the output when the answer is longer than the cap", async () => {
		useFake(REDACT, { FAKE_QV_FLOOD_BYTES: OVER_CAP });
		const pi = mockPi();
		const { ctx } = mockCtx();
		const result = await pi.emit("tool_result", resultEvent("bash", [text(`k=${FIXTURE}`)]), ctx);
		expect(result).toEqual({ content: [text(withheld("internal error"))] });
	});

	it("blocks the edit when the answer is longer than the cap", async () => {
		useFake(REDACT, { FAKE_QV_FLOOD_BYTES: OVER_CAP });
		const pi = mockPi();
		const { ctx } = mockCtx();
		const result = await pi.emit("tool_call", callEvent("write", { path: "a", content: FIXTURE }), ctx);
		expect(result).toEqual({ block: true, reason: unchecked("internal error") });
	});
});
