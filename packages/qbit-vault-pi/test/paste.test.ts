import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BAD_NAME, LOCKED, NOT_INSTALLED } from "../src/messages.js";
import { cleanupFake, err, mockCtx, mockPi, ok, useFake } from "./helpers.js";

const tempDirs: string[] = [];

afterEach(() => {
	cleanupFake();
	for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A fine-grained GitHub token shape that carries the greppable TESTSECRET_ marker. */
const TOKEN = `github_pat_TESTSECRET_${"aB3dE5gH7jK9mN1pQ3sT5vW7yZ9".repeat(3)}`;
const TOKEN2 = `ghp_${"0123456789abcdefghijklmnopqrstuvwxyz"}`;
const NOTICE_DROPPED = "message not sent: it contained a secret";
const TITLE = "This looks like a GitHub fine-grained token. Store it in QBit Vault?";

function dir(withGit: boolean): string {
	const d = mkdtempSync(join(tmpdir(), "qvpi-repo-"));
	tempDirs.push(d);
	if (withGit) mkdirSync(join(d, ".git"));
	return d;
}

const stored = ok({ ok: true, name: "X", layer: "global" });

function setup(opts: { repo?: boolean; ctx?: Parameters<typeof mockCtx>[0]; responses?: Parameters<typeof useFake>[0] } = {}) {
	const fake = useFake(opts.responses ?? { set: stored });
	const harness = mockPi();
	const { ctx, ui, views } = mockCtx({ cwd: dir(opts.repo ?? false), ...opts.ctx });
	const input = (text: string, source = "interactive", extra: object = {}) =>
		harness.emit("input", { type: "input", text, source, ...extra }, ctx);
	return { fake, harness, ctx, ui, views, input };
}

/** Everything that could carry the value to a person, a log or the model. */
function surfaces(s: ReturnType<typeof setup>): string {
	return JSON.stringify([
		s.ui.notify.mock.calls,
		s.ui.setStatus.mock.calls,
		s.ui.select.mock.calls,
		s.ui.input.mock.calls,
		s.views,
		s.harness.pi.sendMessage.mock.calls,
		s.harness.pi.sendUserMessage.mock.calls,
		s.harness.pi.appendEntry.mock.calls,
		s.fake.calls().map((c) => c.argv),
	]);
}

describe("paste interception: pass through", () => {
	it("registers one input handler", () => {
		useFake({});
		expect(mockPi().handlerCount("input")).toBe(1);
	});

	it("text with no match continues with no prompt and no child process", async () => {
		const s = setup();
		expect(await s.input("deploy the app to staging, please")).toEqual({ action: "continue" });
		expect(s.ui.select).not.toHaveBeenCalled();
		expect(s.ui.notify).not.toHaveBeenCalled();
		expect(s.fake.calls()).toEqual([]);
	});

	it.each(["rpc", "extension"])("a %s input is never scanned", async (source) => {
		const s = setup();
		expect(await s.input(`token ${TOKEN}`, source)).toEqual({ action: "continue" });
		expect(s.ui.select).not.toHaveBeenCalled();
		expect(s.fake.calls()).toEqual([]);
	});
});

describe("paste interception: the question", () => {
	it("outside a repository offers all projects, another name and drop, with the exact texts", async () => {
		const s = setup({ repo: false });
		s.ui.select.mockResolvedValueOnce("Don't store, drop the message");
		await s.input(`here ${TOKEN}`);
		expect(s.ui.select).toHaveBeenCalledTimes(1);
		expect(s.ui.select.mock.calls[0]?.[0]).toBe(TITLE);
		expect(s.ui.select.mock.calls[0]?.[1]).toEqual([
			"Store as GITHUB_TOKEN (all projects)",
			"Store under another name…",
			"Don't store, drop the message",
		]);
	});

	it("inside a repository also offers this project", async () => {
		const s = setup({ repo: true });
		s.ui.select.mockResolvedValueOnce("Don't store, drop the message");
		await s.input(`here ${TOKEN}`);
		expect(s.ui.select.mock.calls[0]?.[1]).toEqual([
			"Store as GITHUB_TOKEN (all projects)",
			"Store as GITHUB_TOKEN (this project)",
			"Store under another name…",
			"Don't store, drop the message",
		]);
	});

	it("a .git in an ancestor of the working directory counts as a repository", async () => {
		const root = dir(true);
		const nested = join(root, "a", "b");
		mkdirSync(nested, { recursive: true });
		const s = setup({ ctx: { cwd: nested } });
		s.ui.select.mockResolvedValueOnce(undefined);
		await s.input(TOKEN);
		expect(s.ui.select.mock.calls[0]?.[1]).toContain("Store as GITHUB_TOKEN (this project)");
	});

	it("uses the readable label of the matched pattern", async () => {
		const s = setup();
		s.ui.select.mockResolvedValueOnce(undefined);
		await s.input(`token ${TOKEN2}`);
		expect(s.ui.select.mock.calls[0]?.[0]).toBe("This looks like a GitHub token. Store it in QBit Vault?");
	});
});

describe("paste interception: store", () => {
	it("all projects: set --global --stdin --json with the value on stdin, text transformed, notice shown", async () => {
		const s = setup({ repo: true });
		s.ui.select.mockResolvedValueOnce("Store as GITHUB_TOKEN (all projects)");
		const result = await s.input(`use ${TOKEN} to push, thanks`);
		expect(result).toEqual({ action: "transform", text: "use secret://GITHUB_TOKEN to push, thanks" });
		expect(s.fake.calls()).toEqual([{ argv: ["set", "GITHUB_TOKEN", "--global", "--stdin", "--json"], stdin: TOKEN }]);
		expect(s.ui.notify).toHaveBeenCalledWith("stored as GITHUB_TOKEN", "info");
		expect(surfaces(s)).not.toContain("TESTSECRET_");
	});

	it("this project: set --project", async () => {
		const s = setup({ repo: true });
		s.ui.select.mockResolvedValueOnce("Store as GITHUB_TOKEN (this project)");
		const result = await s.input(TOKEN);
		expect(result).toEqual({ action: "transform", text: "secret://GITHUB_TOKEN" });
		expect(s.fake.calls()[0]?.argv).toEqual(["set", "GITHUB_TOKEN", "--project", "--stdin", "--json"]);
	});

	it("replaces every occurrence of the value and keeps the rest and the images", async () => {
		const s = setup();
		s.ui.select.mockResolvedValueOnce("Store as GITHUB_TOKEN (all projects)");
		const images = [{ type: "image", data: "AAAA", mimeType: "image/png" }];
		const result = await s.input(`a ${TOKEN}\nb ${TOKEN}, c`, "interactive", { images });
		expect(result).toEqual({ action: "transform", text: "a secret://GITHUB_TOKEN\nb secret://GITHUB_TOKEN, c", images });
		expect(s.ui.select).toHaveBeenCalledTimes(1);
		expect(s.fake.calls()).toHaveLength(1);
	});

	it("another name: asks for it, then stores under it", async () => {
		const s = setup();
		s.ui.select.mockResolvedValueOnce("Store under another name…");
		s.ui.input.mockResolvedValueOnce("MY_PUSH_TOKEN");
		const result = await s.input(`x ${TOKEN}`);
		expect(result).toEqual({ action: "transform", text: "x secret://MY_PUSH_TOKEN" });
		expect(s.fake.calls()[0]).toEqual({ argv: ["set", "MY_PUSH_TOKEN", "--global", "--stdin", "--json"], stdin: TOKEN });
		expect(s.ui.notify).toHaveBeenCalledWith("stored as MY_PUSH_TOKEN", "info");
	});

	it("another name: an invalid name is refused and asked again, without echoing it", async () => {
		const s = setup();
		s.ui.select.mockResolvedValueOnce("Store under another name…");
		s.ui.input.mockResolvedValueOnce("lower_case").mockResolvedValueOnce("9BAD").mockResolvedValueOnce("GOOD_NAME");
		const result = await s.input(TOKEN);
		expect(result).toEqual({ action: "transform", text: "secret://GOOD_NAME" });
		expect(s.ui.input).toHaveBeenCalledTimes(3);
		expect(JSON.stringify(s.ui.input.mock.calls[1])).toContain(BAD_NAME);
		expect(JSON.stringify(s.ui.input.mock.calls)).not.toContain("lower_case");
		expect(s.fake.calls()).toHaveLength(1);
	});

	it("another name: cancelling the name drops the message", async () => {
		const s = setup();
		s.ui.select.mockResolvedValueOnce("Store under another name…");
		s.ui.input.mockResolvedValueOnce(undefined);
		expect(await s.input(TOKEN)).toEqual({ action: "handled" });
		expect(s.ui.notify).toHaveBeenCalledWith(NOTICE_DROPPED, "warning");
		expect(s.fake.calls()).toEqual([]);
	});
});

describe("paste interception: drop and refusal", () => {
	it("Don't store: handled, notice, no child process", async () => {
		const s = setup();
		s.ui.select.mockResolvedValueOnce("Don't store, drop the message");
		expect(await s.input(`x ${TOKEN}`)).toEqual({ action: "handled" });
		expect(s.ui.notify).toHaveBeenCalledWith(NOTICE_DROPPED, "warning");
		expect(s.fake.calls()).toEqual([]);
		expect(surfaces(s)).not.toContain("TESTSECRET_");
	});

	it("closing the question is a drop", async () => {
		const s = setup();
		s.ui.select.mockResolvedValueOnce(undefined);
		expect(await s.input(TOKEN)).toEqual({ action: "handled" });
		expect(s.ui.notify).toHaveBeenCalledWith(NOTICE_DROPPED, "warning");
	});

	it("a refusal shows its one-line message, drops the input, never sends the value", async () => {
		const s = setup({ responses: { set: err("exists", "GITHUB_TOKEN already exists; remove it first") } });
		s.ui.select.mockResolvedValueOnce("Store as GITHUB_TOKEN (all projects)");
		expect(await s.input(`x ${TOKEN}`)).toEqual({ action: "handled" });
		expect(s.ui.notify).toHaveBeenCalledTimes(1);
		expect(s.ui.notify).toHaveBeenCalledWith("GITHUB_TOKEN already exists; remove it first", "error");
		expect(surfaces(s)).not.toContain("TESTSECRET_");
	});

	it("a locked vault shows the unlock hint and drops", async () => {
		const s = setup({ responses: { set: err("vault_locked", "locked") } });
		s.ui.select.mockResolvedValueOnce("Store as GITHUB_TOKEN (all projects)");
		expect(await s.input(TOKEN)).toEqual({ action: "handled" });
		expect(s.ui.notify).toHaveBeenCalledWith(LOCKED, "error");
	});

	it("a missing binary shows the install hint and drops", async () => {
		const s = setup();
		process.env.QBIT_VAULT_BIN = join(tmpdir(), "no-such-qbit-vault-binary");
		s.ui.select.mockResolvedValueOnce("Store as GITHUB_TOKEN (all projects)");
		expect(await s.input(TOKEN)).toEqual({ action: "handled" });
		expect(s.ui.notify).toHaveBeenCalledWith(NOT_INSTALLED, "error");
	});

	it("an error message that echoes the value is replaced by a fixed text", async () => {
		const s = setup({ responses: { set: err("internal", `cannot store ${TOKEN}`) } });
		s.ui.select.mockResolvedValueOnce("Store as GITHUB_TOKEN (all projects)");
		expect(await s.input(TOKEN)).toEqual({ action: "handled" });
		expect(JSON.stringify(s.ui.notify.mock.calls)).not.toContain("TESTSECRET_");
	});
});

describe("paste interception: no UI", () => {
	it.each([
		["hasUI is false", { hasUI: false, mode: "tui" }],
		["the mode is not tui", { hasUI: true, mode: "rpc" }],
	])("%s: never sent, never asked, dropped with the notice", async (_n, ctx) => {
		const s = setup({ ctx });
		expect(await s.input(`x ${TOKEN}`)).toEqual({ action: "handled" });
		expect(s.ui.select).not.toHaveBeenCalled();
		expect(s.ui.notify).toHaveBeenCalledWith(NOTICE_DROPPED, "warning");
		expect(s.fake.calls()).toEqual([]);
	});
});

describe("paste interception: several matches", () => {
	it("handles them in order, one question each", async () => {
		const s = setup();
		s.ui.select
			.mockResolvedValueOnce("Store as GITHUB_TOKEN (all projects)")
			.mockResolvedValueOnce("Store under another name…");
		s.ui.input.mockResolvedValueOnce("OTHER_TOKEN");
		const result = await s.input(`first ${TOKEN} then ${TOKEN2} end`);
		expect(result).toEqual({ action: "transform", text: "first secret://GITHUB_TOKEN then secret://OTHER_TOKEN end" });
		expect(s.ui.select.mock.calls.map((c) => c[0])).toEqual([
			TITLE,
			"This looks like a GitHub token. Store it in QBit Vault?",
		]);
		expect(s.fake.calls().map((c) => [c.argv[1], c.stdin])).toEqual([
			["GITHUB_TOKEN", TOKEN],
			["OTHER_TOKEN", TOKEN2],
		]);
		expect(s.ui.notify.mock.calls.map((c) => c[0])).toEqual(["stored as GITHUB_TOKEN", "stored as OTHER_TOKEN"]);
		expect(surfaces(s)).not.toContain("TESTSECRET_");
		expect(surfaces(s)).not.toContain(TOKEN2);
	});

	it("dropping a later one drops the whole message (the earlier one stays stored)", async () => {
		const s = setup();
		s.ui.select
			.mockResolvedValueOnce("Store as GITHUB_TOKEN (all projects)")
			.mockResolvedValueOnce("Don't store, drop the message");
		expect(await s.input(`${TOKEN} ${TOKEN2}`)).toEqual({ action: "handled" });
		expect(s.fake.calls()).toHaveLength(1);
		expect(s.ui.notify).toHaveBeenLastCalledWith(NOTICE_DROPPED, "warning");
	});
});

describe("paste interception: patterns that cannot be loaded", () => {
	const WARNING = "qbit-vault-pi could not load its secret patterns; pasted secrets are not caught. Reinstall the extension.";

	async function broken() {
		vi.resetModules();
		vi.doMock("../src/patterns.js", async (importOriginal) => ({
			...(await importOriginal<typeof import("../src/patterns.js")>()),
			loadPatterns: () => {
				throw new Error("ENOENT secret-patterns.yaml");
			},
		}));
		const helpers = await import("./helpers.js");
		const fake = helpers.useFake({ grants: helpers.ok({ ok: true, grants: [{ name: "A", layer: "global", scope: "session", session: null }] }) });
		const harness = helpers.mockPi();
		const { ctx, ui } = helpers.mockCtx({ cwd: dir(false) });
		return { fake, harness, ctx, ui };
	}

	afterEach(() => {
		vi.doUnmock("../src/patterns.js");
		vi.resetModules();
	});

	it("keeps messages flowing with no prompt and no child process", async () => {
		const s = await broken();
		const result = await s.harness.emit("input", { type: "input", text: `x ${TOKEN}`, source: "interactive" }, s.ctx);
		expect(result).toEqual({ action: "continue" });
		expect(s.ui.select).not.toHaveBeenCalled();
		expect(s.fake.calls()).toEqual([]);
	});

	it("warns once per session, however many messages follow", async () => {
		const s = await broken();
		for (const text of ["one", "two", `three ${TOKEN}`])
			await s.harness.emit("input", { type: "input", text, source: "interactive" }, s.ctx);
		expect(s.ui.notify.mock.calls).toEqual([[WARNING, "warning"]]);
	});

	it("shows the guard off in the footer next to the vault status", async () => {
		const s = await broken();
		await s.harness.emit("session_start", {}, s.ctx);
		await s.harness.emit("input", { type: "input", text: "hello", source: "interactive" }, s.ctx);
		expect(s.ui.setStatus.mock.calls.at(-1)).toEqual(["qbit-vault", "🔐 1 grant · ⚠ paste guard off"]);
		expect(s.ui.notify.mock.calls).toEqual([[WARNING, "warning"]]);
	});

	it("shows the guard off alone when there is no vault", async () => {
		const s = await broken();
		await s.harness.emit("input", { type: "input", text: "hello", source: "interactive" }, s.ctx);
		expect(s.ui.setStatus.mock.calls.at(-1)).toEqual(["qbit-vault", "⚠ paste guard off"]);
	});

	it("does not warn for input that is not typed by the user", async () => {
		const s = await broken();
		await s.harness.emit("input", { type: "input", text: "x", source: "extension" }, s.ctx);
		expect(s.ui.notify).not.toHaveBeenCalled();
	});
});
