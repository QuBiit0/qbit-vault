import { afterEach, describe, expect, it, vi } from "vitest";
import { LOCKED, NOT_INSTALLED } from "../src/messages.js";
import { STATUS_KEY, statusText } from "../src/status.js";
import { cleanupFake, err, mockCtx, mockPi, ok, SESSION, useFake } from "./helpers.js";

afterEach(cleanupFake);

const grantsOf = (...sessions: Array<string | null>) =>
	ok({
		ok: true,
		grants: sessions.map((session, i) => ({ name: `N${i}`, layer: "global", scope: "session", session, expires_at: null })),
	});
const statusCalls = (ui: ReturnType<typeof mockCtx>["ui"]) => ui.setStatus.mock.calls;
const flush = () => vi.waitFor(() => undefined, { timeout: 50 }).catch(() => undefined);

describe("S5 status text", () => {
	it("uses the exact footer texts", () => {
		expect(statusText(3)).toBe("🔐 3 grants");
		expect(statusText(1)).toBe("🔐 1 grant");
		expect(statusText(0)).toBe("🔐 vault");
		expect(statusText(null)).toBe("🔒 locked");
		expect(STATUS_KEY).toBe("qbit-vault");
	});
});

describe("S5 refresh on session_start", () => {
	it("shows the number of grants that apply to this session and to the project", async () => {
		const fake = useFake({ grants: grantsOf(SESSION, null, "pi:someone-else") });
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.emit("session_start", { type: "session_start", reason: "startup" }, ctx);
		expect(fake.calls().map((c) => c.argv)).toEqual([["grants", "--json"]]);
		expect(statusCalls(ui)).toEqual([["qbit-vault", "🔐 2 grants"]]);
		expect(ui.notify).not.toHaveBeenCalled();
	});

	it("shows the vault with no grants", async () => {
		useFake({ grants: grantsOf() });
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.emit("session_start", {}, ctx);
		expect(statusCalls(ui)).toEqual([["qbit-vault", "🔐 vault"]]);
	});

	it("shows locked and tells the user the fix once", async () => {
		useFake({ grants: err("vault_locked", "locked", 4) });
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.emit("session_start", {}, ctx);
		await harness.emit("session_start", {}, ctx);
		expect(statusCalls(ui)).toEqual([
			["qbit-vault", "🔒 locked"],
			["qbit-vault", "🔒 locked"],
		]);
		expect(ui.notify.mock.calls).toEqual([[LOCKED, "warning"]]);
	});

	it("shows nothing without a vault and stays quiet", async () => {
		useFake({ grants: err("not_initialized", "no vault here; run 'qbit-vault init'") });
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.emit("session_start", {}, ctx);
		expect(statusCalls(ui)).toEqual([["qbit-vault", undefined]]);
		expect(ui.notify).not.toHaveBeenCalled();
	});

	it("shows nothing without the binary and reports it once", async () => {
		useFake({});
		process.env.QBIT_VAULT_BIN = "qbit-vault-definitely-not-installed";
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.emit("session_start", {}, ctx);
		await harness.emit("session_start", {}, ctx);
		expect(statusCalls(ui)).toEqual([
			["qbit-vault", undefined],
			["qbit-vault", undefined],
		]);
		expect(ui.notify.mock.calls).toEqual([[NOT_INSTALLED, "warning"]]);
	});

	it("does not spawn anything without a UI", async () => {
		const fake = useFake({ grants: grantsOf() });
		const harness = mockPi();
		const { ctx, ui } = mockCtx({ hasUI: false });
		await harness.emit("session_start", {}, ctx);
		expect(fake.calls()).toEqual([]);
		expect(ui.setStatus).not.toHaveBeenCalled();
	});
});

describe("S5 refresh after a command", () => {
	it("refreshes after a /vault command", async () => {
		useFake({ grants: grantsOf(null), revoke: ok({ ok: true, revoked: 1 }) });
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.command().handler("revoke --all", ctx);
		expect(statusCalls(ui)).toEqual([["qbit-vault", "🔐 1 grant"]]);
	});

	it("refreshes even when the command failed", async () => {
		useFake({ grants: grantsOf(), revoke: err("internal", "boom") });
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.command().handler("revoke --all", ctx);
		expect(statusCalls(ui)).toEqual([["qbit-vault", "🔐 vault"]]);
	});
});

describe("S5 refresh after a QBit Vault MCP tool result", () => {
	it.each(["secret_request", "secret_exec", "secret_manage"])("refreshes after %s", async (tool) => {
		useFake({ grants: grantsOf(null, null) });
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.emit("tool_result", { type: "tool_result", toolName: `mcp__qbit_vault__${tool}` }, ctx);
		await vi.waitFor(() => expect(statusCalls(ui)).toEqual([["qbit-vault", "🔐 2 grants"]]));
	});

	it.each(["secret_list", "bash", "read", "mcp__other__secret_requests"])("ignores %s", async (tool) => {
		const fake = useFake({ grants: grantsOf() });
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.emit("tool_result", { type: "tool_result", toolName: tool }, ctx);
		await flush();
		expect(fake.calls()).toEqual([]);
		expect(ui.setStatus).not.toHaveBeenCalled();
	});

	it("does not wait for the refresh before returning", async () => {
		useFake({ grants: grantsOf() }, { FAKE_QV_SLEEP_MS: "300" });
		const harness = mockPi();
		const { ctx } = mockCtx();
		const started = Date.now();
		await harness.emit("tool_result", { toolName: "mcp__qbit_vault__secret_exec" }, ctx);
		expect(Date.now() - started).toBeLessThan(250);
	});
});

describe("S7 session_shutdown", () => {
	it("revokes the grants of this session only", async () => {
		const fake = useFake({ revoke: ok({ ok: true, revoked: 3 }) });
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.emit("session_shutdown", { type: "session_shutdown", reason: "quit" }, ctx);
		expect(fake.calls()).toEqual([{ argv: ["revoke", "--session-only", "--session", SESSION], stdin: "" }]);
		expect(ui.notify).not.toHaveBeenCalled();
	});

	it.each(["new", "resume", "fork"])("also revokes when the session is left by %s", async (reason) => {
		const fake = useFake({ revoke: ok({ ok: true, revoked: 0 }) });
		const harness = mockPi();
		await harness.emit("session_shutdown", { reason }, mockCtx().ctx);
		expect(fake.calls()).toHaveLength(1);
	});

	it("keeps the grants on reload, where the same session goes on", async () => {
		const fake = useFake({ revoke: ok({ ok: true, revoked: 0 }) });
		const harness = mockPi();
		await harness.emit("session_shutdown", { reason: "reload" }, mockCtx().ctx);
		expect(fake.calls()).toEqual([]);
	});

	it("never blocks or throws when the binary is missing", async () => {
		useFake({});
		process.env.QBIT_VAULT_BIN = "qbit-vault-definitely-not-installed";
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await expect(harness.emit("session_shutdown", { reason: "quit" }, ctx)).resolves.toBeUndefined();
		expect(ui.notify).not.toHaveBeenCalled();
	});

	it("never throws when the vault is locked", async () => {
		useFake({ revoke: err("vault_locked", "locked", 4) });
		const harness = mockPi();
		await expect(harness.emit("session_shutdown", { reason: "quit" }, mockCtx().ctx)).resolves.toBeUndefined();
	});

	it("gives up after its timeout", async () => {
		useFake({ revoke: ok({ ok: true }) }, { FAKE_QV_SLEEP_MS: "6000" });
		const harness = mockPi();
		const started = Date.now();
		await harness.emit("session_shutdown", { reason: "quit" }, mockCtx().ctx);
		expect(Date.now() - started).toBeLessThan(5000);
	}, 10_000);
});

describe("structure for T2", () => {
	it("registers only the handlers it needs and leaves input free", () => {
		useFake({});
		const harness = mockPi();
		expect(harness.handlerCount("session_start")).toBe(1);
		expect(harness.handlerCount("tool_result")).toBe(1);
		expect(harness.handlerCount("session_shutdown")).toBe(1);
		expect(harness.handlerCount("input")).toBe(0);
	});
});
