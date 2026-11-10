import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { completeArguments } from "../src/commands.js";
import { BAD_NAME, LOCKED, NOT_INITIALIZED, NOT_INSTALLED, USAGE } from "../src/messages.js";
import { cleanupFake, err, everythingShown, FIXTURE, mockCtx, mockPi, ok, useFake } from "./helpers.js";

afterEach(cleanupFake);

const emptyGrants = ok({ ok: true, grants: [] });

async function runVault(args: string, canned: Parameters<typeof useFake>[0], ctxOptions = {}) {
	const fake = useFake({ grants: emptyGrants, ...canned });
	const harness = mockPi();
	const { ctx, ui, views } = mockCtx(ctxOptions);
	await harness.command().handler(args, ctx);
	return { fake, harness, ctx, ui, views };
}

const notices = (ui: ReturnType<typeof mockCtx>["ui"]) => ui.notify.mock.calls;

describe("S4 registration", () => {
	it("registers /vault with a description and argument completion", () => {
		useFake({});
		const command = mockPi().command();
		expect(command.description).toBe("QBit Vault: list, set, rm, revoke, audit, doctor");
		expect(typeof command.getArgumentCompletions).toBe("function");
	});

	it("completes subcommands, layers and flags", () => {
		expect(completeArguments("")?.map((i) => i.value)).toEqual(["list", "set", "rm", "revoke", "audit", "doctor"]);
		expect(completeArguments("re")?.map((i) => i.value)).toEqual(["revoke"]);
		expect(completeArguments("list ")?.map((i) => i.value)).toEqual(["list global", "list project", "list all"]);
		expect(completeArguments("list p")?.map((i) => i.value)).toEqual(["list project"]);
		expect(completeArguments("revoke ")?.map((i) => i.value)).toEqual(["revoke --all"]);
		expect(completeArguments("audit ")?.map((i) => i.value)).toEqual(["audit --tail "]);
		expect(completeArguments("set TOKEN ")?.map((i) => i.value)).toEqual(["set TOKEN global", "set TOKEN project"]);
		expect(completeArguments("nope")).toBeNull();
	});
});

describe("S4 usage notice", () => {
	it.each([
		["", "no subcommand"],
		["   ", "blank"],
		["frobnicate", "unknown subcommand"],
		["set", "set without NAME"],
		["rm", "rm without NAME"],
		["revoke", "revoke without target"],
		["list sideways", "bad layer"],
		["list global extra", "extra argument"],
		["set TOKEN galaxy", "bad layer on set"],
		["rm TOKEN global more", "extra argument on rm"],
		["revoke --nope", "unknown revoke flag"],
		["revoke A B", "two revoke targets"],
		["audit --tail", "tail without number"],
		["audit --tail abc", "tail not a number"],
		["audit --tail 0", "tail zero"],
		["audit --tail 1001", "tail too large"],
		["audit --since 1h", "unsupported audit flag"],
		["doctor now", "doctor with argument"],
	])("shows one usage line and runs nothing: %s (%s)", async (args) => {
		const { fake, ui } = await runVault(args, {});
		expect(notices(ui)).toEqual([[USAGE, "info"]]);
		expect(fake.calls()).toEqual([]);
		expect(ui.setStatus).not.toHaveBeenCalled();
	});
});

describe("S4 /vault list", () => {
	const secrets = {
		ok: true,
		project: null,
		secrets: [
			{ name: "GITHUB_TOKEN", layer: "global", description: "GitHub CLI", overrides_global: false },
			{ name: "DB_URL", layer: "project", project_label: "shop", description: "dev database", overrides_global: true },
			{ name: "BARE", layer: "global", description: "" },
		],
	};
	const grants = {
		ok: true,
		grants: [
			{ name: "GITHUB_TOKEN", layer: "global", scope: "session", session: "pi:x", expires_at: "t", remaining: "29m30s" },
			{ name: "DB_URL", layer: "project", scope: "project", session: null, expires_at: null, remaining: null },
		],
	};

	it("shows names, layers, descriptions and grants in a view", async () => {
		const { fake, views, ui } = await runVault("list", { list: ok(secrets), grants: ok(grants) });
		expect(fake.calls().map((c) => c.argv)).toEqual([["list", "--json"], ["grants", "--json"], ["grants", "--json"]]);
		expect(views).toEqual([
			{
				title: "QBit Vault: secrets",
				lines: [
					"NAME          LAYER         DESCRIPTION / GRANTS",
					"GITHUB_TOKEN  global        GitHub CLI  [session 29m30s]",
					"DB_URL        project:shop  dev database (overrides global)  [project]",
					"BARE          global        -",
				],
			},
		]);
		expect(notices(ui)).toEqual([]);
	});

	it.each(["global", "project", "all"])("passes the %s layer to the CLI", async (layer) => {
		const { fake } = await runVault(`list ${layer}`, { list: ok(secrets) });
		expect(fake.calls()[0]?.argv).toEqual(["list", "--layer", layer, "--json"]);
	});

	it("says so when there are no secrets", async () => {
		const { ui, views } = await runVault("list", { list: ok({ ok: true, project: null, secrets: [] }) });
		expect(notices(ui)).toEqual([["no secrets", "info"]]);
		expect(views).toEqual([]);
	});

	it("still lists when grants cannot be read", async () => {
		const { views } = await runVault("list", { list: ok(secrets), grants: err("internal", "boom") });
		expect(views[0]?.lines[1]).toBe("GITHUB_TOKEN  global        GitHub CLI");
	});

	it("falls back to a notice outside the TUI", async () => {
		const { ui, views } = await runVault("list", { list: ok(secrets), grants: ok(grants) }, { mode: "rpc" });
		expect(views).toEqual([]);
		expect(notices(ui)[0]?.[0]).toContain("GITHUB_TOKEN  global");
	});

	it("reports a locked vault with the fix", async () => {
		const { ui } = await runVault("list", { list: err("vault_locked", "x", 4), grants: err("vault_locked", "x", 4) });
		expect(notices(ui)).toEqual([[LOCKED, "error"]]);
	});

	it("reports a missing vault with the fix", async () => {
		const { ui } = await runVault("list", { list: err("not_initialized", "x"), grants: err("not_initialized", "x") });
		expect(notices(ui)).toEqual([[NOT_INITIALIZED, "error"]]);
	});

	it("reports a missing binary with the fix", async () => {
		useFake({});
		process.env.QBIT_VAULT_BIN = join(tmpdir(), "qbit-vault-definitely-not-installed");
		const harness = mockPi();
		const { ctx, ui } = mockCtx();
		await harness.command().handler("list", ctx);
		expect(notices(ui)).toEqual([[NOT_INSTALLED, "error"]]);
	});
});

describe("S4 /vault set and rm", () => {
	it("runs set with the layer flag and no value on the command line or stdin", async () => {
		const { fake, ui } = await runVault("set GITHUB_TOKEN global", {
			set: ok({ ok: true, name: "GITHUB_TOKEN", layer: "global", project: null, replaced: false }),
		});
		expect(fake.calls()[0]).toEqual({ argv: ["set", "GITHUB_TOKEN", "--global", "--json"], stdin: "" });
		expect(notices(ui)).toEqual([["stored GITHUB_TOKEN (global)", "info"]]);
	});

	it("leaves the layer to the CLI when none is given, and says replaced", async () => {
		const { fake, ui } = await runVault("set DB_URL", {
			set: ok({ ok: true, name: "DB_URL", layer: "project", project: {}, replaced: true }),
		});
		expect(fake.calls()[0]?.argv).toEqual(["set", "DB_URL", "--json"]);
		expect(notices(ui)).toEqual([["replaced DB_URL (project)", "info"]]);
	});

	it("shows a cancelled dialog as a warning", async () => {
		const { ui } = await runVault("set DB_URL project", { set: err("cancelled", "cancelled") });
		expect(notices(ui)).toEqual([["cancelled", "warning"]]);
	});

	it("shows a refusal with the CLI's own message", async () => {
		const { ui } = await runVault("set DB_URL project", { set: err("no_project", "not inside a project", 3) });
		expect(notices(ui)).toEqual([["not inside a project", "error"]]);
	});

	it("runs rm with the layer flag", async () => {
		const { fake, ui } = await runVault("rm DB_URL project", {
			rm: ok({ ok: true, name: "DB_URL", layer: "project", removed: true }),
		});
		expect(fake.calls()[0]?.argv).toEqual(["rm", "DB_URL", "--project", "--json"]);
		expect(notices(ui)).toEqual([["removed DB_URL (project)", "info"]]);
	});

	it("never passes a value-shaped name to the binary and never echoes it", async () => {
		for (const sub of ["set", "rm", "revoke"]) {
			const { fake, ui, views } = await runVault(`${sub} ${FIXTURE}`, {});
			expect(fake.calls()).toEqual([]);
			expect(notices(ui)).toEqual([[BAD_NAME, "error"]]);
			expect(everythingShown(ui, views)).not.toContain("TESTSECRET");
			cleanupFake();
		}
	});
});

describe("S4 /vault revoke", () => {
	it("revokes one name", async () => {
		const { fake, ui } = await runVault("revoke GITHUB_TOKEN", { revoke: ok({ ok: true, revoked: 2 }) });
		expect(fake.calls()[0]?.argv).toEqual(["revoke", "GITHUB_TOKEN", "--json"]);
		expect(notices(ui)).toEqual([["revoked 2 grants", "info"]]);
	});

	it("revokes everything and uses the singular for one", async () => {
		const { fake, ui } = await runVault("revoke --all", { revoke: ok({ ok: true, revoked: 1 }) });
		expect(fake.calls()[0]?.argv).toEqual(["revoke", "--all", "--json"]);
		expect(notices(ui)).toEqual([["revoked 1 grant", "info"]]);
	});
});

describe("S4 /vault audit", () => {
	const records = {
		ok: true,
		records: [
			{ ts: "2026-11-10T10:00:00Z", event: "grant", session: "pi:a", names: ["A", "B"], layer: "global", command: "SHOULD NOT SHOW" },
			{ ts: "2026-11-10T10:01:00Z", event: "exec", session: "", names: ["A"], layer: "project", exit_code: 2 },
		],
	};

	it("defaults to the last 20 records and renders one line each", async () => {
		const { fake, views } = await runVault("audit", { audit: ok(records) });
		expect(fake.calls()[0]?.argv).toEqual(["audit", "--tail", "20", "--json"]);
		expect(views).toEqual([
			{
				title: "QBit Vault: audit",
				lines: [
					"2026-11-10T10:00:00Z grant A,B global pi:a",
					"2026-11-10T10:01:00Z exec A project - exit=2",
				],
			},
		]);
	});

	it("honours --tail N", async () => {
		const { fake } = await runVault("audit --tail 5", { audit: ok(records) });
		expect(fake.calls()[0]?.argv).toEqual(["audit", "--tail", "5", "--json"]);
	});

	it("says so when the log is empty", async () => {
		const { ui } = await runVault("audit", { audit: ok({ ok: true, records: [] }) });
		expect(notices(ui)).toEqual([["no audit records", "info"]]);
	});
});

describe("S4 /vault doctor", () => {
	it("shows a healthy report in a view", async () => {
		const { fake, views, ui } = await runVault("doctor", {
			doctor: ok({
				ok: true,
				checks: [
					{ name: "vault", status: "ok", detail: "unlocked (keychain: os)" },
					{ name: "permissions", status: "ok", detail: "owner-only" },
				],
			}),
		});
		expect(fake.calls()[0]?.argv).toEqual(["doctor", "--json"]);
		expect(views).toEqual([
			{
				title: "QBit Vault: doctor",
				lines: ["ok    vault        unlocked (keychain: os)", "ok    permissions  owner-only", "healthy"],
			},
		]);
		expect(notices(ui)).toEqual([]);
	});

	it("counts problems and still shows a report when doctor exits 1", async () => {
		const { views } = await runVault("doctor", {
			doctor: {
				code: 1,
				stdout: {
					ok: false,
					checks: [
						{ name: "vault", status: "fail", detail: "no vault here; run 'qbit-vault init'" },
						{ name: "sync", status: "warn", detail: "push pending" },
					],
				},
			},
		});
		expect(views[0]?.lines).toEqual([
			"fail  vault  no vault here; run 'qbit-vault init'",
			"warn  sync   push pending",
			"2 problems",
		]);
	});
});

describe("S8 nothing reaches the model", () => {
	it("never calls sendMessage, sendUserMessage or appendEntry, and never puts a value in argv", async () => {
		const fake = useFake({
			grants: emptyGrants,
			list: ok({ ok: true, secrets: [{ name: "A", layer: "global", description: "d" }] }),
			set: ok({ ok: true, name: "A", layer: "global", replaced: false }),
			rm: ok({ ok: true, name: "A", layer: "global", removed: true }),
			revoke: ok({ ok: true, revoked: 0 }),
			audit: ok({ ok: true, records: [{ ts: "t", event: "grant", session: "pi:a" }] }),
			doctor: ok({ ok: true, checks: [{ name: "vault", status: "ok", detail: "d" }] }),
		});
		const harness = mockPi();
		const { ctx, ui, views } = mockCtx();
		for (const args of ["list", "set A global", "rm A global", "revoke --all", "audit", "doctor", "list", `set ${FIXTURE}`, "bogus"]) {
			await harness.command().handler(args, ctx);
		}
		await harness.emit("session_start", { type: "session_start" }, ctx);
		await harness.emit("session_shutdown", { type: "session_shutdown", reason: "quit" }, ctx);

		expect(harness.pi.sendMessage).not.toHaveBeenCalled();
		expect(harness.pi.sendUserMessage).not.toHaveBeenCalled();
		expect(harness.pi.appendEntry).not.toHaveBeenCalled();
		expect(JSON.stringify(fake.calls())).not.toContain("TESTSECRET");
		expect(everythingShown(ui, views)).not.toContain("TESTSECRET");
	});
});
