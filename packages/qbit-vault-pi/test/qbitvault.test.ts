import { afterEach, describe, expect, it } from "vitest";
import { run, runJson } from "../src/qbitvault.js";
import { cleanupFake, err, FIXTURE, ok, useFake } from "./helpers.js";

afterEach(cleanupFake);

describe("spawn wrapper", () => {
	it("passes argv literally (no shell) and the value only over stdin", async () => {
		const fake = useFake({ set: ok({ ok: true }) });
		const result = await run(["set", "A;B", "$HOME", "x y", "--stdin"], { stdin: FIXTURE, timeoutMs: 5000 });
		expect(result.kind).toBe("done");
		const [call] = fake.calls();
		expect(call?.argv).toEqual(["set", "A;B", "$HOME", "x y", "--stdin"]);
		expect(call?.stdin).toBe(FIXTURE);
	});

	it("parses --json output and appends the flag", async () => {
		const fake = useFake({ grants: ok({ ok: true, grants: [] }) });
		const outcome = await runJson(["grants"], { timeoutMs: 5000 });
		expect(outcome).toEqual({ ok: true, data: { ok: true, grants: [] } });
		expect(fake.calls()[0]?.argv).toEqual(["grants", "--json"]);
	});

	it("gives stdin nothing when no value is passed", async () => {
		const fake = useFake({ grants: ok({ ok: true, grants: [] }) });
		await runJson(["grants"], { timeoutMs: 5000 });
		expect(fake.calls()[0]?.stdin).toBe("");
	});

	it("reports a missing binary as a typed not_installed result", async () => {
		process.env.QBIT_VAULT_BIN = "qbit-vault-definitely-not-installed";
		expect(await run(["grants"], { timeoutMs: 5000 })).toEqual({ kind: "not_installed" });
		expect(await runJson(["grants"], { timeoutMs: 5000 })).toEqual({ ok: false, reason: "not_installed" });
	});

	it("turns the CLI's error object into a failed outcome", async () => {
		useFake({ grants: err("vault_locked", "locked", 4) });
		expect(await runJson(["grants"], { timeoutMs: 5000 })).toEqual({
			ok: false,
			reason: "failed",
			error: { code: "vault_locked", message: "locked" },
			code: 4,
		});
	});

	it("accepts a non-zero exit that still carries a report only when asked", async () => {
		useFake({ doctor: { code: 1, stdout: { ok: false, checks: [] } } });
		expect((await runJson(["doctor"], { timeoutMs: 5000 })).ok).toBe(false);
		expect((await runJson(["doctor"], { timeoutMs: 5000, acceptCodes: [1] })).ok).toBe(true);
	});

	it("treats output that is not JSON as a failure without echoing it", async () => {
		useFake({ grants: { code: 0, raw: "not json" } });
		expect(await runJson(["grants"], { timeoutMs: 5000 })).toEqual({ ok: false, reason: "failed", code: 0 });
	});

	it("kills a child that does not answer in time", async () => {
		useFake({ grants: ok({ ok: true }) }, { FAKE_QV_SLEEP_MS: "5000" });
		expect(await run(["grants"], { timeoutMs: 200 })).toEqual({ kind: "timeout" });
	});
});
