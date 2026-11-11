import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveBinary, run } from "../src/qbitvault.js";
import { cleanupFake } from "./helpers.js";

const win = process.platform === "win32";
const EXE = win ? "qbit-vault.exe" : "qbit-vault";
const dirs: string[] = [];
const saved = { ...process.env };

afterEach(() => {
	cleanupFake();
	for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
	for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
	Object.assign(process.env, saved);
});

function tmp(): string {
	const d = mkdtempSync(join(tmpdir(), "qvpi-bin-"));
	dirs.push(d);
	return d;
}

/** A file the resolver should treat as the binary; never actually run by the unit tests. */
function plant(dir: string): string {
	mkdirSync(dir, { recursive: true });
	const file = join(dir, EXE);
	writeFileSync(file, "#!/bin/sh\n");
	if (!win) chmodSync(file, 0o755);
	return file;
}

const env = (extra: Record<string, string>) => ({ HOME: tmp(), USERPROFILE: tmp(), LOCALAPPDATA: tmp(), PATHEXT: ".COM;.EXE;.BAT", ...extra });

describe("binary resolution (never from the working directory)", () => {
	it("finds the binary in an absolute PATH entry", () => {
		const bin = tmp();
		const file = plant(bin);
		expect(resolveBinary(env({ PATH: ["", bin].join(delimiter) }), tmp())).toEqual({ ok: true, path: file });
	});

	it("ignores empty and relative PATH entries even when the working directory holds a binary", () => {
		const cwd = tmp();
		plant(cwd);
		plant(join(cwd, "sub"));
		const result = resolveBinary(env({ PATH: ["", ".", "sub", "./sub", ".."].join(delimiter) }), cwd);
		expect(result).toEqual({ ok: false, reason: "not_found" });
	});

	it("skips the working directory even when PATH names it with an absolute path", () => {
		const cwd = tmp();
		plant(cwd);
		expect(resolveBinary(env({ PATH: cwd }), cwd)).toEqual({ ok: false, reason: "not_found" });
	});

	it("takes a later absolute entry after skipping the working directory", () => {
		const cwd = tmp();
		const bin = tmp();
		plant(cwd);
		const file = plant(bin);
		expect(resolveBinary(env({ PATH: [cwd, bin].join(delimiter) }), cwd)).toEqual({ ok: true, path: file });
	});

	it("falls back to the installers' default location", () => {
		const home = tmp();
		const file = win ? plant(join(home, "go", "bin")) : plant(join(home, ".local", "bin"));
		const result = resolveBinary(env({ PATH: "", HOME: home, USERPROFILE: home }), tmp());
		expect(result).toEqual({ ok: true, path: file });
	});

	it.runIf(win)("falls back to the install.ps1 directory", () => {
		const local = tmp();
		const file = plant(join(local, "Programs", "qbit-vault"));
		expect(resolveBinary(env({ PATH: "", LOCALAPPDATA: local }), tmp())).toEqual({ ok: true, path: file });
	});

	it("reports not_found when nothing is installed", () => {
		expect(resolveBinary(env({ PATH: "" }), tmp())).toEqual({ ok: false, reason: "not_found" });
	});

	it("accepts an absolute QBIT_VAULT_BIN override as is", () => {
		const file = join(tmp(), "custom-qbit-vault");
		expect(resolveBinary(env({ QBIT_VAULT_BIN: file, PATH: "" }), tmp())).toEqual({ ok: true, path: file });
	});

	it.each(["qbit-vault", "./qbit-vault", "..\\qbit-vault.exe", "bin/qbit-vault"])("refuses the relative override %s", (value) => {
		expect(resolveBinary(env({ QBIT_VAULT_BIN: value }), tmp())).toEqual({ ok: false, reason: "relative_override" });
	});
});

describe("spawning never reaches the working directory", () => {
	function isolate(cwd: string): void {
		const empty = tmp();
		delete process.env.QBIT_VAULT_BIN;
		process.env.PATH = empty;
		process.env.HOME = empty;
		process.env.USERPROFILE = empty;
		process.env.LOCALAPPDATA = empty;
		void cwd;
	}

	it("does not run a qbit-vault planted in the working directory", async () => {
		const cwd = tmp();
		const marker = join(cwd, "ran");
		const planted = join(cwd, EXE);
		if (win) {
			copyFileSync(process.execPath, planted); // a real executable; if it ran, the result would not be not_installed
		} else {
			writeFileSync(planted, `#!/bin/sh\ntouch '${marker}'\necho '{}'\n`);
			chmodSync(planted, 0o755);
		}
		isolate(cwd);
		process.env.PATH = [".", cwd, ""].join(delimiter);
		const result = await run(["grants"], { timeoutMs: 5000, cwd });
		expect(result).toEqual({ kind: "not_installed" });
		expect(existsSync(marker)).toBe(false);
	});

	it("refuses a relative override without starting anything", async () => {
		process.env.QBIT_VAULT_BIN = "qbit-vault";
		expect(await run(["grants"], { timeoutMs: 5000 })).toEqual({ kind: "failed_to_start" });
	});
});
