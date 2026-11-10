import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const pkgDir = join(here, "..");
const script = join(pkgDir, "scripts", "assemble-dist.mjs");
const tmp: string[] = [];

afterAll(() => {
	for (const d of tmp) rmSync(d, { recursive: true, force: true });
});

function tempDir(): string {
	const d = mkdtempSync(join(tmpdir(), "qvpi-asm-"));
	tmp.push(d);
	return d;
}

function run(args: string[]) {
	return spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
}

/** A package directory shaped like the real one, with dev-only fields. */
function fixturePackage(): { dir: string; license: string } {
	const root = tempDir();
	const dir = join(root, "pkg");
	mkdirSync(join(dir, "dist"), { recursive: true });
	writeFileSync(join(dir, "dist", "index.js"), "export default function () {}\n");
	writeFileSync(join(dir, "secret-patterns.yaml"), "patterns: []\n");
	writeFileSync(join(dir, "README.md"), "# readme\n");
	writeFileSync(
		join(dir, "package.json"),
		JSON.stringify({
			name: "qbit-vault-pi",
			version: "9.9.9",
			description: "d",
			keywords: ["pi-package"],
			license: "MIT",
			type: "module",
			repository: { type: "git", url: "git+https://example.invalid/r.git", directory: "packages/qbit-vault-pi" },
			pi: { extensions: ["./dist/index.js"] },
			files: ["dist", "secret-patterns.yaml", "README.md"],
			scripts: { build: "tsc", prepublishOnly: "npm test" },
			peerDependencies: { typebox: "*" },
			devDependencies: { typescript: "^7.0.2" },
		}),
	);
	const license = join(root, "LICENSE");
	writeFileSync(license, "MIT License\n");
	return { dir, license };
}

describe("assemble-dist", () => {
	it("writes a package.json without devDependencies or scripts and the four payload entries", () => {
		const { dir, license } = fixturePackage();
		const out = join(tempDir(), "tree");
		const r = run(["--out", out, "--package-dir", dir, "--license", license]);
		expect(r.status, r.stderr).toBe(0);

		const pub = JSON.parse(readFileSync(join(out, "package.json"), "utf8"));
		expect(pub.devDependencies).toBeUndefined();
		expect(pub.scripts).toBeUndefined();
		expect(pub.dependencies).toBeUndefined();
		expect(pub.peerDependencies).toEqual({ typebox: "*" });
		expect(pub.pi).toEqual({ extensions: ["./dist/index.js"] });
		expect(pub).toMatchObject({ name: "qbit-vault-pi", version: "9.9.9", type: "module", license: "MIT" });
		expect(pub.repository.directory).toBeUndefined();
		expect(pub.files).toEqual(["dist", "secret-patterns.yaml", "README.md", "LICENSE"]);
		for (const f of ["dist/index.js", "secret-patterns.yaml", "README.md", "LICENSE"]) expect(existsSync(join(out, f)), f).toBe(true);
		expect(readFileSync(join(out, "LICENSE"), "utf8")).toBe("MIT License\n");
	});

	it("refuses a missing build and a non-empty output directory", () => {
		const { dir, license } = fixturePackage();
		rmSync(join(dir, "dist"), { recursive: true });
		const noBuild = run(["--out", join(tempDir(), "t"), "--package-dir", dir, "--license", license]);
		expect(noBuild.status).toBe(1);
		expect(noBuild.stderr).toContain("npm run build");

		const full = fixturePackage();
		const out = tempDir();
		writeFileSync(join(out, "keep"), "x");
		const r = run(["--out", out, "--package-dir", full.dir, "--license", full.license]);
		expect(r.status).toBe(1);
		expect(r.stderr).toContain("is not empty");
	});

	// Same checks on the real package, when it has been built (CI builds first).
	it.skipIf(!existsSync(join(pkgDir, "dist", "index.js")))("assembles the real package with the repository LICENSE", () => {
		const out = join(tempDir(), "real");
		const r = run(["--out", out]);
		expect(r.status, r.stderr).toBe(0);
		const pub = JSON.parse(readFileSync(join(out, "package.json"), "utf8"));
		const src = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
		expect(pub.version).toBe(src.version);
		expect(pub.devDependencies).toBeUndefined();
		expect(Object.keys(pub.peerDependencies).sort()).toEqual(Object.keys(src.peerDependencies).sort());
		for (const f of ["dist/index.js", "secret-patterns.yaml", "README.md", "LICENSE"]) expect(existsSync(join(out, f)), f).toBe(true);
		expect(readFileSync(join(out, "LICENSE"), "utf8")).toBe(readFileSync(join(pkgDir, "..", "..", "LICENSE"), "utf8"));
	});
});
