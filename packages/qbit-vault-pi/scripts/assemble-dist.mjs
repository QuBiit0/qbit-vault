#!/usr/bin/env node
// Assembles the tree that the pi-v<version> git tags hold (S12): the built
// package at the root, with a package.json that has no devDependencies and no
// scripts, so `pi install git:...` needs no build and pulls nothing but the
// (empty) runtime dependencies. Pi installs a git package with
// `npm install --omit=dev --legacy-peer-deps` and never installs peers.
//
//   node scripts/assemble-dist.mjs --out <empty dir> [--package-dir <dir>] [--license <file>]
//
// Run `npm run build` first. Nothing here reads a secret or touches the network.
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// The fields of the source package.json that survive. `scripts` and
// `devDependencies` are dropped on purpose, and so is `repository.directory`
// because the tree is the package root.
const KEEP = ["name", "version", "description", "keywords", "license", "type", "repository", "engines", "pi", "peerDependencies", "files"];
const FILES = ["dist", "secret-patterns.yaml", "README.md", "LICENSE"];

function fail(msg) {
	process.stderr.write(`assemble-dist: ${msg}\n`);
	process.exit(1);
}

function parseArgs(argv) {
	const opts = {};
	for (let i = 0; i < argv.length; i += 2) {
		const flag = argv[i];
		const value = argv[i + 1];
		if (!["--out", "--package-dir", "--license"].includes(flag) || value === undefined) fail(`unexpected argument ${flag}`);
		opts[flag.slice(2)] = value;
	}
	return opts;
}

function publishedManifest(source) {
	const out = {};
	for (const key of KEEP) if (source[key] !== undefined) out[key] = source[key];
	if (out.repository && typeof out.repository === "object") {
		const { directory: _directory, ...repository } = out.repository;
		out.repository = repository;
	}
	out.files = [...FILES];
	return out;
}

function main() {
	const opts = parseArgs(process.argv.slice(2));
	if (!opts.out) fail("--out <dir> is required");
	const pkgDir = resolve(opts["package-dir"] ?? join(here, ".."));
	const license = resolve(opts.license ?? join(pkgDir, "..", "..", "LICENSE"));
	const out = resolve(opts.out);

	if (existsSync(out) && readdirSync(out).length > 0) fail(`${out} is not empty`);
	const manifest = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
	for (const needed of ["dist/index.js", "secret-patterns.yaml", "README.md"]) {
		if (!existsSync(join(pkgDir, needed))) fail(`${needed} is missing in ${pkgDir}${needed.startsWith("dist") ? " (run npm run build)" : ""}`);
	}
	if (!existsSync(license)) fail(`${license} is missing`);
	for (const ext of manifest.pi?.extensions ?? []) {
		if (!existsSync(join(pkgDir, ext))) fail(`pi.extensions entry ${ext} is missing (run npm run build)`);
	}

	mkdirSync(out, { recursive: true });
	cpSync(join(pkgDir, "dist"), join(out, "dist"), { recursive: true });
	cpSync(join(pkgDir, "secret-patterns.yaml"), join(out, "secret-patterns.yaml"));
	cpSync(join(pkgDir, "README.md"), join(out, "README.md"));
	cpSync(license, join(out, "LICENSE"));
	writeFileSync(join(out, "package.json"), `${JSON.stringify(publishedManifest(manifest), null, 2)}\n`);
	process.stdout.write(`assembled ${manifest.name}@${manifest.version} in ${out}\n`);
}

main();
