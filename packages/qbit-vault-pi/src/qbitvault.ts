import { spawn } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import { delimiter, isAbsolute, join, resolve as resolvePath, win32 } from "node:path";

/** Env var that points at the binary; tests use it, users normally leave it unset. */
export const BIN_ENV = "QBIT_VAULT_BIN";

const MAX_OUTPUT_BYTES = 1024 * 1024;

export type RunOptions = {
	/** Written to the child's stdin, then stdin is closed. Never logged. */
	stdin?: string;
	/** Kill the child after this many milliseconds. */
	timeoutMs: number;
	cwd?: string;
};

export type RunResult =
	| { kind: "not_installed" }
	| { kind: "timeout" }
	| { kind: "failed_to_start" }
	| {
			kind: "done";
			/** Exit code of the process, or null when a signal ended it. */
			code: number | null;
			/** Parsed stdout when it is one JSON value, otherwise undefined. */
			json: unknown;
	  };

/** The error object of a failed `--json` call. */
export type CliError = { code: string; message: string };

/** What `qbit-vault` answered, reduced to what the extension acts on. */
export type Outcome<T> =
	| { ok: true; data: T }
	| { ok: false; reason: "not_installed" | "timeout" | "failed"; error?: CliError; code?: number | null };

export type Resolved = { ok: true; path: string } | { ok: false; reason: "not_found" | "relative_override" };

const sameDir = (a: string, b: string) =>
	process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;

function isExecutableFile(file: string): boolean {
	try {
		if (!statSync(file).isFile()) return false;
		if (process.platform !== "win32") accessSync(file, constants.X_OK);
		return true;
	} catch {
		return false;
	}
}

/**
 * Finds `qbit-vault` as an absolute path. Node's spawn searches the working directory on Windows, and
 * a relative PATH entry means the same thing anywhere, so a repository could plant a binary that
 * receives a pasted secret on stdin. Only absolute PATH entries other than the working directory are
 * searched, then the installers' default locations. `QBIT_VAULT_BIN` must be absolute.
 */
export function resolveBinary(env: NodeJS.ProcessEnv, cwd: string | readonly string[]): Resolved {
	const override = env[BIN_ENV];
	if (override) {
		const absolute = process.platform === "win32" ? win32.isAbsolute(override) : isAbsolute(override);
		return absolute ? { ok: true, path: override } : { ok: false, reason: "relative_override" };
	}

	const win = process.platform === "win32";
	const names = win
		? (env.PATHEXT ?? ".COM;.EXE")
				.split(";")
				.map((ext) => ext.toLowerCase())
				// .cmd and .bat need a shell; spawn without one refuses them.
				.filter((ext) => ext === ".exe" || ext === ".com")
				.map((ext) => `qbit-vault${ext}`)
		: ["qbit-vault"];
	if (win && names.length === 0) names.push("qbit-vault.exe");

	const home = (win ? env.USERPROFILE : env.HOME) || env.HOME || env.USERPROFILE;
	const defaults: string[] = [];
	if (home) {
		if (win) {
			if (env.LOCALAPPDATA) defaults.push(join(env.LOCALAPPDATA, "Programs", "qbit-vault"));
			defaults.push(join(home, "go", "bin"));
		} else {
			defaults.push(join(home, ".local", "bin"));
		}
	} else if (win && env.LOCALAPPDATA) {
		defaults.push(join(env.LOCALAPPDATA, "Programs", "qbit-vault"));
	}

	const here = (typeof cwd === "string" ? [cwd] : cwd).map((d) => resolvePath(d));
	const fromPath = (env.PATH ?? env.Path ?? "").split(delimiter).filter((entry) => {
		if (entry === "" || !(win ? win32.isAbsolute(entry) : isAbsolute(entry))) return false;
		return !here.some((d) => sameDir(resolvePath(entry), d));
	});
	for (const dir of [...fromPath, ...defaults.filter((d) => isAbsolute(d))]) {
		for (const name of names) {
			const candidate = join(dir, name);
			if (isExecutableFile(candidate)) return { ok: true, path: candidate };
		}
	}
	return { ok: false, reason: "not_found" };
}

function resolveCommand(cwd: string | undefined): { command: string; prefix: string[] } | Extract<Resolved, { ok: false }> {
	const found = resolveBinary(process.env, cwd === undefined ? process.cwd() : [process.cwd(), cwd]);
	if (!found.ok) return found;
	// A script path (the fake binary in tests) runs through the current Node, still without a shell.
	if (/\.(mjs|cjs|js)$/i.test(found.path)) return { command: process.execPath, prefix: [found.path] };
	return { command: found.path, prefix: [] };
}

/**
 * Runs `qbit-vault` with an argv array (no shell). Arguments and stdin are never
 * logged or included in a result; stderr is discarded because every message the
 * extension shows comes from the parsed `--json` error object.
 */
export function run(args: string[], options: RunOptions): Promise<RunResult> {
	const resolved = resolveCommand(options.cwd);
	if (!("command" in resolved)) {
		return Promise.resolve({ kind: resolved.reason === "not_found" ? "not_installed" : "failed_to_start" });
	}
	const { command, prefix } = resolved;
	return new Promise((resolve) => {
		let settled = false;
		const finish = (result: RunResult) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(result);
		};

		let child;
		try {
			child = spawn(command, [...prefix, ...args], {
				shell: false,
				windowsHide: true,
				cwd: options.cwd,
				stdio: [options.stdin === undefined ? "ignore" : "pipe", "pipe", "ignore"],
			});
		} catch {
			resolve({ kind: "failed_to_start" });
			return;
		}

		const timer = setTimeout(() => {
			child.kill();
			finish({ kind: "timeout" });
		}, options.timeoutMs);

		const chunks: Buffer[] = [];
		let size = 0;
		child.stdout?.on("data", (chunk: Buffer) => {
			size += chunk.length;
			if (size <= MAX_OUTPUT_BYTES) chunks.push(chunk);
		});
		child.on("error", (err: NodeJS.ErrnoException) => {
			finish({ kind: err.code === "ENOENT" ? "not_installed" : "failed_to_start" });
		});
		child.on("close", (code) => {
			let json: unknown;
			if (size <= MAX_OUTPUT_BYTES) {
				try {
					json = JSON.parse(Buffer.concat(chunks).toString("utf8"));
				} catch {
					json = undefined;
				}
			}
			finish({ kind: "done", code, json });
		});

		if (options.stdin !== undefined && child.stdin) {
			child.stdin.on("error", () => {});
			child.stdin.end(options.stdin);
		}
	});
}

function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Runs a command with `--json` and folds the result into an Outcome. `acceptCodes`
 * lists exit codes that still carry a success object (doctor exits 1 with a report).
 */
export async function runJson(
	args: string[],
	options: RunOptions & { acceptCodes?: number[] },
): Promise<Outcome<Record<string, unknown>>> {
	const result = await run([...args, "--json"], options);
	if (result.kind === "not_installed") return { ok: false, reason: "not_installed" };
	if (result.kind === "timeout") return { ok: false, reason: "timeout" };
	if (result.kind === "failed_to_start") return { ok: false, reason: "failed" };

	const body = result.json;
	if (isRecord(body) && body.ok === false && isRecord(body.error)) {
		const { code, message } = body.error;
		if (typeof code === "string" && typeof message === "string") {
			return { ok: false, reason: "failed", error: { code, message }, code: result.code };
		}
	}
	const accepted = result.code === 0 || (result.code !== null && (options.acceptCodes ?? []).includes(result.code));
	if (isRecord(body) && accepted) return { ok: true, data: body };
	return { ok: false, reason: "failed", code: result.code };
}
