import { spawn } from "node:child_process";

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

function resolveCommand(): { command: string; prefix: string[] } {
	const bin = process.env[BIN_ENV] || "qbit-vault";
	// A script path (the fake binary in tests) runs through the current Node, still without a shell.
	if (/\.(mjs|cjs|js)$/i.test(bin)) return { command: process.execPath, prefix: [bin] };
	return { command: bin, prefix: [] };
}

/**
 * Runs `qbit-vault` with an argv array (no shell). Arguments and stdin are never
 * logged or included in a result; stderr is discarded because every message the
 * extension shows comes from the parsed `--json` error object.
 */
export function run(args: string[], options: RunOptions): Promise<RunResult> {
	const { command, prefix } = resolveCommand();
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
