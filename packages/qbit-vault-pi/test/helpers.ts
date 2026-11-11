import { mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { vi } from "vitest";
import qbitVaultPi from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));

/** A value-shaped fixture (AGENTS.md: secrets in tests are TESTSECRET_ fixtures). */
// Assembled at run time so the source holds no token-shaped literal.
export const FIXTURE = ["TESTSECRET_", "ghp", "_0123456789", "abcdefghijklmnopqrstuvwxyz"].join("");
export const SESSION_ID = "11111111-2222-3333-4444-555555555555";
export const SESSION = `pi:${SESSION_ID}`;

export type Canned = Record<string, { code?: number; stdout?: unknown; raw?: string; mode?: "redact" }>;
export type Call = { argv: string[]; stdin: string };

const dirs: string[] = [];

/** Points QBIT_VAULT_BIN at the fake and returns a reader for what it recorded. */
export function useFake(responses: Canned, extraEnv: Record<string, string> = {}) {
	const dir = mkdtempSync(join(tmpdir(), "qvpi-"));
	dirs.push(dir);
	const log = join(dir, "calls.jsonl");
	process.env.QBIT_VAULT_BIN = join(here, "fake-qbit-vault.mjs");
	process.env.FAKE_QV_LOG = log;
	process.env.FAKE_QV_RESPONSES = JSON.stringify(responses);
	for (const [k, v] of Object.entries(extraEnv)) process.env[k] = v;
	return {
		calls(): Call[] {
			if (!existsSync(log)) return [];
			return readFileSync(log, "utf8")
				.split("\n")
				.filter(Boolean)
				.map((l) => JSON.parse(l) as Call);
		},
	};
}

export function cleanupFake(): void {
	for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
	delete process.env.QBIT_VAULT_BIN;
	delete process.env.FAKE_QV_LOG;
	delete process.env.FAKE_QV_RESPONSES;
	delete process.env.FAKE_QV_SLEEP_MS;
}

export const ok = (stdout: unknown, code = 0) => ({ code, stdout });
export const err = (code: string, message: string, exit = 1) => ({
	code: exit,
	stdout: { ok: false, error: { code, message } },
});

type Handler = (event: any, ctx: any) => unknown;

/** The slice of ExtensionAPI the extension uses, plus spies on everything that would reach the model. */
export function mockPi() {
	const commands = new Map<string, any>();
	const handlers = new Map<string, Handler[]>();
	const pi = {
		registerCommand: vi.fn((name: string, options: any) => void commands.set(name, options)),
		on: vi.fn((event: string, handler: Handler) => {
			handlers.set(event, [...(handlers.get(event) ?? []), handler]);
			return () => {};
		}),
		// Anything below enters the model context or the session file: it must stay uncalled.
		sendMessage: vi.fn(),
		sendUserMessage: vi.fn(),
		appendEntry: vi.fn(),
	};
	qbitVaultPi(pi as any);
	return {
		pi,
		command: () => commands.get("vault"),
		/** Runs every handler of the event; returns the last result a handler gave. */
		async emit(event: string, payload: any, ctx: any): Promise<any> {
			let result: unknown;
			for (const h of handlers.get(event) ?? []) result = (await h(payload, ctx)) ?? result;
			return result;
		},
		handlerCount: (event: string) => (handlers.get(event) ?? []).length,
	};
}

export type View = { title: string; lines: string[] };

export function mockCtx(options: { mode?: string; hasUI?: boolean; cwd?: string } = {}) {
	const views: View[] = [];
	const theme = { fg: (_c: string, t: string) => t, bold: (t: string) => t };
	const ui = {
		notify: vi.fn(),
		setStatus: vi.fn(),
		select: vi.fn(),
		input: vi.fn(),
		custom: vi.fn(async (factory: any) => {
			let finish!: (v: unknown) => void;
			const closed = new Promise((r) => (finish = r));
			const component = await factory({}, theme, {}, finish);
			const rendered: string[] = component.render(100);
			// First non-empty line is the title; the lines between the two rules are the body.
			const rules = rendered.flatMap((l, i) => (l.startsWith("─") ? [i] : []));
			views.push({
				title: rendered.find((l) => l !== "") ?? "",
				lines: rendered.slice((rules[0] ?? -1) + 1, rules[1] ?? rendered.length),
			});
			component.handleInput("q");
			return closed;
		}),
	};
	const ctx = {
		ui,
		mode: options.mode ?? "tui",
		hasUI: options.hasUI ?? true,
		cwd: options.cwd ?? process.cwd(),
		sessionManager: { getSessionId: () => SESSION_ID },
	};
	return { ctx, ui, views };
}

/** Everything the UI was told, as one string, for leak assertions. */
export function everythingShown(ui: ReturnType<typeof mockCtx>["ui"], views: View[]): string {
	return JSON.stringify([ui.notify.mock.calls, ui.setStatus.mock.calls, views]);
}
