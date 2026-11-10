import { statSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ExtensionContext, InputEvent, InputEventResult } from "@earendil-works/pi-coding-agent";
import { BAD_NAME, failureText, NAME_PATTERN } from "./messages.js";
import { findMatches, loadPatterns, PATTERN_LABELS, type Match } from "./patterns.js";
import { runJson } from "./qbitvault.js";

const SET_TIMEOUT_MS = 20_000;
const DROPPED = "message not sent: it contained a secret";
const STORE_FAILED = "qbit-vault could not store the secret";
const DROP = "Don't store, drop the message";
const OTHER_NAME = "Store under another name…";

/** True when `dir` or one of its parents has a `.git`, the way the CLI finds the project layer. */
function insideRepository(dir: string): boolean {
	for (let current = dir; ; current = dirname(current)) {
		try {
			statSync(join(current, ".git"));
			return true;
		} catch {
			// not here
		}
		if (dirname(current) === current) return false;
	}
}

type Choice = { name: string; layer: "global" | "project" } | undefined;

/** Asks what to do with one value. `undefined` means drop the message. The value is never in a prompt. */
async function choose(ctx: ExtensionContext, match: Match, repo: boolean): Promise<Choice> {
	const label = PATTERN_LABELS[match.id] ?? "secret";
	const everywhere = `Store as ${match.suggest} (all projects)`;
	const here = `Store as ${match.suggest} (this project)`;
	const options = [everywhere, ...(repo ? [here] : []), OTHER_NAME, DROP];
	const picked = await ctx.ui.select(`This looks like a ${label}. Store it in QBit Vault?`, options);
	if (picked === everywhere) return { name: match.suggest, layer: "global" };
	if (picked === here && repo) return { name: match.suggest, layer: "project" };
	if (picked !== OTHER_NAME) return undefined;

	let title = "Name for the secret";
	for (;;) {
		const typed = await ctx.ui.input(title, "NAME");
		if (typed === undefined) return undefined;
		const name = typed.trim();
		if (NAME_PATTERN.test(name)) return { name, layer: "global" };
		// The rejected text is not echoed: it may have been the value.
		title = BAD_NAME;
	}
}

function dropNotice(ctx: ExtensionContext): void {
	try {
		ctx.ui?.notify(DROPPED, "warning");
	} catch {
		// no UI to tell: the message is dropped all the same
	}
}

/**
 * `pi.on("input")` handler (S6). A typed or pasted value that looks like a secret is never sent as
 * typed: the user stores it (and the text carries `secret://NAME` instead) or the message is dropped.
 */
export function createPasteHandler(onPatternsUnavailable: (ctx: ExtensionContext) => void = () => {}) {
	return async (event: InputEvent, ctx: ExtensionContext): Promise<InputEventResult> => {
		if (event.source !== "interactive") return { action: "continue" };

		let patterns;
		try {
			patterns = loadPatterns();
		} catch {
			// A broken install must not block every message: they keep flowing, and the footer and a
			// one-time warning say that the guard is off.
			onPatternsUnavailable(ctx);
			return { action: "continue" };
		}

		const found = findMatches(event.text, patterns);
		if (found.length === 0) return { action: "continue" };

		// The values exist only in this array and in `text` until the call returns.
		const values: string[] = [];
		let text = event.text;
		try {
			if (!ctx.hasUI || ctx.mode !== "tui") {
				dropNotice(ctx);
				return { action: "handled" };
			}

			const repo = insideRepository(ctx.cwd);
			for (const match of found) {
				if (values.includes(match.value)) continue; // already stored: replaced everywhere below
				values.push(match.value);

				const choice = await choose(ctx, match, repo);
				if (!choice) {
					dropNotice(ctx);
					return { action: "handled" };
				}

				const stored = await runJson(["set", choice.name, `--${choice.layer}`, "--stdin"], {
					stdin: match.value,
					timeoutMs: SET_TIMEOUT_MS,
					cwd: ctx.cwd,
				});
				if (!stored.ok) {
					let message = failureText(stored);
					if (message.includes(match.value)) message = STORE_FAILED;
					ctx.ui.notify(message, "error");
					return { action: "handled" };
				}
				text = text.split(match.value).join(`secret://${choice.name}`);
				ctx.ui.notify(`stored as ${choice.name}`, "info");
			}
			return event.images ? { action: "transform", text, images: event.images } : { action: "transform", text };
		} finally {
			// JS strings cannot be wiped; drop every reference we hold.
			values.fill("");
			values.length = 0;
			found.length = 0;
			text = "";
		}
	};
}
