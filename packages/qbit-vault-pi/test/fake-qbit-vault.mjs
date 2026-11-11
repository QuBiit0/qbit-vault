// A stand-in for the qbit-vault binary. It records its argv and stdin to FAKE_QV_LOG (JSON lines)
// and answers from FAKE_QV_RESPONSES, a JSON object keyed by the first argument:
//   { "grants": { "code": 0, "stdout": { "ok": true, "grants": [] } } }
// FAKE_QV_FLOOD_BYTES prints that many bytes of "x" instead of the response (output cap tests).
// FAKE_QV_SLEEP_MS delays the answer (timeout tests); "raw" in a response prints that text as is.
// A response with "mode": "redact" under "hook" answers hook events like the real binary does for
// a stored value matching /TESTSECRET_\w+/: post-bash/post-read print the PostToolUse
// updatedToolOutput with the value replaced by [REDACTED:API_KEY] in every string (nothing when no
// string changed); pre-write prints the deny with the exact reason (nothing when no string matches).
import { appendFileSync, readFileSync } from "node:fs";

let stdin = "";
try {
	stdin = readFileSync(0, "utf8");
} catch {
	// stdin closed or not readable: nothing was sent
}

const argv = process.argv.slice(2);
if (process.env.FAKE_QV_LOG) {
	appendFileSync(process.env.FAKE_QV_LOG, `${JSON.stringify({ argv, stdin })}\n`);
}

const responses = JSON.parse(process.env.FAKE_QV_RESPONSES ?? "{}");

const VALUE = /TESTSECRET_\w+/g;
const mapStrings = (v, f) =>
	typeof v === "string" ? f(v) : Array.isArray(v) ? v.map((e) => mapStrings(e, f)) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, e]) => [k, mapStrings(e, f)])) : v;

function hookAnswer() {
	let event;
	try {
		event = JSON.parse(stdin);
	} catch {
		return { raw: "" };
	}
	if (argv[1] === "pre-write") {
		let hit = false;
		mapStrings(event.tool_input, (s) => ((hit ||= new RegExp(VALUE.source).test(s)), s));
		if (!hit) return { raw: "" };
		const reason =
			"This edit would write the value of the stored secret API_KEY to a file, so qbit-vault blocked it. Give the value to the command that needs it with secret_exec instead.";
		return { stdout: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } } };
	}
	let n = 0;
	const out = mapStrings(event.tool_response, (s) => s.replace(VALUE, () => (n++, "[REDACTED:API_KEY]")));
	if (n === 0) return { raw: "" };
	return { stdout: { hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: `qbit-vault redacted ${n} occurrence(s) of stored secrets`, updatedToolOutput: out } } };
}

let response = responses[argv[0]] ?? { code: 1, stdout: { ok: false, error: { code: "internal", message: "no canned answer" } } };
if (argv[0] === "hook" && response.mode === "redact") response = hookAnswer();
const sleep = Number(process.env.FAKE_QV_SLEEP_MS ?? 0);

setTimeout(() => {
	const flood = Number(process.env.FAKE_QV_FLOOD_BYTES ?? 0);
	if (flood > 0) {
		process.stdout.write("x".repeat(flood));
		return;
	}
	process.stdout.write(response.raw ?? JSON.stringify(response.stdout ?? {}));
	process.exitCode = response.code ?? 0;
}, sleep);
