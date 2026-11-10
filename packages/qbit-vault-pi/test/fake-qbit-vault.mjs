// A stand-in for the qbit-vault binary. It records its argv and stdin to FAKE_QV_LOG (JSON lines)
// and answers from FAKE_QV_RESPONSES, a JSON object keyed by the first argument:
//   { "grants": { "code": 0, "stdout": { "ok": true, "grants": [] } } }
// FAKE_QV_SLEEP_MS delays the answer (timeout tests); "raw" in a response prints that text as is.
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
const response = responses[argv[0]] ?? { code: 1, stdout: { ok: false, error: { code: "internal", message: "no canned answer" } } };
const sleep = Number(process.env.FAKE_QV_SLEEP_MS ?? 0);

setTimeout(() => {
	process.stdout.write(response.raw ?? JSON.stringify(response.stdout ?? {}));
	process.exitCode = response.code ?? 0;
}, sleep);
