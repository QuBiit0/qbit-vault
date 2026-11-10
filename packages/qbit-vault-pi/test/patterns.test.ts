import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { findMatches, loadPatterns, parsePatterns, PATTERN_LABELS } from "../src/patterns.js";

// Token-shaped samples are assembled at run time (see helpers.ts).
const DASH5 = "-".repeat(5);

const here = dirname(fileURLToPath(import.meta.url));
const alnum36 = "0123456789abcdefghijklmnopqrstuvwxyz";

// Each sample is built here so no complete token sits in the source as one literal.
const samples: Array<{ id: string; text: string; value: string; suggest: string }> = [
	{ id: "github_pat", text: `ghp_${alnum36}`, value: `ghp_${alnum36}`, suggest: "GITHUB_TOKEN" },
	{ id: "github_fine_grained", text: `github_pat_${"A1b2C3d4_".repeat(10)}`, value: `github_pat_${"A1b2C3d4_".repeat(10)}`, suggest: "GITHUB_TOKEN" },
	{ id: "openai", text: `sk-proj-${alnum36}ABCD`, value: `sk-proj-${alnum36}ABCD`, suggest: "OPENAI_API_KEY" },
	{ id: "anthropic", text: `sk-ant-${alnum36}-ABCDEFGHIJ`, value: `sk-ant-${alnum36}-ABCDEFGHIJ`, suggest: "ANTHROPIC_API_KEY" },
	{ id: "aws_access_key", text: ["AK", "IA", "0123456789ABCDEF"].join(""), value: ["AK", "IA", "0123456789ABCDEF"].join(""), suggest: "AWS_ACCESS_KEY_ID" },
	{ id: "slack", text: ["xo", "xb-", "1234567890-abcdefghij"].join(""), value: ["xo", "xb-", "1234567890-abcdefghij"].join(""), suggest: "SLACK_TOKEN" },
	{ id: "stripe", text: `sk_live_${alnum36.slice(0, 26)}`, value: `sk_live_${alnum36.slice(0, 26)}`, suggest: "STRIPE_API_KEY" },
	{ id: "google_api", text: `AIza${alnum36.slice(0, 35)}`, value: `AIza${alnum36.slice(0, 35)}`, suggest: "GOOGLE_API_KEY" },
	{ id: "npm", text: `npm_${alnum36}`, value: `npm_${alnum36}`, suggest: "NPM_TOKEN" },
	{ id: "vercel", text: `vercel_${alnum36.slice(0, 26)}`, value: `vercel_${alnum36.slice(0, 26)}`, suggest: "VERCEL_TOKEN" },
	{
		id: "jwt",
		text: ["ey", "JhbGciOiJIUzI1NiJ9", ".", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0", ".abcdefghijklmnop"].join(""),
		value: ["ey", "JhbGciOiJIUzI1NiJ9", ".", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0", ".abcdefghijklmnop"].join(""),
		suggest: "JWT_TOKEN",
	},
	{
		id: "database_url",
		text: "postgres://app:s3cretpw@db.internal:5432/app",
		value: "postgres://app:s3cretpw@db.internal:5432/app",
		suggest: "DATABASE_URL",
	},
];

describe("secret-patterns.yaml", () => {
	it("parses to every id of the file, each with a readable label", () => {
		const patterns = loadPatterns();
		expect(patterns.map((p) => p.id)).toEqual([
			"github_pat",
			"github_fine_grained",
			"openai",
			"anthropic",
			"aws_access_key",
			"slack",
			"stripe",
			"google_api",
			"npm",
			"vercel",
			"private_key_pem",
			"jwt",
			"database_url",
			"generic_assignment_high_entropy",
		]);
		for (const p of patterns) expect(PATTERN_LABELS[p.id], p.id).toBeTruthy();
	});

	it("is the file the package ships, byte for byte the one in defaults/", () => {
		const shipped = readFileSync(join(here, "..", "secret-patterns.yaml"));
		const defaults = readFileSync(join(here, "..", "..", "..", "defaults", "secret-patterns.yaml"));
		expect(shipped.equals(defaults)).toBe(true);
	});

	for (const s of samples) {
		it(`${s.id} matches its sample and suggests ${s.suggest}`, () => {
			const found = findMatches(`before ${s.text} after`, loadPatterns());
			expect(found).toHaveLength(1);
			expect(found[0]?.id).toBe(s.id);
			expect(found[0]?.value).toBe(s.value);
			expect(found[0]?.suggest).toBe(s.suggest);
		});
	}

	it("matches a PEM private key as the whole block", () => {
		const block = [DASH5, "BEGIN OPENSSH PRIVATE KEY", DASH5, "\nAAAA\nBBBB\n", DASH5, "END OPENSSH PRIVATE KEY", DASH5].join("");
		const found = findMatches(`here:\n${block}\nthanks`, loadPatterns());
		expect(found).toHaveLength(1);
		expect(found[0]).toMatchObject({ id: "private_key_pem", suggest: "PRIVATE_KEY", value: block });
	});

	it("takes a PEM header with no end marker through the end of the text", () => {
		const found = findMatches([DASH5, "BEGIN PRIVATE KEY", DASH5, "\nAAAA"].join(""), loadPatterns());
		expect(found[0]?.value).toBe([DASH5, "BEGIN PRIVATE KEY", DASH5, "\nAAAA"].join(""));
	});

	it("generic assignment: value is the group, suggest is the key, entropy filters", () => {
		const value = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC2eF4hJ6";
		const found = findMatches(`export API_SECRET="${value}"`, loadPatterns());
		expect(found).toHaveLength(1);
		expect(found[0]).toMatchObject({ id: "generic_assignment_high_entropy", suggest: "API_SECRET", value });
		expect(findMatches(`API_SECRET=${"a".repeat(40)}`, loadPatterns())).toEqual([]);
	});

	it("a specific pattern wins over the generic one on the same value", () => {
		const found = findMatches(`GITHUB_TOKEN=ghp_${alnum36}`, loadPatterns());
		expect(found.map((m) => m.id)).toEqual(["github_pat"]);
	});

	it("the Anthropic pattern wins over the OpenAI one on the same span", () => {
		const found = findMatches(`sk-ant-${alnum36}-ABCDEFGHIJ`, loadPatterns());
		expect(found.map((m) => m.id)).toEqual(["anthropic"]);
	});

	it("returns matches in text order, non overlapping", () => {
		const text = `npm_${alnum36} and ${["AK", "IA", "0123456789ABCDEF"].join("")}`;
		expect(findMatches(text, loadPatterns()).map((m) => m.id)).toEqual(["npm", "aws_access_key"]);
	});

	it.each([
		["too short", "ghp_abc"],
		["no word boundary before the prefix", `xghp_${alnum36}`],
		["no word boundary after the token", `npm_${alnum36}x_`],
		["plain prose", "please deploy the app to staging"],
		["a URL without credentials", "postgres://db.internal:5432/app"],
	])("does not match: %s", (_name, text) => {
		expect(findMatches(text, loadPatterns())).toEqual([]);
	});

	it("keeps RE2 \\s ASCII-only: a no-break space does not end a database URL, a space does", () => {
		const url = "mysql://u:pw@host/db";
		expect(findMatches(`${url}\u00a0tail`, loadPatterns())[0]?.value).toBe(`${url}\u00a0tail`);
		expect(findMatches(`${url} tail`, loadPatterns())[0]?.value).toBe(url);
	});

	it("rejects a file with another format or an unsupported construct", () => {
		expect(() => parsePatterns("format: other/1\npatterns:\n")).toThrow();
		expect(() =>
			parsePatterns("format: qbit-vault-secret-patterns/1\npatterns:\n  - id: x\n    regex: '(?i)abc'\n    suggest: X\n"),
		).toThrow();
	});
});
