import { readFileSync } from "node:fs";
/** First line of `defaults/secret-patterns.yaml` that this reader understands. */
const FORMAT = "qbit-vault-secret-patterns/1";
/** Where the package copy lives: next to `dist/` and `src/`, so it resolves from both. */
const FILE = new URL("../secret-patterns.yaml", import.meta.url);
/** What the user is told the text looks like, by pattern id. Starts with a consonant sound ("a …"). */
export const PATTERN_LABELS = {
    github_pat: "GitHub token",
    github_fine_grained: "GitHub fine-grained token",
    openai: "secret OpenAI key",
    anthropic: "secret Anthropic key",
    aws_access_key: "secret AWS access key",
    slack: "Slack token",
    stripe: "Stripe API key",
    google_api: "Google API key",
    npm: "npm token",
    vercel: "Vercel token",
    private_key_pem: "private key",
    jwt: "JSON Web Token",
    database_url: "database URL with credentials",
    generic_assignment_high_entropy: "high-entropy secret",
};
/** RE2 `\s` is ASCII only; JS `\s` also matches no-break and other Unicode spaces. */
const RE2_SPACE = "\\t\\n\\f\\r ";
/**
 * Turns the Go (RE2) source of a pattern into a JS RegExp that matches the same text.
 * `\b`, classes, groups, `{n,}` and `(a|b)` mean the same in both; `\s` is narrowed to RE2's
 * ASCII set. Anything else that differs (inline flags, named groups, `\z`) is refused loudly.
 */
export function re2ToRegExp(source) {
    let out = "";
    let inClass = false;
    for (let i = 0; i < source.length; i++) {
        const c = source[i];
        if (c === "\\") {
            const next = source[i + 1];
            if (next === undefined)
                throw new Error("pattern ends with a backslash");
            i++;
            if (next === "s")
                out += inClass ? RE2_SPACE : `[${RE2_SPACE}]`;
            else if (next === "S" && !inClass)
                out += `[^${RE2_SPACE}]`;
            else if ("zAQEpPCXKGhHVRN".includes(next))
                throw new Error(`unsupported RE2 escape \\${next}`);
            else
                out += c + next;
            continue;
        }
        if (inClass) {
            if (c === "]")
                inClass = false;
            else if (c === "[")
                throw new Error("unsupported nested character class");
            out += c;
            continue;
        }
        if (c === "[") {
            inClass = true;
            out += c;
            if (source[i + 1] === "^")
                out += source[++i];
            // A leading "]" is a literal in RE2 and in JS only outside of a class.
            if (source[i + 1] === "]")
                throw new Error("unsupported leading ] in a class");
            continue;
        }
        if (c === "(" && source[i + 1] === "?" && source.slice(i, i + 3) !== "(?:") {
            throw new Error("unsupported group syntax");
        }
        out += c;
    }
    if (inClass)
        throw new Error("unterminated character class");
    return new RegExp(out, "g");
}
/** Reads one scalar: a single-quoted string (`''` is a quote), or a plain value without its comment. */
function scalar(raw) {
    const v = raw.trim();
    if (v.startsWith("'")) {
        let out = "";
        for (let i = 1; i < v.length; i++) {
            if (v[i] === "'") {
                if (v[i + 1] === "'") {
                    out += "'";
                    i++;
                    continue;
                }
                return out;
            }
            out += v[i];
        }
        throw new Error("unterminated quoted value");
    }
    if (v.startsWith('"'))
        throw new Error("double-quoted values are not supported");
    const plain = v.replace(/\s+#.*$/, "");
    if (plain === "true")
        return true;
    if (plain === "false")
        return false;
    if (/^-?\d+(\.\d+)?$/.test(plain))
        return Number(plain);
    return plain;
}
/** Parses the fixed layout of `secret-patterns.yaml`: `format:` then `patterns:` as a list of flat maps. */
export function parsePatterns(yaml) {
    let format;
    const items = [];
    let inPatterns = false;
    for (const line of yaml.split(/\r?\n/)) {
        const text = line.trim();
        if (text === "" || text.startsWith("#"))
            continue;
        if (!line.startsWith(" ")) {
            const [key, ...rest] = text.split(":");
            if (key === "format")
                format = String(scalar(rest.join(":")));
            else if (key === "patterns" && rest.join(":").trim() === "")
                inPatterns = true;
            else
                throw new Error(`unexpected top-level line: ${key}`);
            continue;
        }
        if (!inPatterns)
            throw new Error("indented line before patterns");
        const body = text.startsWith("- ") ? text.slice(2) : text;
        if (text.startsWith("- "))
            items.push({});
        const current = items[items.length - 1];
        if (!current)
            throw new Error("a pattern field before the first '-'");
        const colon = body.indexOf(":");
        if (colon < 0)
            throw new Error("expected key: value");
        current[body.slice(0, colon).trim()] = scalar(body.slice(colon + 1));
    }
    if (format !== FORMAT)
        throw new Error(`unsupported secret-patterns format: ${format ?? "(none)"}`);
    return items.map((item) => {
        const { id, regex, suggest } = item;
        if (typeof id !== "string" || typeof regex !== "string" || typeof suggest !== "string") {
            throw new Error("a pattern needs id, regex and suggest");
        }
        return {
            id,
            regex: re2ToRegExp(regex),
            suggest,
            multiline: item.multiline === true,
            entropyMin: typeof item.entropy_min === "number" ? item.entropy_min : undefined,
        };
    });
}
let cached;
/** The patterns of the package copy, parsed once. Throws when the file is missing or malformed. */
export function loadPatterns() {
    cached ??= parsePatterns(readFileSync(FILE, "utf8"));
    return cached;
}
function entropy(s) {
    const counts = new Map();
    for (const ch of s)
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
    let bits = 0;
    const total = [...s].length;
    for (const n of counts.values())
        bits -= (n / total) * Math.log2(n / total);
    return bits;
}
/**
 * Finds the secret-shaped values in `text`, in text order and without overlaps. When two patterns
 * claim overlapping text the longer span wins; on a tie a specific pattern beats the generic
 * assignment, and of two specific ones the later in the file wins (the file lists the broad
 * `sk-` key before the `sk-ant-` one).
 */
export function findMatches(text, patterns) {
    const candidates = [];
    patterns.forEach((pattern, index) => {
        const re = new RegExp(pattern.regex.source, pattern.regex.flags);
        for (let m = re.exec(text); m !== null; m = re.exec(text)) {
            if (m[0] === "") {
                re.lastIndex++;
                continue;
            }
            let start = m.index;
            let end = m.index + m[0].length;
            let suggest = pattern.suggest;
            if (pattern.entropyMin !== undefined) {
                const captured = m[1];
                if (captured === undefined || entropy(captured) < pattern.entropyMin)
                    continue;
                start = m.index + m[0].lastIndexOf(captured);
                end = start + captured.length;
            }
            if (suggest.includes("{KEY}")) {
                const key = /^[A-Z][A-Z0-9_]*/.exec(m[0])?.[0] ?? "SECRET";
                suggest = suggest.replace("{KEY}", key);
            }
            if (pattern.multiline) {
                // The header starts a block; take it through its END line, or the end of the text.
                const close = /-----END [A-Z ]*PRIVATE KEY-----/.exec(text.slice(end));
                end = close ? end + close.index + close[0].length : text.length;
            }
            candidates.push({
                id: pattern.id,
                suggest,
                value: text.slice(start, end),
                start,
                end,
                index,
                generic: pattern.entropyMin !== undefined,
            });
        }
    });
    candidates.sort((a, b) => b.end - b.start - (a.end - a.start) || Number(a.generic) - Number(b.generic) || b.index - a.index);
    const accepted = [];
    for (const c of candidates) {
        if (accepted.every((a) => c.end <= a.start || c.start >= a.end))
            accepted.push(c);
    }
    return accepted
        .sort((a, b) => a.start - b.start)
        .map(({ id, suggest, value, start, end }) => ({ id, suggest, value, start, end }));
}
