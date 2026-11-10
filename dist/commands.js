import { BAD_NAME, NAME_PATTERN, USAGE, failureText } from "./messages.js";
import { runJson } from "./qbitvault.js";
import { present } from "./view.js";
const QUERY_TIMEOUT_MS = 15_000;
/** `set` and `rm` wait for the user in a native dialog. */
const DIALOG_TIMEOUT_MS = 10 * 60_000;
const DEFAULT_AUDIT_TAIL = 20;
const MAX_AUDIT_TAIL = 1000;
const SUBCOMMANDS = [
    { value: "list", description: "Secret names, layers and grants" },
    { value: "set", description: "Store a secret (asked in a native dialog)" },
    { value: "rm", description: "Remove a secret" },
    { value: "revoke", description: "Revoke grants: NAME or --all" },
    { value: "audit", description: "Recent audit records" },
    { value: "doctor", description: "Health report" },
];
const LAYERS = ["global", "project"];
const rows = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "object" && x !== null) : []);
const text = (v, fallback = "") => (typeof v === "string" ? v : fallback);
export function completeArguments(prefix) {
    const parts = prefix.split(/\s+/);
    const [sub = ""] = parts;
    let items = [];
    if (parts.length === 1) {
        items = SUBCOMMANDS.map((s) => ({ value: s.value, label: s.value, description: s.description }));
    }
    else if (parts.length === 2 && sub === "list") {
        items = [...LAYERS, "all"].map((l) => ({ value: `list ${l}`, label: l }));
    }
    else if (parts.length === 2 && sub === "revoke") {
        items = [{ value: "revoke --all", label: "--all", description: "Every grant" }];
    }
    else if (parts.length === 2 && sub === "audit") {
        items = [{ value: "audit --tail ", label: "--tail", description: "How many records" }];
    }
    else if (parts.length === 3 && (sub === "set" || sub === "rm")) {
        items = LAYERS.map((l) => ({ value: `${sub} ${parts[1]} ${l}`, label: l }));
    }
    const filtered = items.filter((i) => i.value.startsWith(prefix));
    return filtered.length > 0 ? filtered : null;
}
export function createVaultHandler(status) {
    return async (rawArgs, ctx) => {
        const tokens = rawArgs.trim().split(/\s+/).filter(Boolean);
        const [sub, ...rest] = tokens;
        const usage = () => ctx.ui.notify(USAGE, "info");
        const fail = (outcome) => 
        // A cancelled dialog is not an error.
        ctx.ui.notify(failureText(outcome), outcome.error?.code === "cancelled" ? "warning" : "error");
        switch (sub) {
            case "list": {
                const [layer, ...extra] = rest;
                if (extra.length > 0 || (layer !== undefined && ![...LAYERS, "all"].includes(layer)))
                    return usage();
                const listed = await runJson(["list", ...(layer ? ["--layer", layer] : [])], {
                    timeoutMs: QUERY_TIMEOUT_MS,
                    cwd: ctx.cwd,
                });
                if (!listed.ok) {
                    fail(listed);
                    break;
                }
                const found = rows(listed.data.secrets);
                if (found.length === 0) {
                    ctx.ui.notify("no secrets", "info");
                    break;
                }
                // Grants are an extra: if they cannot be read the list is still shown.
                const grantsOutcome = await runJson(["grants"], { timeoutMs: QUERY_TIMEOUT_MS, cwd: ctx.cwd });
                const grants = grantsOutcome.ok ? rows(grantsOutcome.data.grants) : [];
                await present(ctx, "QBit Vault: secrets", formatList(found, grants));
                break;
            }
            case "set":
            case "rm": {
                const [name, layer, ...extra] = rest;
                if (!name || extra.length > 0 || (layer !== undefined && !LAYERS.includes(layer)))
                    return usage();
                if (!NAME_PATTERN.test(name)) {
                    // The argument may be a pasted value: it is never echoed or passed on.
                    ctx.ui.notify(BAD_NAME, "error");
                    return;
                }
                const outcome = await runJson([sub, name, ...(layer ? [`--${layer}`] : [])], {
                    timeoutMs: DIALOG_TIMEOUT_MS,
                    cwd: ctx.cwd,
                });
                if (!outcome.ok) {
                    fail(outcome);
                    break;
                }
                const where = text(outcome.data.layer, layer ?? "global");
                const verb = sub === "rm" ? "removed" : outcome.data.replaced === true ? "replaced" : "stored";
                ctx.ui.notify(`${verb} ${name} (${where})`, "info");
                break;
            }
            case "revoke": {
                const [target, ...extra] = rest;
                if (!target || extra.length > 0 || (target.startsWith("-") && target !== "--all"))
                    return usage();
                if (target !== "--all" && !NAME_PATTERN.test(target)) {
                    ctx.ui.notify(BAD_NAME, "error");
                    return;
                }
                const outcome = await runJson(["revoke", target], { timeoutMs: QUERY_TIMEOUT_MS, cwd: ctx.cwd });
                if (!outcome.ok) {
                    fail(outcome);
                    break;
                }
                const n = typeof outcome.data.revoked === "number" ? outcome.data.revoked : 0;
                ctx.ui.notify(`revoked ${n} ${n === 1 ? "grant" : "grants"}`, "info");
                break;
            }
            case "audit": {
                let tail = DEFAULT_AUDIT_TAIL;
                if (rest.length > 0) {
                    const [flag, value, ...extra] = rest;
                    if (flag !== "--tail" || !value || extra.length > 0 || !/^\d{1,4}$/.test(value))
                        return usage();
                    tail = Number(value);
                    if (tail < 1 || tail > MAX_AUDIT_TAIL)
                        return usage();
                }
                const outcome = await runJson(["audit", "--tail", String(tail)], { timeoutMs: QUERY_TIMEOUT_MS, cwd: ctx.cwd });
                if (!outcome.ok) {
                    fail(outcome);
                    break;
                }
                const records = rows(outcome.data.records);
                if (records.length === 0) {
                    ctx.ui.notify("no audit records", "info");
                    break;
                }
                await present(ctx, "QBit Vault: audit", records.map(formatAudit));
                break;
            }
            case "doctor": {
                if (rest.length > 0)
                    return usage();
                const outcome = await runJson(["doctor"], { timeoutMs: QUERY_TIMEOUT_MS, cwd: ctx.cwd, acceptCodes: [1, 2] });
                if (!outcome.ok) {
                    fail(outcome);
                    break;
                }
                const { lines, problems } = formatDoctor(rows(outcome.data.checks));
                await present(ctx, "QBit Vault: doctor", lines, problems > 0 ? "warning" : "info");
                break;
            }
            default:
                return usage();
        }
        await status.refresh(ctx);
    };
}
function pad(s, width) {
    return s.length >= width ? s : s + " ".repeat(width - s.length);
}
function layerLabel(row) {
    const layer = text(row.layer, "global");
    const label = text(row.project_label);
    return layer === "project" && label ? `project:${label}` : layer;
}
function grantNote(row) {
    const scope = text(row.scope, "?");
    const remaining = text(row.remaining);
    return remaining ? `${scope} ${remaining}` : scope;
}
export function formatList(found, grants) {
    const table = found.map((s) => {
        const name = text(s.name);
        const own = grants
            .filter((g) => text(g.name) === name && text(g.layer, "global") === text(s.layer, "global"))
            .map(grantNote);
        const description = text(s.description) + (s.overrides_global === true ? " (overrides global)" : "");
        return { name, layer: layerLabel(s), description, grants: own.length > 0 ? `[${own.join(", ")}]` : "" };
    });
    const nameW = Math.max(4, ...table.map((r) => r.name.length));
    const layerW = Math.max(5, ...table.map((r) => r.layer.length));
    const head = `${pad("NAME", nameW)}  ${pad("LAYER", layerW)}  DESCRIPTION / GRANTS`;
    const body = table.map((r) => {
        const tail = [r.description, r.grants].filter(Boolean).join("  ") || "-";
        return `${pad(r.name, nameW)}  ${pad(r.layer, layerW)}  ${tail}`;
    });
    return [head, ...body];
}
export function formatAudit(record) {
    const names = Array.isArray(record.names) ? record.names.filter((n) => typeof n === "string").join(",") : "";
    const parts = [
        text(record.ts, "-"),
        text(record.event, "-"),
        names || "-",
        text(record.layer) || "-",
        text(record.session) || "-",
    ];
    if (typeof record.exit_code === "number")
        parts.push(`exit=${record.exit_code}`);
    return parts.join(" ");
}
export function formatDoctor(checks) {
    const nameW = Math.max(4, ...checks.map((c) => text(c.name).length));
    const lines = checks.map((c) => `${pad(text(c.status), 4)}  ${pad(text(c.name), nameW)}  ${text(c.detail)}`);
    const problems = checks.filter((c) => c.status !== "ok").length;
    lines.push(problems === 0 ? "healthy" : problems === 1 ? "1 problem" : `${problems} problems`);
    return { lines, problems };
}
