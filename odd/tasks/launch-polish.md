# Launch polish: audit findings and step-by-step plan

Full read-only audit before sharing QBit Vault with the community (five parallel audits plus a visual check of the real Windows dialogs). No code was changed. Every phase below is a small PR (about 400 lines), test-first, with no new features.

## Specs

- S1. User (verbatim): "necesito que te tomes todo el tiempo que consideres necesario y analices el repo de manera exhautiva buscando vulnerabilidades y bugs. veas posibles mejoras (sin perder la sencilles y practicidad de uso). Mejora en la ventana emergente, mensajes, botones, etc. tambien a nivel de consola o terminal cuando pida las credenciales que sea bonito, prolijo y no contenga erroes. quiero darle mucho amor para largarlo bien y compartirlo con la comunidad. Anota todo y armamos un plan paso a paso para ir mejorandolo (sin agregarle o llenarlo de mas funcionalidades). La idea es que quede bien sencillo y simple. de facil isntlaacion, configuracion y uso, tanto en local como poder sincronizar con la nube"
- S2. Constraint: no new features. Fixes, hardening, copy and simplification only. Local-only use stays exactly as simple as today.
- S3. Owner decision 1 (verbatim): "de cada reléase". The one-line installers are served from each release (release assets), not from `main` (plan step 5).
- S4. Owner (verbatim): "continua con el plan". Step 1, live server hardening, exactly:
  - S4.1 (C-S01) `QBV_SERVER_TRUST_PROXY=N`, N = number of trusted proxies in front of the server (1 keeps today's meaning of "one proxy"). The client IP is the Nth address counted from the **right** of `X-Forwarded-For` (each proxy appends the address it received from), skipping nothing else; with fewer than N entries, or a malformed one, the IP is `RemoteAddr`. Unset or `0`: `RemoteAddr` only. Any other value: `serve` exits 2 with `error: QBV_SERVER_TRUST_PROXY must be a number of proxies (0, 1, 2...)`. Documented with the Cloudflare + Traefik case.
  - S4.2 (C-S03) Request body caps per route: 9 MiB only for `PUT /v1/vault`, `POST /v1/rekey` and `POST /v1/accounts`; 64 KiB for every other route. Over the cap: 413 with the server's existing error shape and code `too_large`, nothing stored.
  - S4.3 (C-S09) Bootstrap invite: refused unless at least 24 characters **and** at least 12 distinct characters (`aaaa…` is refused) with the existing exit-2 message extended to say so; registering it never refreshes an existing expiry (a restart while the same code is set keeps the first 24 h); `POST /v1/accounts` is rate-limited per client IP (10 per hour) with the existing 429 shape.
  - S4.4 (C-S13) An invite is claimed atomically: two concurrent `POST /v1/accounts` with the same code create exactly one account; the other gets the existing invalid-invite answer.
  - S4.5 (C-S02) Expired nonces, tokens and pending pairings are removed periodically (and pairing files on disk); pending pairings are capped (1000 at once, then 429); the rate limiter evicts expired entries instead of clearing every counter when it grows.
  - S4.6 Tests for every rule (RED first), docs (`docs/REMOTE_SYNC.md` § 10, `deploy/README.md`, `deploy/compose.yaml` comment), CHANGELOG [Unreleased]. Nothing changes for the client or for local-only users.
- S5. Step 2, visible bugs (beta.11), exactly:
  - S5.1 (V1) The Windows show dialog (recovery key, pairing/confirmation code) always shows the whole code. The text's last paragraph (after the last blank line) is the code: it goes alone in the read-only, selectable monospace box; the paragraphs before it go in the normal label above. The box is tall enough for its content (measured, not counted by logical lines). A text with one paragraph puts it all in the box. Render the dialog with the real builder and look at the screenshot (key fully visible) before calling it done.
  - S5.2 (D-B1) On every backend Enter (the default button) on a yes/no confirmation means Decline: zenity gets `--default-cancel`; kdialog shows `Decline` on its default (yes) button and `Confirm` on the other, and the answer is read accordingly; macOS and Windows already default to Decline. Tests on the built argv and the result mapping.
  - S5.3 (E-B1) `init` and `sync` no longer print `pi install npm:qbit-vault-pi` (and `--json` no longer carries `install_command`) while the extension is unpublished; the constant may stay for later. Docs (INSTALL.md § init step 6, AGENT_INTEGRATIONS.md) say the extension is not published yet, without a command to copy.
  - S5.4 (E-B2) SECURITY.md "Supported versions": the latest release is supported; older betas are not.
  - S5.5 (C-S10) The sync client never follows redirects: a 3xx answer is an error (`remote_unreachable` class, fixed message), the body is never sent to another URL. Test with an httptest server that answers 307/308 to a second server that must receive nothing.
  - S5.6 (C-S06) `remote approve`: once the server accepted the approval, the confirmation code is shown first; a failure of the roster write or of the following sync round is then a warning on stderr (exit 0), never an error that hides the code.
  - S5.7 Tests RED first for each rule, docs and CHANGELOG [Unreleased] in the same change.
- S6. Step 3, secret boundary and storage (beta.12), exactly:
  - S6.1 (A-F1) The dump guard splits the script of a shell called with options before `-c`: `-o VALUE` / `+o VALUE` and bash's `-O VALUE` / `+O VALUE` are skipped with their value, `--long` options are skipped, and the first short-option cluster that contains `c` takes the next word as the script. `bash -o pipefail -c 'printenv'`, `sh --login -c 'echo $NAME'` and `bash -O extglob -c env` are refused (`dump_command`) while a secret is injected; `bash -o pipefail -c 'echo hi'` still runs.
  - S6.2 (A-F2) While a secret is injected, `pwsh`/`powershell` with an encoded command (`-e`, `-ec`, `-en`, `-enc`, ..., `-encodedcommand`, any case, `-`/`/` prefix) is refused as `dump_command`; the pre-bash hook refuses it the same way.
  - S6.3 (A-F4) Redaction also matches each value encoded as UTF-16LE and UTF-16BE (a BOM before it is not needed to match); a granted command that writes the value in UTF-16 (PowerShell 5.1 `Out-File`) is redacted in stdout/stderr and by the post-read hook.
  - S6.4 (A-F7) `prompt --value` for a name that already exists issues a token bound to that record id; only a new record gets an empty id.
  - S6.5 (A-F12) A panic in an MCP tool handler (and in the broker op dispatch) answers the typed `internal` refusal and the server keeps serving; the panic text and stack never reach stdout or the MCP result (stderr gets one fixed line).
  - S6.6 (B-F1) The backup snapshot of the previous vault pair is written with fsync like the live files (same synced writer).
  - S6.7 (B-F2) On Linux the unlock cache is used only when `XDG_RUNTIME_DIR` is on tmpfs (statfs); otherwise there is no cache (the passphrase is asked each time), and nothing is written.
  - S6.8 (B-F3) A lock file whose mtime is more than the stale age in the future is stale too (clock skew, copied home).
  - S6.9 Tests RED first for each rule (S6.6 may be structural: the snapshot path uses the synced writer), leak battery extended for S6.3, docs (THREAT_MODEL, STORAGE, CLI where they describe these) and CHANGELOG [Unreleased] in the same change.
- S7. Step 4, dialogs with one voice (same words on Windows, macOS, Linux and the terminal; UI text stays English), exactly:
  - S7.1 (V2, D-B11) Every native dialog window is titled `QBit Vault`; the heading inside says what it is: `Secret request`, `Permission request`, `Confirm`, `Recovery key`, `Pairing code`, `Vault passphrase`, `Export passphrase`. No `qbit-vault:` prefix anywhere in dialogs.
  - S7.2 (D-B3) The permission question names who asks first: `Claude Code wants to use GITHUB_TOKEN (all projects).` then a line `Why: <reason>`; the options stay `Once: only the next command` / `Always: in this project, until you revoke it` / `Don't allow`. The manage replace options read `Replace, allow once` / `Replace, always in this project` / `Replace, but ask me before each use` / `Don't replace`.
  - S7.3 (D-B4, V5) Passphrase prompts say what they protect: unlock/init `Vault passphrase`; export `Export passphrase (protects this backup file)`, again `Type the export passphrase again`; import `Passphrase of the export file`.
  - S7.4 (D-B2) `Who: you (qbit-vault)` for every command the user runs (not `qbit-vault set`).
  - S7.5 (D-B6, V7) The multi-field form header has no `Value:` line; each box says whether it is hidden.
  - S7.6 (V3) In the Windows dialog the header lines (Who, Secret, Why, Saved in, Value) are a two-column grid (label column, value column), not space-aligned text.
  - S7.7 (V4) Buttons say the action: secret and form `Save` / `Cancel`; choose `Continue` / `Cancel`; show `Done` / `Cancel`; confirm keeps `Confirm` / `Decline`. Same labels on every backend that can set them (zenity `--ok-label`, osascript buttons, PowerShell).
  - S7.8 (V8) Windows confirm: Decline (the default, Enter) is the highlighted button; Confirm is neutral.
  - S7.9 (D-B9) One phrase for layers: text says `all projects` / `project <label>`; pickers offer `All projects` / `Only this project (<label>)` (set, import, request, prompt).
  - S7.10 (Audit D copy) Secret dialog line `Paste or type the value. The agent never sees it:` (visible field: `Type the value (shown while you type):`); terminal `Value (hidden): ` / `Value (shown while you type): `; invalid menu answer `Type a number from 1 to N, or press Enter for the default.`; timeout `No answer in time; nothing was saved.`; `No, just save the value` -> `Save it, don't allow yet`; quotes check `The value of X has quotes around it. Most keys and tokens don't, and extra characters break logins. Which one should be saved?` with `Without them (recommended)` / `Keep it as typed` / `Cancel`; no prompt available `Nobody can answer here (no terminal or desktop session). Run it from a terminal.`; unknown backend lists the valid ones.
  - S7.11 (D-B12) Ctrl-C at a terminal choose/confirm/show answers `cancelled` (exit 1) like the hidden reads, never kills the process mid-write.
  - S7.12 (D-B10, D-B14..16) kdialog-only Linux shows the recovery key and pairing code in the terminal; zenity dialogs get `--width=480`; zenity lists have no `Pick`/`Index` headers; macOS icon `note` for requests, `caution` only for removals.
  - S7.13 TUI copy: `asked in a secure prompt` (not `terminal prompt`), `hidden` (not `masked`).
  - S7.14 Tests updated/added for every text and behaviour above (RED first where behaviour changes: S7.2 who, S7.3 labels, S7.5, S7.11, S7.12 fallback); render every Windows dialog with the real builders and check the screenshots (title, heading, grid, buttons, default); docs and CHANGELOG [Unreleased] in the same change.
- S8. Step 5, first run, docs and installers from each release (beta.13, launch candidate), exactly:
  - S8.1 (S3, E-B7) The installers are release assets: the release workflow attaches `scripts/install.sh` and `scripts/install.ps1` to every release and lists them in `checksums.txt`; releases are published as regular releases (GoReleaser `prerelease: false`), so `https://github.com/QuBiit0/qbit-vault/releases/latest/download/install.sh` and `.../install.ps1` always serve the newest. README, docs/INSTALL.md and every doc that shows the one-liners use those URLs. The scripts stay in the repo (the URLs from `main` keep working).
  - S8.2 (E-B5, E-B6) The installers end with one next step: `next: run 'qbit-vault init'` (it checks the setup and tells you to restart your agents). `init` ends with `Restart your coding agents so they load QBit Vault.` when it registered or changed any host.
  - S8.3 (E-B3, E-B4, E-B18, E-B19) docs/INSTALL.md uninstall names where the installers put the binary (`~/.local/bin`, `%LOCALAPPDATA%\Programs\qbit-vault`, or the existing location) and the Windows user PATH entry with the one-line removal; `install.ps1` compares PATH entries ignoring a trailing `\` (no duplicate on re-run) and turns a GitHub API failure into `could not reach the GitHub API (rate limit or network); set QBIT_VAULT_VERSION=vX.Y.Z and try again`.
  - S8.4 (E-B8) Every GitHub Action in ci.yml and release.yml is pinned to a full commit SHA with the version in a comment; `.github/dependabot.yml` updates github-actions weekly.
  - S8.5 (E-B20) Release notes are not the commit list: GoReleaser changelog disabled; the release body links the CHANGELOG section of that version and keeps the install footer.
  - S8.6 (E-sync, C-friction 7) `qbit-vault sync` ends its human output with `(to sync secrets between devices: qbit-vault remote sync)` when the vault syncs with a server; README and docs/CLI.md have one callout explaining the two commands.
  - S8.7 Docs: a short copy-pasteable manual example in docs/CLI.md (`set` -> `grant --session demo --scope once` -> `exec --session demo --secret NAME -- <cmd>`); docs/REMOTE_SYNC.md and docs/INSTALL.md describe what to do when the sync server is lost or wiped (local vaults keep working; `remote logout` on each device, `remote register` on one, `remote join` the rest; recovery keys of the old server no longer apply; keep an `export`); README says in one bold line that sync is optional and local use needs no account.
  - S8.8 (E-B9, E-B10, E-B11, E-B16, E-B17) Actionable errors: an existing master key on init -> `a master key already exists for this vault home; run 'qbit-vault doctor'`; host registration failures end with `; run 'qbit-vault doctor' for details`; flag typos add `see 'qbit-vault <command> --help'`; the TUI says `Re-run the install command to upgrade` instead of `Update · planned / Phase 5`; internal slice numbers removed from comments.
  - S8.9 Tests RED first for behaviour (S8.2 init line, S8.3 PATH compare and API error, S8.6 sync line, S8.8 messages; installers through scripts/install_test.sh and install_test.ps1), structural checks for workflows/goreleaser (`goreleaser check` if available), docs and CHANGELOG [Unreleased] in the same change.

## How to read the findings

IDs keep the audit they came from: **A** secret boundary, **B** crypto and storage, **C** sync and server, **D** dialogs and terminal, **E** install/CLI/docs, **V** visual check of the rendered Windows dialogs. Severity: P0 = before telling anyone, P1 = before the announcement, P2 = polish soon, P3 = when convenient. "Confirmed" means re-checked against the code by the parent session; the rest comes from careful reading and must get a RED test before any fix.

## Findings

### P0: fix before sharing

| ID | Where | Problem | Fix |
| --- | --- | --- | --- |
| V1 (confirmed, rendered) | `internal/prompt/native_powershell.go` psShowText | **The recovery key is not visible on Windows.** The box height counts logical lines (3), the explanation wraps to 5 rows, the box has no scrollbar: the key is cut off. Regression of beta.8. | Explanation in the label, the key alone in the selectable monospace box; or measure with `TextRenderer.MeasureText`. Render test + screenshot. |
| D-B1 (confirmed) | `native_tools.go:39` zenity `--question`, `:95` kdialog `--yesno` | **Enter confirms on Linux** (zenity, kdialog) but declines on macOS and Windows. A stray Enter removes a secret, deletes the dotenv file, creates a grant or links a project. | zenity `--default-cancel`; kdialog equivalent or swap labels so the default is Decline. |
| C-S01 (confirmed) | `internal/server/server.go:198` clientIP | Trusts the **leftmost** `X-Forwarded-For` (client-controlled). `deploy/compose.yaml` sets `QBV_SERVER_TRUST_PROXY=1`. Rate limits on auth, pairing and recovery can be bypassed with a forged header, or (behind Cloudflare + Traefik) every user can share one bucket. Affects the live server. | Take the rightmost hop added by the trusted proxy (configurable hop count); verify what Traefik/Cloudflare send on the live server first. |
| E-B1 (confirmed) | `internal/hosts/pi/pi.go:41`, `internal/cli/init.go` | `init` prints `pi install npm:qbit-vault-pi` on every run; the package does not exist (Phase 4). A new user copies it and gets an npm error. | Do not print it until the package is published. |
| E-B2 | `SECURITY.md` | "Supported: main until the first tagged release", releases beta.2-beta.10 exist. | "Supported: the latest release." |

### P1: before the announcement

**Secret boundary (A)**

| ID | Where | Problem | Fix |
| --- | --- | --- | --- |
| A-F1 (confirmed) | `internal/dumpguard/binaries.go:62-81` scriptOf | `bash -o pipefail -c 'printenv'` and `sh --login -c '…'` are not split, so the inner dump runs (raw value still redacted, encodings not). | Skip `-o/+o VALUE` and `--long` options while looking for `-c`. |
| A-F2 | `binaries.go:84`, `hook/prebash.go:251` | `pwsh -EncodedCommand <base64>` is not inspected. | Refuse `-e/-ec/-enc/-EncodedCommand` while secrets are injected. |
| A-F4 | `internal/redact/redact.go:172` | No UTF-16 forms: Windows PowerShell 5.1 `>`/`Out-File` writes UTF-16LE, the post-read hook does not see the value. | Add UTF-16LE/BE (and BOM) variants of each value. |
| A-F7 | `internal/cli/promptcmd.go` (`--value`) | Prompt token issued with an empty record id for an existing name redeems against a replaced record. | Keep the record id when the record exists. |
| A-F12 | `internal/broker`, `internal/mcp/server.go` | No `recover`: a panic kills the MCP server and prints a Go trace. | Recover in the MCP handler, answer `internal`. |

**Crypto and storage (B)**

| ID | Where | Problem | Fix |
| --- | --- | --- | --- |
| B-F1 | `internal/vault/atomic.go:187` | Backups (the previous consistent pair) are written without fsync; a power loss can leave a torn restore point. | `writeSynced` for the snapshot. |
| B-F3 | `internal/lockfile/lockfile.go:111` | A lock with a future mtime (clock skew, copied home) is never stale: every command says "vault is busy" forever. | Treat `age < -StaleAfter` as stale too. |
| B-F2 | `internal/keychain/cache.go:26` | Unlock cache trusts any existing absolute `XDG_RUNTIME_DIR`; on a disk path the master key lands on disk for 8 h. | Require tmpfs (statfs magic) or skip the cache. |

**Sync and server (C)**

| ID | Where | Problem | Fix |
| --- | --- | --- | --- |
| C-S10 (confirmed) | `internal/remote/client.go:114` | The client follows redirects: a 307/308 sends sealed blobs to another host (invariant 8). | `CheckRedirect` returning `http.ErrUseLastResponse`. |
| C-S03 | `server.go` logged, `s5.go` | Unauthenticated routes accept and decode bodies up to 9 MiB. | Per-route caps (64 KiB small routes). |
| C-S02 | `s5.go:66`, `server.go:377,423`, `limit.go` | Pairings, nonces and tokens are never swept; the limiter clears all counters at 100 000 keys. | Periodic sweep; global cap on pending pairings. |
| C-S09 | `bootstrap.go:23,33`, `server.go:289` | Bootstrap code only length-checked, its 24 h expiry is refreshed on every start, `POST /v1/accounts` has no rate limit. | Require >=128 bits (hex/base64), keep the first-seen time, rate-limit account creation. |
| C-S13 | `server.go:301` | Two concurrent requests with the same invite both create accounts. | Atomic claim (rename) of the invite. |
| C-S06 | `internal/cli/remoteacct.go` approve | A sync error after the server accepted the approval returns before the confirmation code is shown; the new device is registered but cannot finish. | Show the code first, make the post-approval sync non-fatal. |

**Dialogs and terminal (D, V)**

| ID | Where | Problem | Fix |
| --- | --- | --- | --- |
| D-B3 | `capture.go:118` allowQuestion, `request.go:210` | The permission question does not say **who** asks (the capture dialog does). | "Allow Claude Code to use GITHUB_TOKEN (all projects)?" |
| D-B4 / V5 | `exportcmd.go:85`, `dialogs.go:25`, `prompt.go:243` | Export asks "Vault passphrase": users may reuse the wrong secret. | A label on `Passphrase`: "Export passphrase (protects this backup file)". |
| D-B2 | `prompt.go:381` | "Who: you (qbit-vault set)" also shown by `remote register/join/recovery-key`. | "you (qbit-vault)". |
| D-B6 / V7 | `form.go:52` | Multi-field form header says "hidden as you type" even for visible fields. | Drop the Value line from the shared header (each box says it). |
| D-B10 | `show.go:41`, `remote.go:122` | kdialog-only Linux cannot show the recovery key; should fall back to the terminal. | Treat kdialog as no `Shower`. |

**Install, CLI, docs (E)**

| ID | Where | Problem | Fix |
| --- | --- | --- | --- |
| E-B5/B6 | `install.sh`/`install.ps1` last line, `init.go` summary | Three "next" options and no "restart your agent" after `init`. | One next step: `qbit-vault init`; `init` ends with "restart your agents to load QBit Vault". |
| E-B3/B4 | `docs/INSTALL.md` Uninstall, `docs/CLI.md` uninstall | Says "delete it from go/bin"; installers use `~/.local/bin` or `%LOCALAPPDATA%\Programs\qbit-vault` and add a user PATH entry nothing removes. | Document all locations and the PATH entry. |
| E-B8 | `.github/workflows/*.yml` | Actions pinned to floating majors in a secrets project. | Pin to commit SHAs (Dependabot updates them). |
| E-sync | README, CLI.md | `qbit-vault sync` (agent registrations) vs `qbit-vault remote sync` (devices) share a verb. | Docs callout + `sync` prints "for devices: qbit-vault remote sync". No rename. |
| E-exec | `docs/CLI.md` | No copy-pasteable manual example of set -> grant -> exec. | Add one short example. |
| C-wiped | `docs/REMOTE_SYNC.md`, `INSTALL.md` | No documented procedure for a lost or wiped server. | "logout everywhere, register once, join the rest" (as answered to the user). |

### P2: polish (copy, consistency)

- **V2/D-B11** Titles: `QBit Vault: …` vs `qbit-vault: …` (show dialog); heading repeats the window title. One brand, heading without the prefix.
- **V3** Header labels "Who / Secret / Why / Saved in / Value" are space-aligned for the terminal and misaligned in the proportional dialog font: render them as a two-column grid.
- **V4/D-#42-45** Buttons: secret dialog `Save`/`Cancel`; show dialog `I saved it` (not OK/Cancel); choose `Continue`/`Cancel`.
- **V8** Confirm dialog styles Confirm as primary while Enter declines: style Decline as the default, Confirm neutral (red for removals).
- **D-B9** Layer wording: one function and one phrase everywhere: "all projects" / "only this project (label)".
- **D copy table** (Audit D items 1-45): shorter, consistent texts. Key ones: "Paste or type the value. The agent never sees it:"; tty "Value (hidden): "; `invalid choice` -> "Type a number from 1 to N, or press Enter for the default."; `No, just save the value` -> "Save it, don't allow yet"; manage options "Replace, allow once" / "Replace, but ask me before each use"; quotes check "The value of X has quotes around it… Which one should be saved?"; `prompt timed out` -> "No answer in time; nothing was saved."; TUI "asked in the terminal prompt" -> "asked in a secure prompt"; "masked" -> "hidden"; pairing "Confirmation code" title consistent with the README.
- **D-B12** Ctrl-C in cooked terminal reads (choose/confirm/show) should return `cancelled`, not kill the process.
- **D-B14/B15/B16** zenity `--width=480`, icons (`note` for requests, `caution` for removals), no `Pick/Index` headers.
- **E-B9/B10/B11** Actionable errors: untyped "a key already exists…", host failures without "run 'qbit-vault doctor'", flag typos without "see --help".
- **E-B16/B17** TUI "Update · planned / Phase 5" -> "Re-run the install command to upgrade"; remove internal slice numbers from comments.
- **E-B18/B19** Installer: PATH duplicate check with trailing backslash; GitHub API rate-limit message on Windows.
- **E-B20** GoReleaser notes from commits: link the CHANGELOG section instead.
- **C friction** Origin must match byte for byte (`https://Vault.x` or `:443` -> generic "refused"): normalize and say "server URL mismatch". Join: default the device label to the hostname, fold the consent into the label step. Register: recovery-key check loop has a dead end after 5 tries. `remote status` exits 1 on warnings (pending push, conflicts).

### P3: hardening and edge cases

- **A-F3** Pre-bash hook bypassable (`cp` binary, `eval` of decoded text): refuse non-literal `eval`/encoded shells; document the hook as best effort in THREAT_MODEL (the real boundary is the out-of-band prompt).
- **A-F5/F6** POSIX tree kill reaches the process group only; doc says "no descendant outlives Run". Fix the doc; kill before Wait.
- **A-F8** Project identity is a path: a different repo cloned at the same path inherits layer and grants. Document (or bind to origin).
- **A-F9** Cooldown keyed by session; add a short per-name cooldown.
- **A-F10/F11** Env name denylist (`LD_PRELOAD`, `BASH_ENV`, `PATH`), cap the dump-guard compile cache.
- **A-F13** request -> store not atomic against a concurrent `set` (confirm first).
- **B-F4** Missing `audit.head` disables truncation detection: write the head at creation and treat a missing one as `head_mismatch`, or state the limit (owner decision).
- **B-F5..F18** restore hides rekey-recovery errors; staged key promote without retry on Windows; temp files `O_EXCL`; `retired.enc` no rollback counter; Windows empty-DACL/owner check; racy stale-lock break; Setup ignores keychain errors; nits.
- **C-S04** Joiner has no version floor (can accept an old version once). **C-S05** conflicts pruned after 30 days/100 silently. **C-S07** orphan server device blocks rekey/revoke. **C-S08** a revoked device cannot rejoin as REMOTE_SYNC § 4.5 says. **C-S11/S12/S15/S16/S17** pairing overwrite, rekey writes before validation, recovery-key prefix parse, origin normalization, token device-id regex.

### Looks solid (all five audits)

`secret.Secret` never prints values; redaction core (leftmost-longest, hold-back across writes, fail closed); exec output always redacted, values never in argv or parent env; Windows job-object tree kill; strict broker decoding; grants (once consumption under lock, hashed single-use prompt tokens, sensitive = once only); nonces/AAD/rollback counters; Argon2 bounds before derivation; atomic writes; audit chain; recovery key (160-bit, never on stdout); pairing fingerprint + HMAC confirmation code; server paths regex-validated; distroless non-root read-only container; dialog escaping (quotes, `&`, `<tag>` rendered literally, checked visually).

## Plan (step by step)

Each step is one PR, test-first (RED then GREEN), docs in the same PR, CI green on the four jobs. Releases only at the marked points.

| Step | Contents | Release |
| --- | --- | --- |
| 1 | **Live server** (C-S01, C-S03, C-S09, C-S13, C-S02): rightmost trusted hop, per-route body caps, bootstrap code >=128 bits without refresh, rate-limited and atomic account creation, sweeps. Verify the forwarded headers on the live Dokploy server before and after. | server redeploys on merge |
| 2 | **Visible bugs** (V1, D-B1, E-B1, E-B2, C-S10, C-S06): recovery key visible, Enter declines everywhere, no pi install line, SECURITY.md, no redirects, approve shows the code first. | **beta.11** |
| 3 | **Secret boundary and storage** (A-F1, A-F2, A-F4, A-F7, A-F12, B-F1, B-F2, B-F3). | **beta.12** |
| 4 | **Dialogs, one voice** (D-B2, D-B3, D-B4, D-B6, D-B10, V2-V4, V8, D-B9, D copy table, D-B12): same words on Windows, macOS, Linux and terminal; who asks in every permission question; export passphrase labelled. Render every dialog again and check screenshots. | |
| 5 | **First run and docs** (E-B5/B6, uninstall, sync naming callout, manual exec example, wiped-server procedure, actionable errors, TUI planned text, comments, installer robustness, release notes, SHA-pinned actions). | **beta.13** = launch candidate |
| 6 | **Sync friction** (origin normalization, join label default, register confirm loop, remote status exit code) and **C-S04..S08**. | beta.14 |
| 7 | **P3 hardening** as time allows. | |

## Decisions for the owner

1. Installers served from `main` (today) or published as release assets (`releases/latest/download/install.sh`): main is simpler and fixes reach everyone at once; release assets pin the script to a reviewed version.
2. Missing `audit.head` (B-F4): enforce (head written at init, missing = mismatch) or document the limit.
3. `remote status` exit code with warnings: keep 1 or return 0 and keep warnings in the output.
4. Passphrase mismatch: end the command (today) or ask again (up to 3 tries).
5. README tagline "by qbitdev" vs GitHub owner QuBiit0: intended?
6. The four same-day betas in the CHANGELOG stay as they are (published releases are never rewritten); a short note at the top can explain the beta cadence.

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| LP0 | S1, S2 | audits (5 explorers) + visual check | (this document) | done |
| LP1 | S4 | worker | | done, awaiting review |
| LP2 | S5 | worker + parent correction | ab worker commit + 00799f7 (kdialog) | done, beta.11 |
| LP3 | S6 | worker + parent correction | 076a8da, 80ed221, d3ba4df | done, beta.12 |
| LP4 | S7 | worker | 9b222e6, 5631041 | done (ships in beta.13) |
| LP5 | S8 | worker | | done, awaiting review |
| LP6-LP7 | S1-S3 | plan steps 6-7 | | pending |

## Log

- L1. User request verbatim in S1 (owner away; "tomate todo el tiempo"). Five read-only audits ran in parallel (secret boundary, crypto/storage, sync/server, dialogs/terminal, install/CLI/docs), plus eight Windows dialogs rendered with the real builders and edge cases. P0 items were re-checked against the code: C-S01 (`server.go:198-202` takes the first XFF entry), D-B1 (zenity `--question` and kdialog `--yesno` default to Confirm), C-S10 (`client.go:114` http.Client without CheckRedirect), A-F1 (`scriptOf` stops at `-o pipefail`), E-B1 (`pi.go:41`), V1 (screenshot: the key is cut off). No code changed.
- L2. Owner chose installers from each release (S3) and asked to continue the plan (S4). Step 1 started on branch fix/server-hardening.
- L3. Step 1 merged (PR #22); live server healthy after redeploy. QBV_SERVER_TRUST_PROXY kept at 1 behind Cloudflare + Traefik (Traefik rewrites the header unless it trusts Cloudflare). Step 2 started on branch fix/visible-bugs.
- L3. LP2 (S5.1-S5.7) done by worker, not committed. RED first for each rule, then GREEN. S5.1 `splitShown` + `psShowText` (code alone in the box, height from `TextRenderer.MeasureText`; screenshot of the real builder at 1440-style render shows the whole key). S5.2 zenity `--default-cancel`, kdialog labels swapped (`Decline` on yes) and `classify` reads confirmations swapped. S5.3 `init` no longer prints or carries the Pi install command (constant kept); docs say the extension is unpublished. S5.4 SECURITY.md. S5.5 `CheckRedirect: http.ErrUseLastResponse` and a 3xx maps to `ErrUnreachable`. S5.6 `remote approve` shows the code right after the server accepts; roster and sync failures are warnings (new `warnApproveSync`). Left for the owner: `e2e/hosts/scenario.sh:99` still expects the old install line (outside this task's edit surface); `docs/GENTLE_SHELL_EXTENSION.md:5`, `docs/ROADMAP.md:76`, `docs/TESTING.md:43` still mention the printed line.
- L4. Step 2 review: a CRITICAL finding (the kdialog label swap made Escape/close confirm) was corrected in 00799f7: kdialog confirmations are a list with Decline preselected. Review approved after targeted validation. Released as 0.1.0-beta.11.
- L5. beta.11 released (9 assets), this machine upgraded, doctor healthy. Step 3 started on branch fix/boundary-storage.
- L6. LP3 (S6.1-S6.8) done by worker, not committed. RED first for each rule, then GREEN. S6.1 `scriptOf` skips `-o/+o/-O/+O VALUE` and `--long` options before `-c`. S6.2 `encodedPowerShell` in `Match`/`MatchRaw` and `encodedCommand` in the pre-bash hook. S6.3 `utf16Form` (LE and BE) in `addEncodings`; leak battery gets a UTF-16 child and needles. S6.4 `prompt --value` keeps the existing record id and `set` redeems with it. S6.5 `recover` in `broker.Handle` and the MCP handler, one fixed stderr line (`broker.PanicLine`). S6.6 snapshot uses `writeSynced` (seam `syncFile`). S6.7 `memoryBacked` seam, statfs tmpfs/ramfs on Linux, true elsewhere. S6.8 `stale()` also true for an age below minus the stale age. Docs: THREAT_MODEL (R2, R5), STORAGE, CLI, AGENT_INTEGRATIONS, TESTING, CHANGELOG.
- L7. Step 3 review: two CRITICAL findings (encoded PowerShell after an option with a value, `-ExecutionPolicy Bypass -EncodedCommand`, passed the guard and the hook) corrected in d3ba4df and validated. Advisory follow-ups for step 7: R1-psenc-valued-option-bypass and R4-encoded-ps-option-value (binaries.go:119), R3-scriptof-valued-long-options (bash long options with a value before -c), R3-set-replace-grant-id (secrets.go:438). Released as 0.1.0-beta.12.
- L8. beta.12 released, this machine upgraded, doctor healthy. Step 4 started on branch feat/dialogs-one-voice.
- L9. LP4 (S7.1-S7.14) done by worker, not committed. RED first for who in the question (S7.2), passphrase labels (S7.3), form header (S7.5), Ctrl-C at cooked reads (S7.11, `console.interrupts` seam) and the kdialog show fallback (S7.12, `native.open` seam). `Backend.Passphrase` takes a `PassphraseRequest` (heading, label, again, confirm; keychain's `PassphraseFunc` unchanged). Dialogs carry a heading, request rows (Windows grid), button labels and one title `QBit Vault`; `prompt.Escape` keeps an agent's reason on one line because `Choose`/`Confirm` now keep layout line breaks. Windows dialogs rendered with the real builders to PNG and checked. Left for the owner: `e2e/docker-test.sh:252` waits for `SHOW Confirmation code` (now `SHOW Pairing code`); `docs/TESTING.md:67` and `contracts/secrets-broker/v1/CONTRACT.md:162` still quote `prompt timed out` and the old replace options.
- L10. Step 4 reviewed as two candidates (the whole change exceeded the review context budget): prompt commit approved (advisory R3-001..005 on dialogs.go/prompt.go/scripted.go), cli commit approved (advisory: pairing heading reuse, dead session branch in replaceOption, stale log line). Screenshots of six Windows dialogs re-rendered and checked by the parent. Leftovers fixed by the parent: e2e/docker-test.sh pairing transcript, TESTING.md timeout text, CONTRACT.md replace options.
- L11. Step 4 merged (PR #25). Step 5 started on branch feat/first-run. Decision taken to serve installers from releases/latest: releases become regular releases (not pre-releases) from beta.13 on, since releases/latest skips pre-releases; the -beta in the version still says what it is.
- L12. LP5 (S8.1-S8.8) done by worker, not committed. RED first for S8.2 (installer next step, `init` restart line), S8.3 (`QBIT_VAULT_USER_PATH` seam for the trailing-backslash compare, API failure message), S8.6 (`sync` device hint) and S8.8 (`init` key-exists and host failure messages, flag-typo hint, TUI Update text). S8.1/S8.5 goreleaser: `prerelease: "false"`, changelog disabled, header links CHANGELOG, both installers in `checksum.extra_files` and `release.extra_files`; S8.4 four actions pinned to SHAs plus dependabot; structural checks in `release_files_test.go`. `goreleaser` is not installed here, so `goreleaser check` did not run (YAML parsed with yaml.v3). Docs: README, INSTALL (uninstall locations and PATH removal, wiped server), CLI (manual example, two-sync callout), REMOTE_SYNC § 4.7. Left for the owner: the first release with regular (non-pre) status needs `install.sh` on that release before the README one-liners work.
- L12. Step 5: goreleaser check and a full snapshot build passed (install.sh and install.ps1 in checksums.txt). Review approved; R1-001 (a test PATH override could be written into the real user PATH) fixed before release. Released as 0.1.0-beta.13, the first regular (non pre-release) release, so releases/latest/download serves the installers.
