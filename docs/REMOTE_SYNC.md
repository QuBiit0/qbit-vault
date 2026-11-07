# Remote sync: one vault on several machines

Status: built (Phase 2S: the client in `internal/remote` and the commands, `internal/merge`, the server in `internal/server`; the Docker sync battery `bash e2e/docker-test.sh` passes). Not built: a published server image and release jobs (Phase 5), and the `config.yaml` tunables mentioned below (budgets and intervals are constants). Requirement IDs `R-SYNC-*` live in `PRD.md` § 5.10; this document is the normative protocol behind them.

qbit-vault can keep the same vault on several machines through **`qbit-vault-server`**, a small self-hosted service. The server is **zero-knowledge**: it stores ciphertext, public keys and counters, and has nothing that decrypts them. Sync is opt-in; a vault that never runs `qbit-vault remote register` makes no network call (AGENTS.md invariant 8).

## 1. What syncs and what stays on the machine

| Data | Syncs | Why |
| --- | --- | --- |
| Secret records of every layer (values and metadata) | yes, encrypted | the point of sync |
| Project layer identity (`id`, `label`, normalized origin URL) | yes, encrypted | so another machine can link the same project |
| Project roots | per device, inside the encrypted body; each device writes only its own entry | paths differ between machines |
| Tombstones and conflicts | yes, encrypted | deletions propagate; nothing is lost silently |
| Device roster (labels, public keys, revocations) | yes, encrypted | devices authenticate each other through it, not through the server |
| Grants (`grants.enc`), pending prompt tokens | **no** | a permission is a decision about one machine and one session |
| Audit log (`audit.jsonl`) | **no**; only an encrypted digest of its head (§ 8) | R-AUD-03 |
| `config.yaml`, `bindings.yaml`, `dumpguard.yaml`, `state.json` | **no** | machine settings |

## 2. Keys

All derivations use HKDF-SHA256 with salt `qbit-vault/v1` and the info string shown. All symmetric encryption is XChaCha20-Poly1305 with a random 24-byte nonce and canonical-JSON AAD, as in `STORAGE.md`.

| Key | Size | Where it lives | Purpose |
| --- | --- | --- | --- |
| `MK` master key | 32 B | OS keychain or `key.enc` (unchanged) | seals `vault.enc`, `grants.enc`, and everything below |
| `RVK` remote vault key | 32 B | derived: `HKDF(MK, "remote-vault")` | seals the remote vault object |
| `AAK` audit anchor key | 32 B | derived: `HKDF(MK, "audit-anchor")` | seals audit anchors |
| `PCK` pairing confirm key | 32 B | derived: `HKDF(MK, "pairing-confirm")` | computes pairing confirmation codes |
| `DK` device secret | 32 B random | `remote/device.enc`, sealed with `MK` | one per device |
| device signing key | Ed25519 | seed `HKDF(DK, "device-sign")` | authenticates the device to the server and signs key envelopes |
| device box key | X25519 | `HKDF(DK, "device-box")`, clamped | receives key envelopes |
| `RK` recovery key | 20 B random | **only with the user** (written down) | recovers the vault on a new machine with no other device |
| recovery lookup id | 16 B | `HKDF(RK, "recovery-id")` | lets the server find the account from `RK` alone |
| recovery auth secret | 32 B | `HKDF(RK, "recovery-auth")`; the server stores its SHA-256 | proves possession of `RK` to the server |
| recovery wrap key | 32 B | `HKDF(RK, "recovery-wrap")`; never sent | seals the recovery envelope |

The **generation** `g` counts master keys: 1 at registration, +1 at every rekey. It is in the AAD of every remote object, so an object sealed under an old key is recognizably old.

**Recovery key format.** 20 random bytes in Crockford base32 (32 characters, case-insensitive, `I L O` read as `1 1 0`; the `QVR1-` prefix is optional when typing and is told apart from a body that starts with `QVR1` by length), shown as `QVR1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`. It is high-entropy by construction, so the server cannot brute-force it the way it could a password.

**Device identity.** `device_id` is 16 random bytes (hex), created with the vault (or at the schema-2 migration) and stored in `state.json`; it names the device in the roster and in project roots even when sync is off. The **pairing code** is the first 80 bits of `SHA-256("qbit-vault/pairing/v1" || sign_pub || box_pub)` in Crockford base32, shown as `XXXX-XXXX-XXXX-XXXX`; it fingerprints the new device's public keys.

## 3. Objects the server stores

| Object | Content | Sealed with | AAD |
| --- | --- | --- | --- |
| remote vault | the plaintext body (STORAGE § Plaintext body, schema 2), padded with zero bytes after the JSON to a multiple of 4 KiB | `RVK` | `{format: "qbit-vault-remote/1", cipher, account_id, generation, version, writer, created_at}` |
| key envelope (one per device per generation) | `{generation, master_key}` | X25519 sealed box to the device's box key (ephemeral key, `HKDF(shared, salt = eph_pub ‖ box_pub, "key-envelope")`), then signed with the issuing device's Ed25519 key over AAD ‖ eph_pub ‖ ct | `{format: "qbit-vault-keyenv/1", account_id, device_id, generation, issuer}` |
| recovery envelope | `{generation, master_key}` | recovery wrap key | `{format: "qbit-vault-recoveryenv/1", account_id, generation}` |
| audit anchor | `{device_id, seq, line, at}` (§ 8) | `AAK` | `{format: "qbit-vault-anchor/1", account_id, device_id, generation}` |
| device record (cleartext) | `device_id`, `sign_pub`, `box_pub`, created, last seen, revoked | — | used only to authenticate requests |

The server keeps the **last 10 versions** of the remote vault per account, so a client can list and restore earlier states (§ 7.6). Everything the server holds is ciphertext or public keys; backing up its `/data` volume is safe.

## 4. Account lifecycle

Every command in this section except `remote status`, `remote devices` and `remote history` is **user-only**: it asks its questions and shows its codes through the prompt backend (native dialog when a desktop session exists, else the controlling terminal; `AGENT_INTEGRATIONS.md` § Native capture dialog), never reads codes or keys from arguments or stdin, and never writes the recovery key or a confirmation code to stdout, stderr, `--json` output or the audit log. With no prompt backend available they are refused with `not_model_callable`. Host hooks refuse them in an agent's shell (phase 3). See THREAT_MODEL L26–L28.

### 4.1 Register the first device: `qbit-vault remote register --server URL`

1. Refuse a URL that is not `https://`, except `http://` to `localhost`, `127.0.0.1` or `[::1]`. `GET /v1/info` must answer API major 1. The URL is reduced to its **origin** before it is used or signed: scheme and host in lower case, the default port dropped (`:443` for https, `:80` for http), no path, no trailing slash. The server normalizes its `QBV_SERVER_PUBLIC_URL` the same way, so `https://Vault.example.com:443/` and `https://vault.example.com` are one server.
2. Prompt (out of band): the **invite code** (masked) and the confirmation *"Sync this vault to `<host>`? Secrets are encrypted on this device before upload; the server can never read them."*
3. Generate `account_id` (16 random bytes), `DK`, `RK`. The existing `MK` becomes the account key; `generation` = 1.
4. Seal the remote vault (version 1), the device's key envelope (issuer = itself) and the recovery envelope. `POST /v1/accounts`.
5. Save the device state (step 6) with the flag `recovery_unconfirmed`, then show `RK` out of band with *"Write this recovery key down and keep it offline. It is the only way to open your vault on a new machine if you lose access to every device."* and ask the user to type its last four characters to confirm they saved it. A wrong answer shows it again, as many times as it takes, until it is right or the user cancels; a cancel leaves the account registered, `remote status` keeps warning `recovery key not confirmed`, and the message says `run 'qbit-vault remote recovery-key --rotate' to get a new recovery key`.
6. Write `remote/device.enc`, `remote/base.enc` and `state.json.remote`; append the audit record `remote` (`detail: "registered"`).

### 4.2 Add a device by pairing: `remote join --server URL` + `remote approve`

On the **new** device:

1. Create `DK` if absent. `POST /v1/pairings {code, sign_pub, box_pub}` (unauthenticated, rate-limited, expires in 10 minutes).
2. Print the pairing code (it is a public-key fingerprint, safe on stdout) and *"On a device that already syncs, run `qbit-vault remote approve`."* Poll every 2 s until approved, expired or Ctrl-C.

On an **existing** device, `qbit-vault remote approve`:

3. Prompt (out of band) for the pairing code. `GET /v1/pairings/{code}`; recompute the fingerprint of the returned keys and refuse (`pairing_failed`) unless it equals the code typed, so the server cannot substitute its own device key.
4. Prompt (out of band) for the device name, which is also the consent: *"Add this device to your vault on `<host>`? It will be able to read every secret. Name it, or leave this empty for `device <n>`."* Enter (an empty answer) takes the default `device <n>`, n = roster size + 1; Cancel refuses and nothing is sent. Approving asks two things: the code and the name.
5. Pull and merge (§ 7), seal a key envelope for it (issuer = this device), `POST /v1/pairings/{code}/approve`. Once the server accepted, nothing below is an error: the code (step 6) is shown first, then the device is added to the roster and pushed (a refused approval leaves no entry); a failure of the roster write or of that sync round is a warning on stderr and the exit code stays 0.
6. Show the **confirmation code** out of band: the first 40 bits of `HMAC-SHA256(PCK, code ‖ device_id ‖ eph_pub)` in base32, `XXXX-XXXX`, with *"Type this code on the new device."*

Back on the **new** device:

7. The poll returns `{account_id, envelope, issuer}`. Decrypt the envelope, compute the confirmation code from the received `MK` and ask the user (out of band) to type the code shown on the other device. A mismatch wipes the received key, deletes the device on the server and fails with `pairing_failed`: the server tried to plant a master key of its own, or the user typed the code of another pairing. The server cannot compute the code because it never holds `MK`.
8. Adopt `MK` on the existing local vault (`join` needs `init` first): stage it in the keychain (or `key.enc` under the current passphrase), re-seal the local files and retire the old key as `rekey` does (§ 4.4), write `device.enc`, pull, merge the local vault into the account (§ 4.4), push, and audit `remote` (`detail: "joined (pairing)"`).

### 4.3 Recover on a new machine: `remote join --server URL --recovery`

1. Prompt (out of band, masked) for `RK`. Derive lookup id, auth secret and wrap key.
2. `POST /v1/recovery/token {lookup_id, auth}` returns a short-lived token scoped to recovery; `GET /v1/recovery/envelope`; decrypt with the wrap key (AEAD failure = `remote_auth`, *"recovery key not recognized"*).
3. Register the device with the recovery token, add it to the roster with `added_by: "recovery"`, then continue as step 8 above (`detail: "joined (recovery)"`).

Every other device that later sees a new roster entry appends an audit `warning` (`detail: "device added: <label> via pairing|recovery"`) and `remote status` lists it, so an unexpected recovery is visible.

### 4.4 Joining with secrets already on the machine

If the local vault is not empty, the confirmation of `join` says *"N local secrets will be added to the synced vault on `<host>`."* The join merges with an empty base (every local and remote record is kept; a key present on both sides with different content becomes a conflict, § 7.4), re-seals the local files with the account `MK` and keeps the old local key in `keys/retired.enc` so local backups stay restorable (STORAGE § Retired keys).

### 4.5 Revoke a device: `remote revoke-device DEVICE_ID`

A revoked device still knows the current `MK`, so revocation always **rotates the master key**:

1. Confirm out of band (label, last sync time).
2. Pull and merge. Mark the device `revoked_at` in the roster.
3. Generate `MK'` (generation `g+1`) and a new `RK'`. Seal the body under `RVK'`, a key envelope for every non-revoked device (issuer = this device) and a recovery envelope under `RK'`.
4. `POST /v1/rekey {base_version, generation, blob, envelopes, recovery, revoke: [DEVICE_ID]}` is one atomic transaction: the server stores everything, deletes the revoked device and its tokens, and refuses the call with 409 if `base_version` is stale (restart from step 2).
5. Re-seal `vault.enc`, `grants.enc`, `device.enc`, `base.enc` with `MK'`; replace the keychain entry; move the old key to `keys/retired.enc`.
6. Show `RK'` out of band as in § 4.1 step 5; the old recovery key no longer works.

Other devices see generation `g+1` on their next pull (the generation in the cleartext AAD of the version is only a hint to try the swap), fetch their envelope (`GET /v1/keys/self`), and accept it only if its issuer is a device of their **local** roster that is not revoked and its signature, AAD (account, this device, generation, issuer) and the decrypted remote vault all verify (otherwise `remote_auth` and the device keeps its key); then they swap keys the same way. The revoked device gets `device_revoked` from the server, turns sync off and keeps its local copy: revocation cannot wipe a machine, so credentials that device held must be rotated at their provider (THREAT_MODEL R11).

`qbit-vault rekey` with sync enabled runs steps 3–6 without revoking anyone.

**A device that missed a rotation.** The issuer check uses the local roster on purpose, so a server cannot vouch for a device of its own. The cost: a device that was offline while the roster gained a device which then issued the next rotation does not know that issuer and refuses the envelope (`remote_auth`). It keeps its local vault and key; add it again with `remote join` (pairing or recovery).

**Order and crash safety.** After step 2 (a round that pushes everything this device has) the order is: build `MK'`, `RK'` and every object in memory; set `recovery_unconfirmed` in `state.json` (pessimistic, put back if the call fails); `POST /v1/rekey` (step 4, the only step that changes the account); the local swap of step 5 through the staged path of `rekey` (stage, `vault.Rekey`, promote), then `device.enc` and `base.enc`; then step 6. A failure or 409 before the call changes nothing on this device. A crash after the call leaves the server on `g+1` while this device is still on `g`, but the server holds this device's own key envelope for `g+1` (issuer = itself), so the next round runs the swap below with the envelope from `GET /v1/keys/self`; a crash inside the local swap is finished by the next command that opens the vault (the staged key) and by the same swap, which skips the re-seal when the key already is the new one, while `device.enc` and `base.enc` are re-sealed from `keys/retired.enc`. The new recovery key is lost only if the process dies before step 6 shows it: `remote status` keeps warning and `remote recovery-key --rotate` replaces it. The local swap is never done first, because a failed call would then leave this device on a key the account never had.

### 4.6 Other commands

- `remote recovery-key --rotate`: new `RK`, new recovery envelope, old one deleted on the server. For a lost or exposed recovery key while a device still works. It is `PUT /v1/recovery {generation, lookup_id, auth, envelope}` at the current generation (409 when the account key changed meanwhile); the master key and the vault do not change. When the master key may be exposed too, run `rekey`, which replaces both.
- `remote logout`: confirm, delete this device on the server (best effort), remove `remote/` and `state.json.remote`. The local vault and key stay.
- `remote status`: server, account (first 8 hex), device, generation, version, last sync, pending push, conflicts, devices, anchor state. Read-only, never prompts and never finishes a rekey: without a key that opens the vault as it is, the counts that need the encrypted roster read `locked (run 'qbit-vault unlock')`.
- `remote devices`: the roster (labels from the encrypted body, last sync per device, revoked ones marked).

### 4.7 The server is lost or wiped

Nothing local is lost: every device keeps its vault and keeps working, only the sync stops (a round fails with `remote_unreachable`). The recovery keys of the old server no longer apply, because they opened accounts that no longer exist. Start again on the new or empty server:

1. Keep an `export` of the vault first (`INSTALL.md` § Backup without a server).
2. On each device: `qbit-vault remote logout` (the best-effort call to the old server may fail; the local vault and key stay).
3. On one device, the one with the secrets you want: `qbit-vault remote register --server URL` (it shows a new recovery key).
4. On every other device: `qbit-vault remote join --server URL`, approved with `remote approve` on a device that is already in.

A device that joins with secrets of its own merges them into the account (§ 4.4).

## 5. Server authentication

- **Device token.** `POST /v1/auth/challenge {device_id}` returns a 32-byte nonce valid 60 s; `POST /v1/auth/token {device_id, nonce, sig}` where `sig = Ed25519(sign_key, "qbit-vault/auth/v1" ‖ server_origin ‖ nonce)` returns a random bearer token valid 15 minutes. Binding `server_origin` (the configured public URL, normalized as in § 4.1) stops a signature from being relayed to another server. `challenge` and `token` both refuse a device id that is not 1-64 lower-case letters or digits before any lookup. When a login is refused and `GET /v1/info` reports a different `origin`, the client says `the server is configured as <origin>; you used <url>. Use the same URL (qbit-vault remote logout, then register or join with it).` The reported origin is used only when it is itself a plain normalized origin; anything else keeps the generic refusal.
- **Recovery token.** From the recovery auth secret; valid 10 minutes; can only read the recovery envelope and register one device.
- **Invite.** Account creation needs a single-use invite issued by the server operator (`qbit-vault-server invite --ttl 24h`, default 24 h); the server stores only its SHA-256.
- Tokens are never logged; the client keeps them in memory only.

## 6. Server API (v1)

JSON over HTTPS; blobs are base64url inside the JSON. Every response carries `{"api":1}`; a client refuses an unknown major (`server_incompatible`). Errors are `{"error":{"code","message"}}` with codes `unauthorized`, `forbidden`, `not_found`, `conflict`, `too_large`, `rate_limited`, `invalid`, `device_revoked`, `internal`.

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz`, `GET /v1/info` | none | liveness; `{api, version, origin, limits}` (`origin`, the server's normalized public URL, is optional for a client: it is used only to explain a refused login) |
| `POST /v1/accounts` | invite | create account with first device, recovery envelope and vault version 1 |
| `POST /v1/auth/challenge`, `POST /v1/auth/token` | none / signature | device token |
| `GET /v1/vault` (`If-None-Match: <version>` → 304) | device | current version |
| `GET /v1/vault/versions`, `GET /v1/vault?version=N` | device | the last 10 versions |
| `PUT /v1/vault {base_version, blob}` | device | compare-and-swap: 200 `{version}` or 409 `{version}` |
| `POST /v1/rekey` | device | atomic rekey and revocation (§ 4.5); everything is validated before the new version is written, so a refused call leaves no version |
| `PUT /v1/recovery` | device | replace the recovery key at the current generation (§ 4.6) |
| `GET /v1/keys/self` | device | this device's latest key envelope |
| `GET /v1/devices`, `DELETE /v1/devices/{id}` | device | list, revoke (only through `rekey`), self-delete (`logout`) |
| `POST /v1/pairings` | none | new device announces its public keys; 409 when a pending, unexpired pairing already has that code (nothing is overwritten) |
| `GET /v1/pairings/{code}`, `POST /v1/pairings/{code}/approve` | device | approver reads and approves |
| `GET /v1/pairings/{id}?poll=<secret>` | poll secret | new device waits for approval |
| `POST /v1/recovery/token`, `GET /v1/recovery/envelope`, `POST /v1/devices` | recovery auth / recovery token | recovery |
| `PUT /v1/anchors`, `GET /v1/anchors?device=<id>` | device | audit anchors (§ 8) |

The server verifies only what it can: token validity, CAS on `version`, sizes and rates. It does not and cannot validate ciphertext; every client verifies AEAD, AAD (`account_id`, `generation`, `version`) and signatures on everything it downloads.

**Limits.** Vault blob ≤ 8 MiB; request body ≤ 9 MiB on `PUT /v1/vault`, `POST /v1/rekey` and `POST /v1/accounts` and ≤ 64 KiB on every other route (over the cap: 413 `too_large`, nothing stored); account creation 10/hour per IP; pairing creation 5/min per IP and at most 1000 pending pairings at once (then 429); recovery token 5/min per IP and 20/day per lookup id; auth 30/min per device; at most 20 devices per account.

## 7. Sync

### 7.1 When it runs (no daemon)

- **Push after every mutation.** `set`, `rm`, `mv`, `edit`, `relink`, `link`, `import`, `restore`, `rekey` and an applied `manage` run one sync round after releasing the vault lock, with a 5 s budget (a constant; `config.remote.timeout` is planned, no `config.yaml` loader exists). If the server is unreachable the change stays committed locally, `state.json.remote.pending_push` is set and stderr says `warning: not synced (server unreachable); will retry`. `--json` output gains `"remote":"synced"|"pending"` when sync is enabled (not on the broker's `manage`, whose response is pinned by the contract). A round that fails for a reason other than reachability (`remote_rollback`, a refused verification or device) keeps the change local and the push pending and prints `warning: not synced (<code>); the change is kept on this device; run 'qbit-vault remote status'`; it is never reported as unreachable. After three conflicts in a row (another device pushed first each time) the push stays pending and stderr says `warning: not synced (the server changed while syncing); will retry`. Until a `config.yaml` loader exists the budgets and the pull interval are constants (`pushBudget`, `pullBudget`, `pullInterval` in `internal/cli/remoteauto.go`). `QBIT_VAULT_NO_REMOTE=1` makes no call and marks pushes pending, without a warning.
- **Pull before reading for a person or the agent.** `list`, `describe`, the broker's `request` and `list`, `prompt`, `set` and `remote sync` pull first when the last pull is older than the pull interval (60 s, a constant; `config.remote.pull_interval` is planned), with a 2 s budget; a failure is silent there and shown by `remote status` and `doctor`. A pending push is retried at the same moments.
- **Never on the hot path.** `exec`, `grant`, `revoke`, `grants` and `audit` (except `audit --verify`, § 8) never touch the network, so running a command with a secret works offline and keeps its latency (R-NFR-02).

### 7.2 One round

1. `GET /v1/vault` with `If-None-Match: last_version`.
2. On a newer version: verify AAD (`account_id`, `generation` ≥ local, `version` ≥ `state.json.remote.last_version`, else `remote_rollback`) and decrypt. A higher generation first runs the key swap of § 4.5.
3. Under `vault.lock`: load local `L` and base `B` (`remote/base.enc`, the body of the last version this device agreed with), compute `M = merge(B, L, R)` (§ 7.3), save `M` locally through the normal save path (snapshot, atomic write).
4. If `M ≠ R` or a push is pending: seal `M` as `version = R.version + 1`, `PUT` with `base_version = R.version`. On 200, set `last_version` and `base = M`. On 409 go back to 1 (at most 3 times, then `pending`).
5. Upload the audit anchor if the last one is older than 10 minutes (§ 8). It is best effort: a failure never fails the round.

The network calls run outside `vault.lock`; only step 3 holds it.

### 7.3 Merge

Merge is per key. Keys are `global/<NAME>`, `project/<project_id>/<NAME>`, `project/<project_id>` (layer metadata), `device/<device_id>` (roster entry). Every record, tombstone and metadata entry carries an `hlc`: a hybrid logical clock `"<unix_ms>.<counter>@<device_id>"`, compared by milliseconds, then counter, then device id. A device sets a new `hlc` on every change, never lower than the highest it has seen.

For a key with base `b`, local `l` and remote `r` (each a record, a tombstone or absent), compared by `hlc`:

| Case | Result |
| --- | --- |
| `l = r` | `l` |
| `l = b` | `r` (only the other side changed) |
| `r = b` | `l` (only this side changed) |
| otherwise (both changed) | the higher `hlc` wins; the loser goes to `conflicts` (§ 7.4) |

Special keys: project roots are written only by their own device (`roots[device_id]`), so each device takes its own entry from `l` and every other entry from `r`. Roster entries merge as a union; `revoked_at` is sticky (once set, never cleared) and `last_sync` takes the maximum. Grants need no merge rule: they bind to a record `id` (STORAGE § Grants), and a value replaced on another device has a new id, so the local grant no longer matches it.

Tombstones `{key, hlc, deleted_by}` are kept 180 days. A device that comes back after that still deletes correctly when it did not touch the record (its base holds the record, so `l = b` and the remote absence wins).

### 7.4 Conflicts

When both sides changed a key, the losing version is kept in the encrypted body under `conflicts` (at most 100 entries, 30 days): `{id, key, record or deleted: true, lost_at, winner_device}`. Nothing is ever lost silently. `remote conflicts` lists names, layers, dates and devices (never values); `remote resolve NAME [--global|--project] --keep current|conflict` (user-only, § 4) swaps or discards the kept version, and the result syncs like any change. `remote status`, `doctor` and the human output of `list` say `N sync conflicts` while any exist.

`--keep current` discards every kept version of the record; `--keep conflict` swaps (the replaced record becomes the kept version, so `--keep current` afterwards ends the conflict) and gives the record that returns a fresh `hlc` and record `id`. The merge unions the `conflicts` of both sides, which alone would bring back a conflict that one device resolved, so the merge treats kept conflicts three ways like records: a conflict the base held and one side no longer holds was resolved there and stays resolved; any other conflict of either side is kept (`internal/merge`). `remote conflicts` is local and read-only; it lists the winner's label from the roster.

### 7.5 Projects on several machines

A project layer is identified by a random `id`, not by its path. Its `roots` map each device to that device's checkout (STORAGE § Layers). Resolution uses `roots[this device]` only. On a machine where a layer has no root yet, it is invisible to resolution; when the repository of `cwd` has an `origin` URL (read from `.git/config`, normalized: scheme and `.git` suffix dropped, host lower-cased) equal to the layer's `origin`, human commands print `hint: project secrets "<label>" from another device match this repository; run 'qbit-vault link <label>'` on stderr, and the broker's `list` returns `unlinked_match: {label}` so the agent can suggest it. Only the user links: `qbit-vault link LABEL [DIR]` confirms out of band and is never automatic, because a match by URL alone would let any clone of that repository receive its secrets.

### 7.6 History and restore

`remote history` lists the server's last 10 versions (version, writer device label, time). `remote restore --version N` (user-only) downloads and verifies version N, asks for confirmation and only then runs a sync round and writes the difference: a cancel makes no request that changes anything and leaves a pending push pending. It makes the vault equal to version N by writing the difference as new changes with fresh `hlc`, so it syncs to every device as an ordinary edit; the replaced state stays in local backups.

The command first runs a round, so the difference is computed against the newest state; then it downloads version N and verifies it as in § 7.2 step 2: AEAD, and an AAD of this account, the **current** generation and version N. A version sealed under an older generation cannot be opened with the current key (the key it used is retired) and is refused with `restore_unavailable`, as is a version the server no longer keeps (it holds the last 10). Only the records are restored: the roster (a revoked device stays revoked), the kept conflicts and the grants keep their current state. A record that differs from N is written with N's content, a fresh `hlc` and a fresh record `id` (grants bind to the `id`, so a grant of the replaced record does not come back); a record N lacks is deleted and leaves a tombstone; an identical record is left alone, with its clock. Then the push is the normal one.

## 8. Audit anchor

The local audit log is hash-chained and anchored by `audit.head`, but a local attacker who rewrites both files can make `audit --verify` pass (THREAT_MODEL R8). With sync enabled, each round uploads at most every 10 minutes an **anchor**: `{device_id, seq, line, at}` from `audit.head`, sealed with `AAK`. The server keeps the last 100 anchors per device and learns only how many there are and when they arrive.

The time of the last upload is kept in `state.json` under `remote_anchor_at` (beside the `remote` object, which `logout` and a revocation clear with it); `remote status` shows it.

`audit --verify` with sync enabled also fetches this device's anchors (5 s budget; `--offline` skips; unreachable prints `remote anchor: unavailable` and does not fail the verification; neither does a key that is not available without a prompt, an interrupted rekey, or a `state.json` that cannot be read: the check never prompts and never finishes a rekey). For every anchor whose `seq` is within the log, the raw line at `seq` must hash to `line`; otherwise the result is `anchor_mismatch` at that line. A log shorter than the highest anchored `seq` is `truncated`. Human output adds `remote anchor ok (seq N, <time>)`. The check runs only when the local chain is valid, and only anchors this device's key opens count: one sealed before a key rotation, or altered by the server, is ignored (when none opens the output says `remote anchor: none uploaded`, or `remote anchor: missing (...)` when this device has uploaded anchors before: a key rotation since, or a server that removed or altered them; it does not fail the verification, but it no longer looks like a fresh account). A rewrite is now detectable unless the attacker also controls the server and removed the anchors (R8, narrowed).

## 9. What the server learns

| Learns | Never learns |
| --- | --- |
| account id, number of devices, their ids and public keys, request IPs | secret values, names, descriptions, kinds |
| time of every auth, pull, push, pairing, recovery and anchor upload | project labels, paths, origin URLs |
| size of each vault version, padded to 4 KiB (a rough count of secrets) | device labels, the roster's content |
| generation count (how many rekeys and revocations) | audit log content, grants, which secret was used when |

The "never learns" column is tested, not just claimed: `e2e/docker-test.sh` (TESTING.md § Tier 2 item 7) records every HTTP exchange through a proxy and scans those bodies, URLs and headers, and the server's whole `/data` volume, for every fixture value, secret name, project path and device label.

## 10. The server

`qbit-vault-server` is a Go binary in the same module (`cmd/qbit-vault-server`), standard library only.

- **Run:** `qbit-vault-server serve`. Env: `QBV_SERVER_DATA` (default `/data`), `QBV_SERVER_LISTEN` (default `:8080`), `QBV_SERVER_PUBLIC_URL` (required; the origin clients sign, § 5), `QBV_SERVER_TLS_CERT` / `QBV_SERVER_TLS_KEY` (optional; otherwise TLS terminates at the reverse proxy), `QBV_SERVER_TRUST_PROXY=N` (N = how many trusted proxies sit in front; unset or `0` uses the connection's address only; any other non-number makes `serve` exit 2. The client IP for rate limits is the Nth address counted **from the right** of `X-Forwarded-For`, because each proxy appends the address it received from and everything to the left is client-controlled; with fewer than N entries, or a malformed one, it is the connection's address. `1` is one proxy, e.g. Traefik alone. Behind Cloudflare and Traefik it depends on Traefik: by default it does not trust the incoming header and rewrites it with the Cloudflare edge's address, so keep `1` (buckets per Cloudflare edge, nothing spoofable); use `2` only when Cloudflare's ranges are in Traefik's `forwardedHeaders.trustedIPs`, which keeps the visitor's address. A wrong N only weakens the per-IP limits (a too-high N lets a client choose its bucket); the per-device and per-account limits still apply), `QBV_SERVER_BOOTSTRAP_INVITE` (optional: while the server has no account, `serve` registers this code as a single-use invite valid 24 h, hash only, exactly like `invite`; at least 24 characters and at least 12 different ones (`aaaa…` is refused), else exit 2; a restart with the same code never extends its first 24 h; ignored with a log line once an account exists; the code is never logged. For platforms where the operator cannot exec `invite` in the shell-less container; remove it after the first `remote register`).
- **Admin:** `qbit-vault-server invite [--ttl 24h]` (1 s to 720 h) prints one invite code; it is an operator credential, not a vault secret. `qbit-vault-server health` exits 0 when `/healthz` answers on `QBV_SERVER_LISTEN` (the image's health check; the image has no shell). Exit codes: 0 ok, 1 failure, 2 usage. `serve` stops gracefully on SIGTERM.
- **Storage:** files under `QBV_SERVER_DATA` (`accounts/<id>/…`, `pairings/`, `invites/`, `recovery/`, `revoked/`), every write atomic (temp file, `fsync`, rename) and serialized per account. One instance per data directory.
- **Memory:** nonces, tokens and pending pairings (also the files in `pairings/`) are swept once expired, about once a minute; the rate limiter drops only entries whose window is over, and refuses new keys rather than reset live counters if it ever fills (100 000 keys).
- **Logs:** method, path template, status, duration and the first 8 hex of the account id. Never bodies, tokens, codes or IPs beyond the rate limiter's memory.
- **Status page:** `GET /` (and `HEAD /`) answers a small HTML page with the QBit Vault mark and colors inline: "This QBit Vault sync server is running", the server version (`QBV_SERVER_VERSION`, baked into the image; `dev` when unset), `API v1`, one sentence that the server only stores data sealed on the user's devices, and a link to the documentation. It carries no account, device or usage information, no script and no external request; headers `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Every other unknown path keeps the 404. There is no web management of secrets or accounts: the server cannot read them (§ 9) and never serves code that touches keys.
- **Image:** `deploy/Dockerfile` (build from the repository root: `docker build -f deploy/Dockerfile .`). Every release publishes it as `ghcr.io/qubiit0/qbit-vault-server` (linux/amd64 and linux/arm64, tags `vX.Y.Z-...` and `latest`, the version baked in) from the release workflow; `deploy/compose.yaml` builds it locally as `qbit-vault-server:local` instead: a static binary on `gcr.io/distroless/static-debian12:nonroot`, user 65532, one volume `/data`, `HEALTHCHECK` through `qbit-vault-server health`. `deploy/compose.yaml` (build) and `deploy/compose.image.yaml` (the published image, one file to copy) run it read-only with all capabilities dropped and `no-new-privileges`; `compose.yaml` is written for the Dokploy (Traefik) proxy that terminates TLS on the public domain (`QBV_SERVER_PUBLIC_URL` is required, `QBV_SERVER_TRUST_PROXY` defaults to `1` there).

## 11. Client state and errors

`state.json.remote`: `{server, ca_file?, account_id, device_id, generation, last_version, pending_push, last_pull_at, hlc}`. Files: `remote/device.enc`, `remote/base.enc` (STORAGE § Remote files). `--ca-file PATH` on `register`/`join` trusts a private CA for self-signed deployments.

| Code | Exit | Meaning |
| --- | --- | --- |
| `remote_not_configured` | 1 | a `remote` command on a vault that does not sync |
| `remote_unreachable` | 1 | network or TLS failure; retryable |
| `remote_auth` | 1 | invite invalid or used, recovery key not recognized, token refused |
| `remote_rollback` | 5 | the server offered a version or generation older than one already seen |
| `pairing_failed` | 1 | fingerprint or confirmation code mismatch, pairing expired |
| `device_revoked` | 1 | this device was revoked; sync is now off |
| `server_incompatible` | 1 | the server speaks another API major |
| `restore_unavailable` | 1 | `remote restore`: the version is not on the server, or was sealed under an older account key |

None of these messages contains a value, a key, a code or a token.

`device_revoked` is read from the `error.code` of any error response (never from its message). The server keeps the SHA-256 of every revoked device id (`revoked/` under its data directory) and answers that device's challenge with 403 `device_revoked`; a device it never knew gets 401 `unauthorized`. Its tokens are dropped at the revocation, so the next request fails and the re-login learns `device_revoked`.
