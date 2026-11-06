# Feature: never lose the vault with the machine

Run the user's own sync server on Dokploy so a lost machine is recovered with the recovery key, then add an encrypted offline export as a second, server-free backup.
Branch for code changes: `feat/export`.

## Specs

- S1. User (verbatim): "que pasa si se rompio mi sistema? pierdo todo? como se hace backup del vault?"
- S2. User choice (verbatim): "Las dos" (sync on Dokploy first, then an encrypted offline export).
- S3. User choice (verbatim): domain "vault.leandroalvarez.com.ar (Recomendado)".

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| B1 | S2, S3 | inline | deploy qbit-vault-server on Dokploy (new project, GitHub source, compose `deploy/compose.yaml`, domain, DNS, volume backup), verify from outside | (infra) | pending |
| B2 | S2 | user | `qbit-vault-server invite` (operator) and `qbit-vault remote register` on this PC; the recovery key is written down offline | (user) | pending |
| B3 | S2 | inline | `qbit-vault export` / restore from an export file: passphrase-sealed, portable, tests, docs | | pending |
| B4 | S2 | user | join the WSL PC (`remote join`, `remote approve`) | (user) | pending |

## Log

- L1. User request verbatim in S1. Today: keychain mode keeps the master key in this Windows' Credential Manager; `backups/` lives on the same disk, so losing Windows loses the vault. Sync (built, `docs/REMOTE_SYNC.md`) gives recovery with the recovery key; an offline export does not exist yet.
- L2. B1 done (infra, no repo change): Dokploy project "QBit Vault" (9zeSh-8n3WkAMAS3mz_YW), compose qbit-vault-server (Qor338ATVg3rRKK_hVnL2) from github QuBiit0/qbit-vault main ./deploy/compose.yaml, autoDeploy on, isolated, watchPaths deploy/**, cmd/qbit-vault-server/**, internal/server/**, go.mod, go.sum; env QBV_SERVER_PUBLIC_URL; domain vault.leandroalvarez.com.ar:8080 https letsencrypt (l7oXtN2KP36W-QJy3NEsX); Cloudflare A record proxied to the zone IP. All API calls ran through qbit-vault secret_exec (DOKPLOY_URL, DOKPLOY_API_KEY, CF_ZONE_DNS_TOKEN, session grant); the Dokploy host was redacted in output. curl: https /healthz 200 {"api":1,"ok":true}, http 301 to https, /v1/info api 1. A POST to the http URL was turned into a GET by the 301 (fixed by resolving the effective URL first); an inline shell function was refused as dump_command (correct), so the calls ran from a script file. Open: volume backup of /data (needs an S3 destination on Dokploy).
- L3. B2 blocker: the image is distroless (no shell), the user has no SSH, so `invite` cannot be run. Added QBV_SERVER_BOOTSTRAP_INVITE (feat/bootstrap-invite): while no account exists, serve registers that code as a single-use 24 h invite (hash only, never logged; >= 24 chars; ignored once an account exists). Tests in internal/server/bootstrap_test.go. Flow: the user stores a code with `qbit-vault set QBV_BOOTSTRAP_INVITE`, the agent sets it in Dokploy through secret_exec without seeing it, redeploys, the user registers with the same code, then the variable is removed.
- L4. User: "si esa confirmacion de 12hs no esta funcionando porque el agente se reinicia y vuelva a aparecer o no lo hace por algun problema revisala o quitala". Cause confirmed: a session grant is bound to the MCP session, and a restarted agent is a new session. Fix (feat/project-12h): inside a repository the request and manage-replace dialogs offer "12 hours: in this project, even if the agent restarts", a project grant with ExpiresAt = now+12h (grants.Request.TTL now valid for project scope, 1m..24h). Outside a repository the session answer stays. prompt command and set --grant unchanged (grant --ttl stays session-only). Tests: grants TestProjectGrantWithATTLExpires, cli grants_project12h_test.go.
- L5. User: "creo que es mejor que dejes aprobar una vez, aprobar siempre o rechazar nomas. eso de las 12hs no me convence". Decisions (asked): outside a repository only once or no; for a global secret "always" means this project (one approval per repository). Implemented on feat/once-always-deny: the request and manage-replace dialogs offer Once (preselected) / Always: in this project, until you revoke it / Don't allow; session never offered there; the 12h project grant of beta.7 removed (grants TTL back to session only). The prompt command keeps its --scopes contract. User: "deberia poder seleccionarse y copiarse nomas ese codigo de recuperacion" and "puedes hacer los dialogos mas bonitos y prolijos?": Windows show dialog uses a read-only selectable box; all PowerShell dialogs use design/system.md colors, Segoe UI, padding, right-aligned buttons (screenshots checked). B2 done: account 17cca1d6, device QuBit-Notebook; bootstrap env var removed.
