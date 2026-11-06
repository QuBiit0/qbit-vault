# Feature: clearer capture dialogs, fewer of them, and a value check

Rewrite the text of the capture, permission and confirmation dialogs; replace a value and grant it in one decision; warn before saving a value that is quoted or carries invisible characters.
Branch `feat/prompt-ux`.

## Specs

- S1. User (verbatim): "me ha pedido varias veces el mismo token el agente, me paso con cloudflare, lei algo asi como que tenia problemas en detectar algunos carecteres o comillas o no se que onda. revisa bien."
- S2. User (verbatim): "si pudes mejora los textos y descripciones que aparecen en la caja de texto cuando pide para ingresar los secretos que estan desprolijos"
- S3. The client/group layer is not built now (recommendation accepted with S1/S2 as the next work); kept as an idea in L3.

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| U1 | S2 | inline | dialog and terminal text: plain words, host name instead of the session id, no internal jargon | | pending |
| U2 | S1 | inline | `secret_manage replace`: one decision (replace + permission scope) before the value, so no second permission dialog | | pending |
| U3 | S1 | inline | value check at capture: surrounding quotes, invisible characters, line breaks inside; ask before saving | | pending |
| U4 | S1 | inline | skill: what to do when a service rejects a credential; docs, CHANGELOG | | pending |

## Log

- L1. User request verbatim in S1, S2.
- L2. Audit (read with the user's permission, `qbit-vault audit`, names only) for CLOUDFLARE_API_TOKEN on 2026-11-06: 10:21 capture + session grant (2 dialogs: value, scope); commands ran in bash with exit 0 but Cloudflare answered "Invalid API Token" (401); 10:24 a dump_command refusal (the agent probing the value); 10:27 secret_manage replace (2 dialogs: confirm, value); 10:30 grant_required, because a replaced value drops its grants, then a third permission dialog. Injection worked (bash, variable present); not a once grant. Why the first value was rejected is not in the log (values are never logged): typical causes are pasted quotes or invisible characters, or the wrong credential type (a Global API Key used as a token).
- L3. Capture fidelity checked on Windows with the real WinForms dialog driven by a scratch test (not committed): a cfut_-shaped token, quotes, ñ/€/emoji, shell metacharacters and a 2400-byte value all came back byte for byte; the multi-field form returns base64 per field. So the dialog stores exactly what is pasted.
- L4. Client/group layer: not now (S3). If repos of one client end up duplicating secrets, start with "several repositories share one project layer" (no new resolution level, no contract change) before a separate client layer.
