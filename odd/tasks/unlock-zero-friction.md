# Zero-friction unlock: an agent call opens the unlock dialog

When a vault is locked, every agent-callable QBit Vault tool opens the native passphrase dialog itself, and no message tells the user or the model to run a command in a terminal unless the dialog cannot be shown. The user only manages secrets and authorizes. Builds on `odd/tasks/agent-prompts.md` (S5: `secret_request` and `secret_manage` already open the dialog).

## Specs

- S1. User (verbatim, 2026-11-12): "tambien revisa que para desbloquear la boveda el agente siempre me pide que yo corra el comando. La idea siempre tiene que ser que si necesita esto te lo pida y si confirmas te aparezca automaticamente la ventana para poner la contraseña maestra y desbloquear la boveda"; on making `secret_exec` and `secret_list` open the dialog too: "si la idea es que el agente ejecute los comandos y que el usuario solo tenga que gestionar sus secretos y autorizar, es 0 friccion".
- S2. `secret_exec` and `secret_list` (MCP broker) on a locked vault open the same unlock dialog as `secret_request` (`internal/cli/agentunlock.go` `agentPassphrase`: names the requester and the secrets involved, the process-wide dialog gate, audited), then continue the call normally (grants, exec, list). Cancel or a wrong passphrase: the existing `vault_locked` refusal, never a value or the passphrase in any output. `QBIT_VAULT_NO_PROMPT_UNLOCK=1` keeps today's refusal. No dialog backend available: today's refusal.
- S3. Hooks never open a dialog (unchanged). Their locked texts point to the agent flow, not a terminal command, wherever the model reads them.
- S4. Agent skill (`internal/hosts/skill/SKILL.md`): for a locked vault, `output withheld … (vault locked)` and `qbit-vault could not check this edit for secrets (vault locked)`, the model calls a QBit Vault tool (e.g. `secret_list`), which opens the unlock dialog, then retries; asking the user to run `qbit-vault unlock` is only the fallback when the tool reports that no dialog could be shown. The model never asks the user to type a command for something a tool can do.
- S5. Pi extension (`packages/qbit-vault-pi`): the locked notice no longer says to run a command in a terminal: it says the vault unlocks when a QBit Vault tool or a `/vault` command needs it. The footer refresh never opens a dialog; a `/vault` command the user runs may open it (check what the CLI child does today and keep it if it already prompts). Version 0.2.2 if the package changes (`ExtensionVersion`, install lines; the tag is published after merge).
- S6. Tests (RED first, public interface: the broker/MCP calls with a scripted prompt backend as the existing agent-unlock tests do): exec and list unlock and proceed after a correct passphrase; cancel, wrong passphrase, `QBIT_VAULT_NO_PROMPT_UNLOCK=1` and no backend keep the refusal; audit entry; leak battery: the passphrase never appears in any output; the skill test (texts present). Existing `secret_request`/`secret_manage` unlock behavior unchanged.
- S7. Docs: AGENT_INTEGRATIONS (unlock section), CLI, THREAT_MODEL if it lists which tools prompt, CHANGELOG `[1.4.0]` (this ships in 1.4.0).

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T1 | S2-S7 | worker | | in progress |
| T2 | verify, then ship with 1.4.0 | parent | | pending |

## Log

- L1. User (verbatim): see S1.
- L2. Research: the dialog path exists (`agentunlock.go:79-102`, routed by `passphraseSource` for broker calls); `secret_request` and `secret_manage` ask; `secret_exec` and `secret_list` set `g.unlock.never` (`brokercmd.go:156, 222`) and refuse with `vault is locked; call secret_request to ask the user to unlock it`; `SKILL.md:43,45` (added by output-guard 1.3.0) tell the model to have the user run `qbit-vault unlock`; Pi `messages.ts:5` says `run 'qbit-vault unlock' in a terminal`; hooks never prompt by spec (`AGENT_INTEGRATIONS.md:115`).
