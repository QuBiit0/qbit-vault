# Agent prompts: Windows dialogs from WSL, unlock on demand, a robust MCP server

The agent must never send the user to a terminal to run `grant` or `unlock`: the approval and the passphrase are asked out of band, in a native dialog, with the reason, and the MCP server must neither hang nor fail when an agent calls its tools. Ships in 1.1.0 with `odd/tasks/self-update.md`.

## Specs

- S1. User (verbatim, 2026-11-10): "el unlock de la boveda... el agente deberia pedir que ingrese la contrase;a para desbloquearla cuando la necesita, no mandarte a la terminal a que vos pongas el comando y la pass para desbloquearla cuando el necesita hacer algo. siempre con autorizacion"
- S2. User (verbatim): "lo mismo cuando necesita permisos me pide que vaya al wsl y desde la terminal le haga grant.. esto se puede mejorar? ya que si estoy usando wsl es porque tengo windows con interfaz grafica y por ende podria mostrar el cartel para ingresar la clave o dar los permisos"
- S3. User (verbatim): "revisa que el mcp no se bloquee y que tampoco tenga errores a la hora del agente tener que llamarlo y usar las tools"
- S4. WSL (S2). Evidence on the owner's Ubuntu: `WSL_DISTRO_NAME=Ubuntu`, `DISPLAY=:0` (WSLg), `/proc/sys/fs/binfmt_misc/WSLInterop` present, `/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe` present, no zenity or kdialog, so `internal/prompt/native.go` `nativeFor` returns no backend and the agent is told to use a terminal.
  - S4.1 On Linux, when the process runs under WSL (`WSL_DISTRO_NAME` set or WSLInterop registered) and the Windows PowerShell helper exists at its fixed path, the native backend is the PowerShell/WinForms one (the same dialogs as on Windows), before zenity and kdialog; never looked up on PATH. `QBIT_VAULT_PROMPT` still forces a backend.
  - S4.2 Every dialog kind works through it from WSL (secret, form, choose/permission, confirm, passphrase, show/recovery key, the plain question): values come back over the helper's stdout pipe exactly as on Windows, never through a file, an argument or the environment; paths given to PowerShell are Windows paths when a path is needed at all.
  - S4.3 `doctor` names the backend it would use (`prompt: powershell (WSL)`), so the owner can see it.
- S5. Unlock on demand (S1).
  - S5.1 When an agent call (MCP `secret_request`, `secret_exec`, `secret_manage`; the hook paths that need the vault) finds the vault locked in passphrase mode, it asks the passphrase out of band through the prompt backend instead of refusing: heading `Vault passphrase`, text `<Requester> wants to use <NAME> (<layer>). Unlock the vault to continue.` (for a call without a name: `<Requester> needs the vault. Unlock it to continue.`).
  - S5.2 A right passphrase unlocks for the same time and with the same cache rules as `qbit-vault unlock` (owner-only, memory-backed where `unlock` caches), then the call continues and still needs its own grant (unlocking never grants). A wrong passphrase is asked again with the existing retry rule; cancel is the typed `cancelled` refusal; no prompt backend keeps today's `vault_locked` refusal (retryable) with its message.
  - S5.3 The passphrase never reaches the model, a log, the audit log, an argument or an environment variable; the audit log records one `unlock` event (requester, no value).
  - S5.4 `QBIT_VAULT_NO_PROMPT_UNLOCK=1` keeps the old behavior (refuse with `vault_locked`) for users who want it.
- S6. MCP robustness (S3). First an audit, then fixes for what is real:
  - S6.1 A tool call that waits for the user (a dialog) must not be lost when the client gives up: the server sends MCP progress notifications while it waits (so clients that reset their timeout on progress keep waiting), and the dialog's own timeout bounds the wait; when the client cancels, the dialog is closed and nothing is stored or granted.
  - S6.2 Concurrent tool calls never interleave two dialogs, deadlock or corrupt the vault: prompts are serialized; a second call waits or gets a typed retryable refusal, never a hang without bound.
  - S6.3 No tool returns an untyped error, a panic text or an empty result for a valid request; malformed arguments are typed refusals; every tool and refusal is in the skill (AGENTS.md: the skill is part of the contract).
  - S6.4 An end-to-end check with the real binary over stdio (`e2e/mcpclient`): initialize, tools/list, every tool's happy path and its main refusals, a call while a dialog is open, a cancelled call; no stderr noise that a client would show as an error.
- S7. Tests RED first for S4.1-S4.3, S5.1-S5.4 and every confirmed S6 defect, through the public APIs (prompt `SelectWith` with a fake Env, the CLI/MCP test worlds, the scripted backend); docs (CLI.md prompt backends, env table, AGENT_INTEGRATIONS.md, THREAT_MODEL, the skill if refusal handling changes) and CHANGELOG [Unreleased].
- S8. Verified on the owner's WSL Ubuntu after release: a permission request and a locked-vault unlock show the Windows dialog.

## Tasks

| ID | Specs | Route | Commit | Status |
| --- | --- | --- | --- | --- |
| T1 | S4 | worker | | pending |
| T2 | S5 | worker | | pending |
| T3 | S6 audit | explorer | | pending |
| T4 | S6 fixes | worker | | pending |
| T5 | S8 | parent + owner | | pending |

## Log

- L1. User requests S1, S2, S3 (verbatim above), during the self-update work. Root cause of S2 found by the parent: `nativeFor` on Linux only tries zenity/kdialog when DISPLAY is set; the WSL PowerShell path exists in `locate` but is reached only when forced with `QBIT_VAULT_PROMPT=powershell`.
