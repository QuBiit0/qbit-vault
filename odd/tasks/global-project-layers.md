# Feature: global and project layers, agent-managed vault, manual entry

Spec change only (no code exists yet). Updates the gentle-vault specification so secrets live in a
global layer and per-project layers, the agent can propose management actions the user confirms,
and the agent can read the full list of what it may and may not do.

## Specs

- S1. "estaria bueno que esta herramienta permita de manera sencilla poder administrar los secretos de manera global y tambien por proyectos"
- S2. "el agente debe poder hacerlo y saber en totalidad que cosas puede hacer y que no." Decision (L3): option A, "el agente *propone* crear, borrar, editar metadata o mover entre global y proyecto, y vos confirmás cada acción en el prompt fuera del chat, igual que una captura."
- S3. "esto deberia ser como el vault para los agentes de ia."
- S4. "cuando se guarden los secretos sea de manera encriptada cosa que si se filtra la db no sea accesible sin autorizacion.."
- S5. "la interfaz, comandos y conexion debe ser sencilla siempre respetando onecomand como engram y demas herramientas de gentle-ai"
- S6. "no solo el agente puede solicitar en el chat las credenciales y que estas no pasen por llm sino que tambien deberia permitir a un usuario poder ingresarlas de manera manual si quisiera."

## Tasks

| ID | Specs | Route | Change | Status |
| --- | --- | --- | --- | --- |
| T1 | S1-S6 | inline | `docs/PRD.md`: layer, management, policy, manual-entry and at-rest requirements | done |
| T2 | S1, S4 | inline | `docs/STORAGE.md`: layered body, encrypted grants, what a leaked directory reveals | done |
| T3 | S1, S2 | inline | `contracts/secrets-broker/v1/`: `layer` fields, `manage` op, `policy` in `list`, new refusals | done |
| T4 | S1, S5, S6 | inline | `docs/CLI.md`: `--project`/`--global`, `mv`, `list --layer`, manual entry | done |
| T5 | S1-S3 | inline | `docs/ARCHITECTURE.md`: D9 update, D11-D13, Flow E | done |
| T6 | S2, S4 | inline | `docs/THREAT_MODEL.md`: management abuse, leaked directory | done |
| T7 | S2, S6 | inline | `docs/GENTLE_SHELL_EXTENSION.md`, `docs/AGENT_INTEGRATIONS.md`: `secret_manage`, manual entry per host | done |
| T8 | S1-S6 | inline | `docs/ROADMAP.md`, `docs/TESTING.md`, `README.md` | done |

No commits: the directory is not a Git repository yet.

## Log

- L1. User: "algo para agregar, estaria bueno que esta herramienta permita de manera sencilla poder administrar los secretos de manera global y tambien por proyectos, el agente debe poder hacerlo y saber en totalidad que cosas puede hacer y que no. esto deberia ser como el vault para los agentes de ia. tambien me interesa que cuando se guarden los secretos sea de manera encriptada cosa que si se filtra la db no sea accesible sin autorizacion.. la interfaz, comandos y conexion debe ser sencilla siempre respetando onecomand como engram y demas herramientas de gentle-ai"
- L2. User: "no solo el agente puede solicitar en el chat las credenciales y que estas no pasen por llm sino que tambien deberia permitir a un usuario poder ingresarlas de manera manual si quisiera. La recomendacion A esta perfecto."
- L3. Decision: agent management = option A (propose, user confirms out of band). Invariant 6 kept.
- L4. Design decisions taken by the agent (user may veto):
  - Two layers: `global` and `project` (keyed by repository root, PRD Q1 leaning). Project overrides global for the same name.
  - All layers live in the single `vault.enc` body, so project paths are encrypted too; nothing is ever stored inside the repository.
  - The per-secret `projects` allowlist is removed; layers replace it.
  - `grants.json` becomes `grants.enc` (same envelope and master key), so a leaked directory does not reveal grants.
  - Agent surface: `secret_list` gains a `policy` block (what the agent can and cannot do); one new tool `secret_manage` (remove, edit, move, replace), every action confirmed by the user. Four tools total.
  - Grants bind to the layer they were granted for; a later project override does not inherit a global grant.
- L5. Verification: schema passes Draft 2020-12 meta-validation; 15 accept/reject cases for request, list, manage, grant and refusal shapes pass; grep finds no stale `three tools`, `grants.json`, `scope_project` or `projects` allowlist references.
