# Feature: pending round after the public beta

Remove the WSL / headless-Linux friction at `init`, close the open review follow-ups, and run the checks that could not run before (Docker batteries, a real Linux install from GitHub).
Branch `fix/pending-round`.

## Specs

- S1. User (verbatim): "con respecto a las fricciones: lo de wsl se puede mejorar? yo por ejemplo lo uso en otra pc. Lo de la firma del binario olvidate porque creo que hay que pagar y no quiero eso. las demas fricciones creo que es normal hasta probarlo. Despues de ver todo esto, podrias ir por los pendientes"
- S2. WSL / headless Linux: plain `qbit-vault init` on a machine without an OS keychain must not fail; it protects the vault with a passphrase instead and says so. With no way to ask (no terminal, no dialog), the error names the fix.
- S3. Code signing is out of scope (user, S1).
- S4. Pending items from earlier logs: F7 `R1-chr-device-fd3`, F8 `R3-closed-fd-race`, F9 `R3-linux-epoll-type` (odd/tasks/launch-prep.md L9); the hosts e2e battery not run after the skill change (odd/tasks/agent-skill.md L5); the one-line install never run on a real Linux host (odd/tasks/public-launch.md L9).

## Tasks

| ID | Specs | Route | Change | Commit | Status |
| --- | --- | --- | --- | --- | --- |
| W1 | S1, S2 | inline | init falls back to a passphrase when no OS keychain is reachable; docs | | pending |
| W2 | S4 | inline | F7-F9: value fd 3 refuses a terminal; closed-fd test without the race; Linux epoll probe | | pending |
| W3 | S4 | inline | run e2e/hosts-test.sh and the real install.sh in a Linux container | | pending |

## Log

- L1. User request verbatim in S1.
