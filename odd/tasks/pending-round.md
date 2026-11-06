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
| W1 | S1, S2 | inline | init falls back to a passphrase when no OS keychain is reachable; docs | e4c1eab | done |
| W2 | S4 | inline | F7-F9: value fd 3 refuses a terminal; closed-fd test without the race; Linux epoll probe | 4a0ebb7 | done |
| W3 | S4 | inline | run e2e/hosts-test.sh and the real install.sh in a Linux container | (checks only, L4) | done |

## Log

- L1. User request verbatim in S1.
- L2. W1: RED showed plain `init` without a keychain answering `error: vault is locked` (exit 4), not just failing. createVault now passes the prompt backend's passphrase function in every mode; keychain.Setup already uses it only when no OS keychain is reachable. Tests (keyring.MockInitWithError): fallback asks one confirmed passphrase prompt and prints the note; JSON names `passphrase-file`; no prompt backend gives the usage error naming `--passphrase --passphrase-stdin` and writes no key or vault; a machine with a keychain is asked nothing. The TUI setup already hands the terminal to `init` for its passphrase prompt.
- L3. W2 (F7-F9, odd/tasks/launch-prep.md L9). RED in golang:1.26 on Linux: TestValueFDKindRefusesATerminalButNotDevNull ("a terminal was accepted", /dev/ptmx) and TestIsEventPollerProbesEpoll ("an epoll descriptor was not recognized"). Fix: S_IFCHR is accepted only when it is not a terminal (golang.org/x/term IsTerminal, no *os.File) and not a poller; Linux isEventPoller probes with epoll_ctl(EPOLL_CTL_DEL) of a fresh pipe (ENOENT only on an epoll; epoll_wait is never called, so the runtime's edge-triggered events are not stolen). F8: the closed-descriptor case uses fd 1<<20 instead of dup+close, so no other goroutine can reuse the number. GREEN on Linux (Docker, Go 1.26) incl. the prompt tests; go vet clean for linux, darwin, freebsd, windows; macOS runs in CI.
- L4. W3. Docker batteries on this branch: e2e/hosts-test.sh 147 passed 0 failed (incl. the new skill checks: one shared ~/.agents copy, no Pi duplicate, both removed on uninstall), e2e/install-test.sh 98/0, e2e/docker-test.sh (sync) 85/0. Real one-line install from GitHub (v0.1.0-beta.3): ubuntu:24.04 with curl installs linux/amd64 and a second run says "is already installed; reinstalling it", `init --passphrase --passphrase-stdin` then doctor healthy; alpine:3 (busybox sh, wget, no curl) installs and runs; alpine arm64 (emulated) installs linux/arm64. W1 on real Linux with this branch's binary: with no terminal, `init` prints the new usage error and writes no vault home; with a pty it reaches `Passphrase (input is hidden):` (the scripted pty does not answer the prompt's terminal queries, so the run timed out there; the full flow is covered by the unit tests).
