# e2e/: Docker batteries

End-to-end checks that run the real binaries inside Docker, on Linux. They complement `go test ./...` (see [../docs/TESTING.md](../docs/TESTING.md) § Tier 2 for every step each one asserts). They are not part of CI: run them locally before a change that touches sync, host registration or the install path.

## Run

Needs Docker (with Compose v2) and bash (Git Bash works on Windows). Run from anywhere; each script changes to the repository root. The binary never runs on your machine and no real home directory is mounted.

| Battery | Command | Proves |
| --- | --- | --- |
| Sync | `bash e2e/docker-test.sh` | One `qbit-vault-server` behind a recording TLS proxy and three clients: register, pair, recover, conflicts, revoke, rollback refusal. Then every byte the server stored and every recorded HTTP exchange is scanned for secrets (R-SYNC-02) |
| Hosts | `bash e2e/hosts-test.sh` | `init`, `sync`, hooks, an MCP session and `uninstall` against fake Claude Code, Codex and Pi configs: the user's own entries survive, a second run changes nothing, leak scan |
| Install from scratch | `bash e2e/install-test.sh` | A clean `golang:1.26` container, empty `HOME`, non-root user: `go install`, `init`, `set`, an MCP agent session, `audit --verify`, `doctor`, `uninstall`, `uninstall --purge`, then a leak scan |

Each script prints PASS or FAIL per check, ends with `N passed, M failed`, exits non-zero on any failure, and removes its own containers (and the install image) when it ends. Expect the first run to be slow: it builds images.

## Layout

| Path | Role |
| --- | --- |
| `Dockerfile`, `compose.yaml` | Sync battery images (`client`) and the `hosts` image target |
| `hosts/` | `compose.yaml` and `scenario.sh` of the hosts battery |
| `install/` | `Dockerfile` and `scenario.sh` of the install battery |
| `leakscan/` | Go tool that searches files for the `TESTSECRET_` fixtures in every modeled encoding |
| `mcpclient/` | Small MCP client (official Go SDK) that drives `qbit-vault mcp` over stdio from a JSON script |
| `proxy/` | TLS proxy that records every exchange and can replay an older response |

## Test builds

The client images build qbit-vault with `-tags e2eprompt`, which adds a `scripted` prompt backend that answers from a file. Release builds do not contain it, and a unit test proves that. **Never push these images.** Details: [../docs/TESTING.md](../docs/TESTING.md).
