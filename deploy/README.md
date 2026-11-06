# deploy/: the sync server image

Files to build and run `qbit-vault-server`, the optional self-hosted server for multi-device sync. It is zero-knowledge: it stores ciphertext, public keys and counters only. Protocol, keys, limits and failure modes: [../docs/REMOTE_SYNC.md](../docs/REMOTE_SYNC.md).

| File | What it is |
| --- | --- |
| `Dockerfile` | Builds a static `qbit-vault-server` and runs it on distroless as a non-root user (65532). Build context is the repository root |
| `compose.yaml` | One `server` service: read-only root filesystem, all capabilities dropped, a `vault-data` volume on `/data`, a health check. Written for a reverse proxy that terminates TLS (Dokploy / Traefik) |

No image is published yet (Phase 5). You build it from this repository.

## Run it

`QBV_SERVER_PUBLIC_URL` is required: the `https://` origin your clients use.

```bash
export QBV_SERVER_PUBLIC_URL=https://vault.example.com
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml exec server /qbit-vault-server invite --ttl 24h
```

No shell on the host? Set `QBV_SERVER_BOOTSTRAP_INVITE` (a code of your own, at least 24 characters) in the service environment and redeploy: while the server has no account it accepts that code once as the invite. Remove it afterwards.

Then, on the first machine: `qbit-vault remote register --server https://vault.example.com`. The invite is an operator credential, not a vault secret.

Without compose: `docker build -f deploy/Dockerfile .` from the repository root.

## Settings

Set through the environment (`QBV_SERVER_DATA` defaults to `/data`, `QBV_SERVER_LISTEN` to `:8080`; `QBV_SERVER_TRUST_PROXY=1` is set by `compose.yaml` because the proxy terminates TLS; `QBV_SERVER_TLS_CERT` and `QBV_SERVER_TLS_KEY` exist for serving TLS directly). The full list and the admin commands (`serve`, `invite`, `health`) are in [../docs/REMOTE_SYNC.md](../docs/REMOTE_SYNC.md) § 10.

Back up the `vault-data` volume: it holds every account's sealed vault, invites and device records.
