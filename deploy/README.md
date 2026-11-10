# deploy/: the sync server image

Files to build and run `qbit-vault-server`, the optional self-hosted server for multi-device sync. It is zero-knowledge: it stores ciphertext, public keys and counters only. Protocol, keys, limits and failure modes: [../docs/REMOTE_SYNC.md](../docs/REMOTE_SYNC.md).

| File | What it is |
| --- | --- |
| `Dockerfile` | Builds a static `qbit-vault-server` and runs it on distroless as a non-root user (65532). Build context is the repository root |
| `compose.image.yaml` | The same service, hardened the same way, running the published image `ghcr.io/qbitdevz/qbit-vault-server` (no build, no clone needed: copy this one file) |
| `compose.yaml` | One `server` service built from this repository (used by the Dokploy deployment): read-only root filesystem, all capabilities dropped, a `vault-data` volume on `/data`, a health check. Written for a reverse proxy that terminates TLS (Dokploy / Traefik) |

Every release publishes `ghcr.io/qbitdevz/qbit-vault-server` for linux/amd64 and linux/arm64, tagged with the release version (for example `v1.0.0`) and `latest`, built from `Dockerfile` with the version baked in (`QBV_SERVER_VERSION`, shown by `/v1/info` and the status page).

## Run it

`QBV_SERVER_PUBLIC_URL` is required: the `https://` origin your clients use. From the published image, with one file:

```bash
export QBV_SERVER_PUBLIC_URL=https://vault.example.com
docker compose -f compose.image.yaml up -d
docker compose -f compose.image.yaml exec server /qbit-vault-server invite --ttl 24h
```

Open `https://vault.example.com/` in a browser: the server answers a small status page with the QBit Vault branding, its version and API version. It shows nothing about accounts, devices or usage and has no script; secrets are never managed on the web (the server cannot read them).

To pin a release, change `:latest` in `compose.image.yaml` to a version tag such as `:v1.0.0`. To build from this repository instead:

```bash
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml exec server /qbit-vault-server invite --ttl 24h
```

No shell on the host? Set `QBV_SERVER_BOOTSTRAP_INVITE` (a code of your own: at least 24 characters, at least 12 of them different, so not `aaaa…`) in the service environment and redeploy: while the server has no account it accepts that code once as the invite. Remove it afterwards.

Then, on the first machine: `qbit-vault remote register --server https://vault.example.com`. The invite is an operator credential, not a vault secret.

Without compose: `docker build -f deploy/Dockerfile .` from the repository root.

## Settings

Set through the environment (`QBV_SERVER_DATA` defaults to `/data`, `QBV_SERVER_LISTEN` to `:8080`; `QBV_SERVER_TRUST_PROXY` is the number of proxies in front of the server and `compose.yaml` defaults it to `1` because Traefik terminates TLS; keep `1` behind Cloudflare too unless Traefik trusts Cloudflare's ranges (`forwardedHeaders.trustedIPs`), then `2`, and `0` if the server is reachable directly: a wrong number weakens the per-IP rate limits, never the data; `QBV_SERVER_TLS_CERT` and `QBV_SERVER_TLS_KEY` exist for serving TLS directly). The full list and the admin commands (`serve`, `invite`, `health`) are in [../docs/REMOTE_SYNC.md](../docs/REMOTE_SYNC.md) § 10.

Back up the `vault-data` volume: it holds every account's sealed vault, invites and device records.
