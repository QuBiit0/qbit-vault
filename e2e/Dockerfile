# syntax=docker/dockerfile:1
# Images of the sync e2e battery (docs/TESTING.md § Tier 2 item 7). Build from
# the repository root: docker build -f e2e/Dockerfile --target client .
#
# `client` holds qbit-vault built WITH the e2eprompt tag (the scripted
# prompt backend). It is a test image: never push it, never ship its binary.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -tags e2eprompt -o /out/qbit-vault ./cmd/qbit-vault && \
    CGO_ENABLED=0 go build -trimpath -o /out/proxy ./e2e/proxy && \
    CGO_ENABLED=0 go build -trimpath -o /out/leakscan ./e2e/leakscan

# The recording TLS proxy, and the auditor that scans volumes for leaks.
FROM alpine:3.21 AS tools
COPY --from=build /out/proxy /out/leakscan /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/proxy"]

FROM alpine:3.21 AS client
RUN adduser -D -u 1000 qbv
COPY --from=build /out/qbit-vault /out/leakscan /usr/local/bin/
USER qbv
WORKDIR /home/qbv
ENV QBIT_VAULT_HOME=/home/qbv/vault \
    QBIT_VAULT_PROMPT=scripted \
    QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE=/home/qbv/passphrase \
    QBIT_VAULT_SCRIPTED_ANSWERS=/home/qbv/answers \
    QBIT_VAULT_SCRIPTED_TRANSCRIPT=/home/qbv/transcript
CMD ["sleep", "infinity"]

# The host registration battery (e2e/hosts-test.sh): the same test binary plus
# bash, jq and python3 (tomllib) for the assertions. No claude, codex or pi
# binary is installed: the scenario only creates their config directories.
FROM alpine:3.21 AS hosts
RUN apk add --no-cache bash jq python3 coreutils && adduser -D -u 1000 qbv
COPY --from=build /out/qbit-vault /out/leakscan /usr/local/bin/
COPY e2e/hosts/scenario.sh /usr/local/bin/hosts-scenario
USER qbv
WORKDIR /home/qbv
ENV HOME=/home/qbv/fakehome \
    XDG_RUNTIME_DIR=/dev/shm/qbv-run \
    QBIT_VAULT_HOME=/home/qbv/vault \
    QBIT_VAULT_PROMPT=scripted \
    QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE=/home/qbv/passphrase \
    QBIT_VAULT_SCRIPTED_ANSWERS=/home/qbv/answers \
    QBIT_VAULT_SCRIPTED_TRANSCRIPT=/home/qbv/transcript
CMD ["sleep", "infinity"]
