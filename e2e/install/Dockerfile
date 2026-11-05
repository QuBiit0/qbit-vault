# syntax=docker/dockerfile:1
# Install-from-scratch battery (docs/TESTING.md § Tier 2 item 10). Build from
# the repository root: docker build -f e2e/install/Dockerfile .
#
# A clean official Go image, a fresh non-root user and an EMPTY home. The
# source tree is copied in; the scenario itself runs `go install` as that user.
# Test image: once the scenario has run it holds a binary built with
# -tags e2eprompt. Never push it.

FROM golang:1.26-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends jq python3 \
    && useradd --create-home --uid 10001 --shell /bin/bash qbv \
    && mkdir -p /home/qbv/fresh /home/qbv/src /home/qbv/go \
    && chown -R qbv:qbv /home/qbv
USER qbv
WORKDIR /home/qbv/src
# Dependencies first, so editing the source does not download them again.
COPY --chown=qbv:qbv go.mod go.sum ./
RUN go mod download
COPY --chown=qbv:qbv . .
COPY --chown=qbv:qbv --chmod=755 e2e/install/scenario.sh /home/qbv/install-scenario

# HOME is empty on purpose (nothing but the scenario's fake host dirs ends up
# in it); Go's GOPATH and caches live next to it, not inside it.
ENV HOME=/home/qbv/fresh \
    GOPATH=/home/qbv/go \
    GOCACHE=/home/qbv/gocache \
    GOFLAGS=-trimpath \
    CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    PATH=/home/qbv/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    XDG_RUNTIME_DIR=/dev/shm/qbv-run \
    QBIT_VAULT_HOME=/home/qbv/vault \
    QBIT_VAULT_PROMPT=scripted \
    QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE=/home/qbv/passphrase \
    QBIT_VAULT_SCRIPTED_ANSWERS=/home/qbv/answers \
    QBIT_VAULT_SCRIPTED_TRANSCRIPT=/home/qbv/transcript
ENTRYPOINT ["/home/qbv/install-scenario"]
