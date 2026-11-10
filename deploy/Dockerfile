# syntax=docker/dockerfile:1
# qbit-vault-server: zero-knowledge sync server (docs/REMOTE_SYNC.md § 10).
# Build from the repository root: docker build -f deploy/Dockerfile .

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/qbit-vault-server ./cmd/qbit-vault-server
# /data must belong to the runtime user: a new volume copies this ownership.
RUN mkdir -p /out/data && chmod 0700 /out/data

# Static binary on distroless: no shell, no package manager, non-root (65532).
FROM gcr.io/distroless/static-debian12:nonroot
# Links the published image to its repository on GitHub (ghcr shows it under
# the repository and takes its description and license from these labels).
LABEL org.opencontainers.image.source="https://github.com/qbitdevz/qbit-vault" \
      org.opencontainers.image.description="QBit Vault sync server: stores only data sealed on your devices" \
      org.opencontainers.image.licenses="MIT"
# The version the server reports in /v1/info and on its status page.
ARG VERSION=dev
COPY --from=build /out/qbit-vault-server /qbit-vault-server
COPY --from=build --chown=65532:65532 /out/data /data
ENV QBV_SERVER_VERSION=${VERSION} \
    QBV_SERVER_DATA=/data \
    QBV_SERVER_LISTEN=:8080
VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/qbit-vault-server", "health"]
ENTRYPOINT ["/qbit-vault-server"]
CMD ["serve"]
