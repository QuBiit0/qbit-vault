# syntax=docker/dockerfile:1
# gentle-vault-server: zero-knowledge sync server (docs/REMOTE_SYNC.md § 10).
# Build from the repository root: docker build -f deploy/Dockerfile .

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/gentle-vault-server ./cmd/gentle-vault-server
# /data must belong to the runtime user: a new volume copies this ownership.
RUN mkdir -p /out/data && chmod 0700 /out/data

# Static binary on distroless: no shell, no package manager, non-root (65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gentle-vault-server /gentle-vault-server
COPY --from=build --chown=65532:65532 /out/data /data
ENV GV_SERVER_DATA=/data \
    GV_SERVER_LISTEN=:8080
VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/gentle-vault-server", "health"]
ENTRYPOINT ["/gentle-vault-server"]
CMD ["serve"]
