#!/usr/bin/env bash
# Regenerates the README demo assets from the real binary:
#   assets/screenshots/tui-home.png, assets/demo/tui.gif, assets/demo/cli.gif
# Needs Go and Docker. Usage: bash assets/demo/make.sh
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'   # Git Bash on Windows

cd "$(dirname "$0")/../.."
ROOT=$(pwd)
VHS_IMAGE=${VHS_IMAGE:-ghcr.io/charmbracelet/vhs}
host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf "%s" "$1"; fi; }
# The version shown in the TUI header. Defaults to the release being announced.
DEMO_VERSION=${DEMO_VERSION:-v1.0.0}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The scripted prompt backend (e2eprompt tag) answers the demo setup's prompts
# from a file. This binary is only for the demo: never ship it.
echo "building the demo binary"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags e2eprompt -ldflags "-s -w -X github.com/qbitdevz/qbit-vault/internal/cli.Version=$DEMO_VERSION -X github.com/qbitdevz/qbit-vault/internal/cli.Commit=release" -o "$(host_path "$WORK")/qbit-vault" ./cmd/qbit-vault
mkdir -p "$WORK/out"
cp assets/demo/*.tape assets/demo/setup-demo.sh "$WORK/"



echo "recording with VHS ($VHS_IMAGE)"
docker run --rm --entrypoint bash \
  -v "$(host_path "$WORK"):/work" -w /work \
  -e QBIT_VAULT_HOME=/root/demo/vault -e HOME=/root/demo \
  -e XDG_RUNTIME_DIR=/dev/shm/demo-runtime -e QBIT_VAULT_PROMPT=scripted \
  -e QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE=/root/demo/.passphrase \
  -e QBIT_VAULT_SCRIPTED_ANSWERS=/root/demo/.answers \
  -e QBIT_VAULT_SCRIPTED_TRANSCRIPT=/root/demo/.transcript \
  -e QBIT_VAULT_NO_REMOTE=1 -e QBIT_VAULT_NO_UPDATE_CHECK=1 -e QBIT_VAULT_SESSION=demo:vhs-1 \
  "$VHS_IMAGE" -c '
    set -e
    install -m 0755 /work/qbit-vault /usr/local/bin/qbit-vault
    bash /work/setup-demo.sh
    cd /root/demo/work/acme-api
    vhs /work/tui.tape
    vhs /work/cli.tape
  '

mkdir -p assets/screenshots
cp "$WORK/out/tui-home.png" assets/screenshots/tui-home.png
cp "$WORK/out/tui.gif" assets/demo/tui.gif
cp "$WORK/out/cli.gif" assets/demo/cli.gif
ls -l assets/screenshots/tui-home.png assets/demo/tui.gif assets/demo/cli.gif
