#!/usr/bin/env bash
# Install-from-scratch e2e battery (docs/TESTING.md § Tier 2 item 10).
#
#   bash e2e/install-test.sh
#
# Builds the image of e2e/install/Dockerfile (official golang image, a fresh
# non-root user, an empty HOME, the source tree copied in) and runs ONE
# container from it: e2e/install/scenario.sh does `go install`, init, set, an
# MCP agent session, audit, doctor, uninstall and uninstall --purge, then scans
# every byte it captured for the TESTSECRET_ fixtures. The binary never runs on
# the host and nothing from the host is mounted. Prints PASS or FAIL per check,
# `N passed, M failed`, exits non-zero on any failure and always removes its
# container and image.
set -euo pipefail

# Git Bash would rewrite container paths into C:/Program Files/...
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."
IMAGE=qbit-vault-e2e-install:local
NAME=qbv-e2e-install
WORK=$(mktemp -d)

teardown() {
  local rc=$?
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit "$rc"
}
trap teardown EXIT

printf '== build the clean install image (golang image, user qbv, empty HOME, source copied in)\n'
if ! docker build -q -t "$IMAGE" -f e2e/install/Dockerfile . >"$WORK/build.log" 2>&1; then
  printf 'FAIL  image build\n      %s\n' "$(tail -n 15 "$WORK/build.log" | tr '\n' ' ')"
  printf '\n0 passed, 1 failed\nFAIL: install e2e battery\n'
  exit 1
fi
printf 'PASS  image built\n'

RC=0
docker run --rm --init --name "$NAME" --cap-drop ALL --security-opt no-new-privileges:true \
  "$IMAGE" 2>&1 | tee "$WORK/scenario.log" || RC=${PIPESTATUS[0]}

if [[ $RC -ne 0 ]] || ! grep -qE '^[0-9]+ passed, 0 failed$' "$WORK/scenario.log"; then
  printf 'FAIL: install e2e battery\n'
  exit 1
fi
# The scenario output is what the user sees: it must not hold the fixtures either.
if grep -qF 'TESTSECRET_value_' "$WORK/scenario.log"; then
  printf 'FAIL  the scenario output holds a fixture value\n'
  printf 'FAIL: install e2e battery\n'
  exit 1
fi
printf 'PASS: install e2e battery\n'
