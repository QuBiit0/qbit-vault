#!/usr/bin/env bash
# Host registration e2e battery (docs/TESTING.md § Tier 2 item 9).
#
#   bash e2e/hosts-test.sh
#
# Builds the `hosts` image (qbit-vault built with -tags e2eprompt, plus bash,
# jq and python3), starts ONE container whose HOME is a fake user home, and
# runs e2e/hosts/scenario.sh in it: pre-existing Claude Code, Codex and Pi
# configs, init, idempotence, hooks, drift, uninstall and --purge, and a leak
# scan. The binary never runs on the host, no real home is mounted, and no
# real claude, codex or pi exists in the image. Prints PASS or FAIL per check,
# `N passed, M failed`, exits non-zero on any failure and always tears down its
# own compose project (qbv-e2e-hosts) when it ends.
set -euo pipefail

# Git Bash would rewrite container paths into C:/Program Files/...
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."
PROJECT=qbv-e2e-hosts
DC=(docker compose -p "$PROJECT" -f e2e/hosts/compose.yaml)
WORK=$(mktemp -d)

teardown() {
  local rc=$?
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit "$rc"
}
trap teardown EXIT

printf '== build the hosts image and start the container\n'
if ! "${DC[@]}" up -d --build --wait >"$WORK/up.log" 2>&1; then
  printf 'FAIL  stack up\n      %s\n' "$(tail -n 15 "$WORK/up.log" | tr '\n' ' ')"
  printf '\n0 passed, 1 failed\nFAIL: hosts e2e battery\n'
  exit 1
fi
printf 'PASS  container up (fake HOME %s)\n' "$("${DC[@]}" exec -T hosts printenv HOME | tr -d '\r')"

RC=0
"${DC[@]}" exec -T hosts hosts-scenario 2>&1 | tee "$WORK/scenario.log" || RC=${PIPESTATUS[0]}

if [[ $RC -ne 0 ]] || ! grep -qE '^[0-9]+ passed, 0 failed$' "$WORK/scenario.log"; then
  printf 'FAIL: hosts e2e battery\n'
  exit 1
fi
printf 'PASS: hosts e2e battery\n'
