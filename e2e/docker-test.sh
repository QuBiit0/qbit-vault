#!/usr/bin/env bash
# Sync e2e battery (docs/TESTING.md § Tier 2 item 7).
#
#   bash e2e/docker-test.sh
#
# Builds the server and client images, brings up one qbit-vault-server behind
# a recording TLS proxy and three client containers (A, B, C), runs the sync
# scenario with prompts driven by the e2eprompt test backend, asserts every
# step, then scans the server's whole /data volume, every recorded HTTP
# exchange and the clients' vault homes for every fixture value, secret name,
# project path and device label (R-SYNC-02). Prints PASS or FAIL per check and
# exits non-zero if any failed. The stack is always torn down (its own compose
# project only) when the script ends.
set -euo pipefail

# Git Bash would rewrite container paths such as /certs into C:/Program Files/...
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."
PROJECT=qbv-e2e-sync
DC=(docker compose -p "$PROJECT" -f e2e/compose.yaml)
WORK=$(mktemp -d)
SERVER_URL=https://proxy:8443
CA=/certs/ca.pem

teardown() {
  local rc=$?
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit "$rc"
}
trap teardown EXIT

# ---- fixtures (TESTSECRET_ prefix: a leak in CI output is greppable) ----

PASSPHRASE=TESTSECRET_passphrase_e2e_7c1d
N_GLOBAL=TESTSECRET_E2E_GLOBAL_KEY
N_SHARED=TESTSECRET_E2E_SHARED_KEY
N_PROJECT=TESTSECRET_E2E_PROJECT_KEY
N_LATE=TESTSECRET_E2E_LATE_KEY
V_GLOBAL=TESTSECRET_value_global_a1b2c3d4
V_SHARED=TESTSECRET_value_shared_e5f6a7b8
V_A_EDIT=TESTSECRET_value_edit_on_A_9a8b7c6d
V_B_EDIT=TESTSECRET_value_edit_on_B_5e4f3a2b
V_PROJECT=TESTSECRET_value_project_1c2d3e4f
V_LATE=TESTSECRET_value_late_0f9e8d7c
LABEL_A=e2e-laptop-a      # container hostnames: the label register and recovery give a device
LABEL_B=e2e-device-b-label # typed by the approver
LABEL_C=e2e-phone-c
PROJECT_LABEL=e2e-project-alpha
PROJECT_PATH_A=/home/qbv/work/$PROJECT_LABEL
PROJECT_PATH_B=/home/qbv/checkout/$PROJECT_LABEL

# ---- reporting ----

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %s\n' "$1"; }
fail() {
  FAILS=$((FAILS + 1))
  printf 'FAIL  %s\n' "$1"
  [[ -n "${2:-}" ]] && printf '      %s\n' "$2"
  return 0
}
step() { printf '\n== %s\n' "$1"; }
snippet() { printf '%s' "$1" | tr '\n' ' ' | cut -c1-300; }

# ---- running commands in the containers ----

RC=0 OUT='' ERR=''
EXECENV=()   # extra "-e VAR=value" arguments for the next run
WD=/home/qbv  # working directory of the next run

# run NODE CMD...: runs CMD in the container, sets RC, OUT and ERR.
run() {
  local node=$1 o e wd=$WD
  shift
  [[ $node == auditor ]] && wd=/
  o=$(mktemp -p "$WORK")
  e=$(mktemp -p "$WORK")
  RC=0
  "${DC[@]}" exec -T -w "$wd" "${EXECENV[@]}" "$node" "$@" >"$o" 2>"$e" || RC=$?
  OUT=$(cat "$o")
  ERR=$(cat "$e")
  cat "$o" "$e" >>"$WORK/captured.log"
  rm -f "$o" "$e"
  EXECENV=()
  WD=/home/qbv
}
qbv() { local node=$1; shift; run "$node" qbit-vault "$@"; }

# set_answers NODE ANSWER...: the answers the node's prompts read, in order,
# and a fresh transcript.
set_answers() {
  local node=$1
  shift
  { [[ $# -gt 0 ]] && printf '%s\n' "$@" || true; } |
    "${DC[@]}" exec -T "$node" sh -c ': >"$QBIT_VAULT_SCRIPTED_TRANSCRIPT"; cat >"$QBIT_VAULT_SCRIPTED_ANSWERS"'
}
add_answer() { printf '%s\n' "$2" | "${DC[@]}" exec -T "$1" sh -c 'cat >>"$QBIT_VAULT_SCRIPTED_ANSWERS"'; }
transcript() { "${DC[@]}" exec -T "$1" cat /home/qbv/transcript; }

# wait_transcript NODE REGEX SECONDS: succeeds once the transcript matches.
wait_transcript() {
  local node=$1 re=$2 i t
  for ((i = 0; i < $3 * 2; i++)); do
    t=$(transcript "$node" 2>/dev/null || true)
    grep -qE -- "$re" <<<"$t" && return 0
    sleep 0.5
  done
  return 1
}

# bg_start NODE NAME ARGS...: runs qbit-vault ARGS detached; bg_wait collects it.
bg_start() {
  local node=$1 name=$2
  shift 2
  "${DC[@]}" exec -d -w /home/qbv "$node" sh -c \
    'rm -f "bg.$0".*; qbit-vault "$@" >"bg.$0.out" 2>"bg.$0.err"; echo $? >"bg.$0.rc"' "$name" "$@"
}
bg_wait() {
  local node=$1 name=$2 i
  for ((i = 0; i < $3 * 2; i++)); do
    if RC=$("${DC[@]}" exec -T "$node" cat "bg.$name.rc" 2>/dev/null); then
      OUT=$("${DC[@]}" exec -T "$node" cat "bg.$name.out")
      ERR=$("${DC[@]}" exec -T "$node" cat "bg.$name.err")
      printf '%s\n%s\n' "$OUT" "$ERR" >>"$WORK/captured.log"
      return 0
    fi
    sleep 0.5
  done
  RC=124 OUT='' ERR="timed out waiting for $name on $node"
  return 1
}

# ---- assertions on the last run ----

expect_rc() { if [[ $RC -eq $2 ]]; then pass "$1"; else fail "$1" "exit $RC, want $2; stdout: $(snippet "$OUT") stderr: $(snippet "$ERR")"; fi; }
expect_out() { if grep -qF -- "$2" <<<"$OUT"; then pass "$1"; else fail "$1" "stdout lacks $2: $(snippet "$OUT")"; fi; }
expect_err() { if grep -qF -- "$2" <<<"$ERR"; then pass "$1"; else fail "$1" "stderr lacks $2: $(snippet "$ERR")"; fi; }
expect_ok_json() { expect_rc "$1" 0; expect_out "$1: JSON $2" "$2"; }
expect_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "got [$2], want [$3]"; fi; }
expect_ne() { if [[ "$2" != "$3" ]]; then pass "$1"; else fail "$1" "both are [$2]"; fi; }
expect_json_code() { # DESC EXIT CODE
  expect_rc "$1" "$2"
  expect_out "$1: error code" "\"code\":\"$3\""
}

sha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

# reveal NODE SESSION NAME: runs reveal.sh under exec; prints the sha256 of
# the injected value (the value itself never leaves the child).
reveal() {
  qbv "$1" exec --json --session "$2" --secret "$3" -- sh reveal.sh "$3"
  sed -n 's/.*"stdout":"\([0-9a-f]\{64\}\).*/\1/p' <<<"$OUT"
}

# grant NODE SESSION NAME: a session grant, confirmed on the prompt backend.
grant() {
  set_answers "$1" y
  qbv "$1" grant "$3" --global --scope session --session "$2"
}

# ---- the scenario ----

step "build images and start the stack"
if "${DC[@]}" up -d --build --wait >"$WORK/up.log" 2>&1; then
  pass "stack up: server, recording TLS proxy, clients A B C, auditor"
else
  fail "stack up" "$(tail -n 15 "$WORK/up.log" | tr '\n' ' ')"
  exit 1
fi

step "leak scanner self-check (a scanner that finds nothing proves nothing)"
"${DC[@]}" exec -T auditor sh -c 'rm -rf /tmp/canary && mkdir -p /tmp/canary/clean /tmp/canary/raw /tmp/canary/b64 /tmp/canary/json
  printf "canary\tTESTSECRET_canary_needle_42\n" >/tmp/canary/needles
  echo "nothing to see" >/tmp/canary/clean/f
  printf "xx TESTSECRET_canary_needle_42 yy" >/tmp/canary/raw/f
  printf "pad:" >/tmp/canary/b64/f; printf "TESTSECRET_canary_needle_42" | base64 -w0 >>/tmp/canary/b64/f
  printf "{\"v\":\"TESTSECRET_canary_needle_42\"}" >/tmp/canary/json/f'
for kind in raw b64 json; do
  if "${DC[@]}" exec -T auditor leakscan -needles /tmp/canary/needles /tmp/canary/$kind >/dev/null 2>&1; then
    fail "scanner finds a planted needle ($kind)"
  else
    pass "scanner finds a planted needle ($kind)"
  fi
done
if "${DC[@]}" exec -T auditor leakscan -needles /tmp/canary/needles /tmp/canary/clean >/dev/null 2>&1; then
  pass "scanner passes a clean tree"
else
  fail "scanner passes a clean tree"
fi

step "setup: every client starts a passphrase-mode vault"
for n in a b c; do
  printf '%s
' "$PASSPHRASE" | "${DC[@]}" exec -T "$n" sh -c 'cat >"$QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE"'
  # prints the sha256 of the value of $1, so a test can compare without seeing it
  "${DC[@]}" exec -T "$n" sh -c 'cat >reveal.sh' <<'SH'
v=$(printenv "$1")
printf '%s' "$v" | sha256sum | cut -d' ' -f1
SH
  set_answers "$n"
  qbv "$n" init --passphrase --json
  expect_ok_json "init $n" '"initialized":true'
  expect_out "init $n uses the passphrase file (no keychain in the container)" 'passphrase-file'
done

step "A: global and project secrets before the first sync"
set_answers a "$V_GLOBAL"
qbv a set "$N_GLOBAL" --global
expect_rc "A set global" 0
set_answers a "$V_SHARED"
qbv a set "$N_SHARED" --global
expect_rc "A set shared" 0
"${DC[@]}" exec -T a sh -c "mkdir -p $PROJECT_PATH_A/.git"
set_answers a "$V_PROJECT"
WD=$PROJECT_PATH_A qbv a set "$N_PROJECT" --project
expect_rc "A set project secret" 0

step "A registers the account (recovery key shown through the prompt backend)"
INVITE=$("${DC[@]}" exec -T server /qbit-vault-server invite | tr -d '\r\n')
set_answers a "$INVITE" y
bg_start a register remote register --server "$SERVER_URL" --ca-file "$CA" --json
if wait_transcript a 'SHOW Recovery key' 60; then
  RECOVERY_KEY=$(transcript a | grep -oE 'QVR1(-[A-Z0-9]{4})+' | sed -n 1p)
  flat=${RECOVERY_KEY//-/}
  add_answer a "${flat: -4}"
else
  RECOVERY_KEY=''
fi
bg_wait a register 60 || true
expect_ok_json "A register" '"registered":true'
expect_eq "recovery key was shown" "$([[ -n $RECOVERY_KEY ]] && echo yes || echo no)" yes
qbv a remote status --json
expect_ok_json "A status" '"generation":1'
expect_out "A status: recovery key confirmed" '"recovery_confirmed":true'

step "B joins by pairing (two live processes: join polls while approve runs)"
set_answers b y
bg_start b join remote join --server "$SERVER_URL" --ca-file "$CA" --json
PAIRING=''
for _ in $(seq 1 60); do
  PAIRING=$("${DC[@]}" exec -T b cat bg.join.err 2>/dev/null | sed -n 's/^pairing code: //p' | sed -n 1p || true)
  [[ -n $PAIRING ]] && break
  sleep 0.5
done
expect_eq "B printed a pairing code" "$([[ -n $PAIRING ]] && echo yes || echo no)" yes
set_answers a "$PAIRING" "$LABEL_B" y
qbv a remote approve --json
expect_ok_json "A approve" '"approved":true'
wait_transcript a 'SHOW Pairing code' 10 || true
CONFIRM=$(transcript a | sed -n 's/^| \([A-Z0-9]\{4\}-[A-Z0-9]\{4\}\)$/\1/p' | tail -n1 || true)
expect_eq "A showed a confirmation code" "$([[ -n $CONFIRM ]] && echo yes || echo no)" yes
add_answer b "$CONFIRM"
bg_wait b join 60 || true
expect_ok_json "B join (pairing)" '"joined":true'

step "C joins by recovery key"
set_answers c y "$RECOVERY_KEY"
qbv c remote join --recovery --server "$SERVER_URL" --ca-file "$CA" --json
expect_ok_json "C join (recovery)" '"joined":true'

step "a secret set on A is listed and, after a grant, usable on B and C"
for n in b c; do
  qbv "$n" list --json
  expect_ok_json "$n lists A's global secret" "\"name\":\"$N_GLOBAL\""
done
set_answers b
qbv b exec --json --session e2e:sess-b-0 --secret "$N_GLOBAL" -- sh reveal.sh "$N_GLOBAL"
if [[ $RC -ne 0 ]] && ! grep -qF "$(sha "$V_GLOBAL")" <<<"$OUT$ERR"; then
  pass "B exec without a grant is refused"
else
  fail "B exec without a grant is refused" "exit $RC: $(snippet "$OUT$ERR")"
fi
grant b e2e:sess-b-1 "$N_GLOBAL"
expect_rc "B grant" 0
expect_eq "B exec injects the value A set" "$(reveal b e2e:sess-b-1 "$N_GLOBAL")" "$(sha "$V_GLOBAL")"
grant c e2e:sess-c-1 "$N_GLOBAL"
expect_eq "C exec injects the value A set" "$(reveal c e2e:sess-c-1 "$N_GLOBAL")" "$(sha "$V_GLOBAL")"

step "offline edits of one record on A and B: one winner, one conflict"
EXECENV=(-e QBIT_VAULT_NO_REMOTE=1)
set_answers a "$V_A_EDIT"
qbv a set "$N_SHARED" --global
expect_rc "A edits offline" 0
sleep 1
EXECENV=(-e QBIT_VAULT_NO_REMOTE=1)
set_answers b "$V_B_EDIT"
qbv b set "$N_SHARED" --global
expect_rc "B edits offline" 0
qbv a remote sync --json
expect_rc "A syncs (pushes its edit)" 0
qbv b remote sync --json
expect_rc "B syncs (merges against A's edit)" 0
qbv a remote sync --json
expect_rc "A syncs (pulls the merge)" 0
for n in a b; do
  qbv "$n" remote conflicts --json
  expect_ok_json "$n sees the conflict" "\"name\":\"$N_SHARED\""
  count=$( (grep -o '"lost_at"' <<<"$OUT" || true) | wc -l | tr -d ' ')
  expect_eq "$n has exactly one conflict" "$count" 1
done
grant a e2e:sess-a-1 "$N_SHARED"
grant b e2e:sess-b-1 "$N_SHARED"
WIN_A=$(reveal a e2e:sess-a-1 "$N_SHARED")
WIN_B=$(reveal b e2e:sess-b-1 "$N_SHARED")
expect_eq "A and B converge on one winner" "$WIN_A" "$WIN_B"
# the higher hybrid logical clock wins, and B edited a second after A
expect_eq "the later edit (B's) is the winner" "$WIN_A" "$(sha "$V_B_EDIT")"

step "a project layer appears on B only after link"
qbv b remote sync --json
expect_rc "B syncs the project layer" 0
"${DC[@]}" exec -T b sh -c "mkdir -p $PROJECT_PATH_B/.git"
WD=$PROJECT_PATH_B qbv b list --json
if grep -qF "$N_PROJECT" <<<"$OUT"; then fail "B before link: the project secret is invisible" "$(snippet "$OUT")"; else pass "B before link: the project secret is invisible"; fi
qbv b list --layer all --json
expect_out "B before link: the layer is listed as unlinked" '"unlinked":true'
set_answers b y
WD=$PROJECT_PATH_B qbv b link "$PROJECT_LABEL" --json
expect_ok_json "B link" "\"label\":\"$PROJECT_LABEL\""
WD=$PROJECT_PATH_B qbv b list --json
expect_out "B after link: the project secret is listed" "\"name\":\"$N_PROJECT\""

step "revoke C: C gets device_revoked, A and B move to generation 2"
qbv a remote sync --json
qbv a remote devices --json
C_ID=$(sed -n "s/.*\"id\":\"\([^\"]*\)\",\"label\":\"$LABEL_C\".*/\1/p" <<<"$OUT")
expect_eq "A found C in the roster" "$([[ -n $C_ID ]] && echo yes || echo no)" yes
set_answers a y
bg_start a revoke remote revoke-device "$C_ID" --json
if wait_transcript a 'SHOW Recovery key' 60; then
  NEW_KEY=$(transcript a | grep -oE 'QVR1(-[A-Z0-9]{4})+' | tail -n1)
  flat=${NEW_KEY//-/}
  add_answer a "${flat: -4}"
else
  NEW_KEY=''
fi
bg_wait a revoke 90 || true
expect_ok_json "A revoke-device" '"generation":2'
expect_ne "the recovery key was replaced" "$NEW_KEY" "$RECOVERY_KEY"
qbv c remote sync --json
expect_json_code "C is refused with device_revoked" 1 device_revoked
qbv b remote sync --json
expect_rc "B syncs and adopts the new key" 0
for n in a b; do
  qbv "$n" remote status --json
  # status exits 1 while there is a warning, and the conflict is one
  expect_out "$n is on generation 2" '"generation":2'
  expect_out "$n still lists the conflict after the key rotation" '"conflicts":1'
done
qbv c list --json
expect_out "C keeps its local vault readable" "\"name\":\"$N_GLOBAL\""

step "a secret set on A after the revoke reaches B (generation 2)"
set_answers a "$V_LATE"
qbv a set "$N_LATE" --global
expect_rc "A set after revoke" 0
qbv b remote sync --json
expect_rc "B pulls it" 0
qbv b list --json
expect_out "B lists the late secret" "\"name\":\"$N_LATE\""

step "a server replaying an old version is refused with remote_rollback"
qbv b remote status --json
LAST_B=$(sed -n 's/.*"version":\([0-9]*\).*/\1/p' <<<"$OUT")
# the oldest recorded generation-2 vault response: older than what B has seen
OLD=$("${DC[@]}" exec -T auditor sh -c 'for m in /rec/*.meta; do
  n=$(basename "$m" .meta)
  if [ "$(sed -n 1p "$m")" = "GET /v1/vault" ] && sed -n 2p "$m" | grep -q "^status 200$" && grep -q "\"generation\":2" "/rec/$n.resp"; then echo "$n"; break; fi
done' | tr -d '\r\n')
OLD_VERSION=$("${DC[@]}" exec -T auditor cat "/rec/$OLD.resp" 2>/dev/null | sed -n 's/.*"version":\([0-9]*\).*/\1/p' | sed -n 1p)
if [[ -n $OLD && -n $OLD_VERSION && -n $LAST_B && $OLD_VERSION -lt $LAST_B ]]; then
  pass "found a recorded generation-2 response (version $OLD_VERSION) older than B's version $LAST_B"
else
  fail "found an older recorded response" "old=[$OLD] old_version=[$OLD_VERSION] b_version=[$LAST_B]"
fi
before=$("${DC[@]}" exec -T b sh -c 'sha256sum vault/vault.enc vault/key.enc')
"${DC[@]}" exec -T proxy sh -c "echo '$OLD' >/rec/control/replay"
qbv b remote sync --json
expect_json_code "B refuses the replayed version" 5 remote_rollback
after=$("${DC[@]}" exec -T b sh -c 'sha256sum vault/vault.enc vault/key.enc')
expect_eq "B's vault is unchanged" "$after" "$before"
"${DC[@]}" exec -T proxy sh -c 'rm -f /rec/control/replay'
qbv b remote sync --json
expect_rc "B syncs again once the server tells the truth" 0

step "leak scan (R-SYNC-02): the server's /data, every HTTP exchange, the client homes"
{
  printf 'value-global\t%s\nvalue-shared\t%s\nvalue-edit-a\t%s\nvalue-edit-b\t%s\nvalue-project\t%s\nvalue-late\t%s\n' \
    "$V_GLOBAL" "$V_SHARED" "$V_A_EDIT" "$V_B_EDIT" "$V_PROJECT" "$V_LATE"
  printf 'passphrase\t%s\n' "$PASSPHRASE"
  [[ -n $RECOVERY_KEY ]] && printf 'recovery-key\t%s\nrecovery-key-flat\t%s\n' "$RECOVERY_KEY" "${RECOVERY_KEY//-/}"
  [[ -n ${NEW_KEY:-} ]] && printf 'recovery-key-2\t%s\nrecovery-key-2-flat\t%s\n' "$NEW_KEY" "${NEW_KEY//-/}"
  [[ -n ${CONFIRM:-} ]] && [[ ${#CONFIRM} -ge 8 ]] && printf 'confirmation-code\t%s\n' "$CONFIRM"
} >"$WORK/values.needles"
{
  cat "$WORK/values.needles"
  printf 'name-global\t%s\nname-shared\t%s\nname-project\t%s\nname-late\t%s\n' "$N_GLOBAL" "$N_SHARED" "$N_PROJECT" "$N_LATE"
  printf 'project-path-a\t%s\nproject-path-b\t%s\nproject-label\t%s\n' "$PROJECT_PATH_A" "$PROJECT_PATH_B" "$PROJECT_LABEL"
  printf 'label-a\t%s\nlabel-b\t%s\nlabel-c\t%s\n' "$LABEL_A" "$LABEL_B" "$LABEL_C"
} >"$WORK/all.needles"
"${DC[@]}" exec -T auditor sh -c 'cat >/tmp/all.needles' <"$WORK/all.needles"
run auditor leakscan -needles /tmp/all.needles /data /rec
expect_rc "server /data and the recorded HTTP exchanges hold no value, name, path or label" 0
files=$(sed -n 's/^leakscan: \([0-9]*\) files.*/\1/p' <<<"$OUT")
exchanges=$("${DC[@]}" exec -T auditor sh -c 'ls /rec/*.meta | wc -l' | tr -d '\r\n ')
if [[ ${files:-0} -ge 10 && ${exchanges:-0} -ge 20 ]]; then
  pass "the scan was not vacuous ($files files, $exchanges exchanges)"
else
  fail "the scan was not vacuous" "files=$files exchanges=$exchanges"
fi
for n in a b c; do
  "${DC[@]}" exec -T "$n" sh -c 'cat >/tmp/values.needles' <"$WORK/values.needles"
  run "$n" leakscan -needles /tmp/values.needles /home/qbv/vault
  expect_rc "$n: the vault home holds no value (the audit log may name secrets)" 0
done
# positive control on real data: the audit log of A names the secrets, so the
# full needle set must hit there, or the scan above could not have seen a name
"${DC[@]}" exec -T a sh -c 'cat >/tmp/all.needles' <"$WORK/all.needles"
run a leakscan -needles /tmp/all.needles /home/qbv/vault
expect_rc "positive control: the scan reports the names in A's own audit log" 1
# everything the qbit-vault commands printed (exec output is redacted, so no value may be there)
if grep -qF -f <(cut -f2 "$WORK/values.needles" | grep -v '^$') "$WORK/captured.log"; then
  fail "no command output contained a fixture value or key"
else
  pass "no command output contained a fixture value or key ($(wc -l <"$WORK/captured.log" | tr -d ' ') lines)"
fi

printf '\n%d passed, %d failed\n' "$PASSES" "$FAILS"
if [[ $FAILS -gt 0 ]]; then
  printf 'FAIL: sync e2e battery\n'
  exit 1
fi
printf 'PASS: sync e2e battery\n'
