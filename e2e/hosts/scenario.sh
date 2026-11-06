#!/usr/bin/env bash
# Runs INSIDE the hosts container (e2e/Dockerfile target `hosts`), driven by
# e2e/hosts-test.sh. HOME is a fake user home; the real binaries of claude,
# codex and pi do not exist, only their config directories. Prints PASS or
# FAIL per check and "N passed, M failed"; exits non-zero on any failure.
set -euo pipefail

VAULT=$QBIT_VAULT_HOME
PASSPHRASE=TESTSECRET_passphrase_hosts_3e9a
SECRET_NAME=HOSTS_API_KEY
SECRET=TESTSECRET_value_hosts_0a1b2c3d4e5f
WORK=$(mktemp -d)
LOG=$WORK/captured.log
: >"$LOG"

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
snippet() { printf '%s' "$1" | tr '\n' ' ' | cut -c1-400; }

RC=0 OUT='' ERR=''
# run CMD...: sets RC, OUT, ERR and appends both streams to the captured log.
run() {
  RC=0
  "$@" >"$WORK/o" 2>"$WORK/e" || RC=$?
  OUT=$(cat "$WORK/o")
  ERR=$(cat "$WORK/e")
  cat "$WORK/o" "$WORK/e" >>"$LOG"
}
# runin STDIN CMD...: like run with STDIN as standard input.
runin() {
  local in=$1
  shift
  RC=0
  printf '%s' "$in" | "$@" >"$WORK/o" 2>"$WORK/e" || RC=$?
  OUT=$(cat "$WORK/o")
  ERR=$(cat "$WORK/e")
  cat "$WORK/o" "$WORK/e" >>"$LOG"
}
qbv() { run qbit-vault "$@"; }
# answers LINE...: a fresh answers file (one line per prompt, in order) and transcript.
answers() {
  : >"$QBIT_VAULT_SCRIPTED_TRANSCRIPT"
  if [[ $# -gt 0 ]]; then printf '%s\n' "$@" >"$QBIT_VAULT_SCRIPTED_ANSWERS"; else : >"$QBIT_VAULT_SCRIPTED_ANSWERS"; fi
}

expect_rc() { if [[ $RC -eq $2 ]]; then pass "$1"; else fail "$1" "exit $RC, want $2; stdout: $(snippet "$OUT") stderr: $(snippet "$ERR")"; fi; }
expect_out() { if grep -qF -- "$2" <<<"$OUT"; then pass "$1"; else fail "$1" "stdout lacks [$2]: $(snippet "$OUT")"; fi; }
expect_no_out() { if grep -qF -- "$2" <<<"$OUT$ERR"; then fail "$1" "output holds [$2]: $(snippet "$OUT$ERR")"; else pass "$1"; fi; }
expect_empty_err() { if [[ -z $ERR ]]; then pass "$1"; else fail "$1" "stderr: $(snippet "$ERR")"; fi; }
expect_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "got [$2], want [$3]"; fi; }
# jqt DESC FILE FILTER: the jq filter must output true.
jqt() { if [[ $(jq -r "$3" "$2" 2>&1) == true ]]; then pass "$1"; else fail "$1" "jq $3 on $2 => $(jq -c "$3" "$2" 2>&1 | head -c 300)"; fi; }
has() { if grep -qF -- "$3" "$2"; then pass "$1"; else fail "$1" "$2 lacks [$3]"; fi; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

CLAUDE_JSON=$HOME/.claude.json
SETTINGS=$HOME/.claude/settings.json
CODEX=$HOME/.codex/config.toml
PI_MCP=$HOME/.pi/agent/mcp.json

# ---- step 1: the fake home, with user configs that must survive ----

step "1. fake HOME with the user's own configs (no claude, codex or pi binary)"
mkdir -p "$HOME/.claude" "$HOME/.codex" "$HOME/.pi/agent"
# tabs, an unusual key order and unrelated keys: our merge must keep all of it
printf '{\n\t"numStartups": 42,\n\t"theme": "dark",\n\t"mcpServers": {\n\t\t"other-mcp": { "command": "npx", "args": ["-y", "other-mcp"] }\n\t},\n\t"projects": { "/work/x": { "allowedTools": [] } }\n}\n' >"$CLAUDE_JSON"
printf '{\n\t"model": "opus",\n\t"permissions": { "deny": ["Read(./.env)"], "allow": ["Bash(git status)"] },\n\t"hooks": {\n\t\t"PreToolUse": [\n\t\t\t{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "gentle-ai hook guard" }] }\n\t\t],\n\t\t"Stop": [ { "hooks": [{ "type": "command", "command": "notify-send done" }] } ]\n\t}\n}\n' >"$SETTINGS"
printf '# my codex config\r\nmodel = "gpt-5"   # keep me\r\n\r\n[mcp_servers.x]\r\ncommand = "x-server"\r\nargs = ["--flag"]\r\n\r\n[profiles.fast]\r\nmodel = "small"\r\n' >"$CODEX"
printf '{\n  "mcpServers": {\n    "pi-other": { "command": "pi-other", "args": [] }\n  }\n}\n' >"$PI_MCP"
ORIG_CLAUDE=$(sha "$CLAUDE_JSON") ORIG_SETTINGS=$(sha "$SETTINGS") ORIG_CODEX=$(sha "$CODEX") ORIG_PI=$(sha "$PI_MCP")
cp "$CLAUDE_JSON" "$WORK/claude.json.orig"
if ! command -v claude >/dev/null && ! command -v codex >/dev/null && ! command -v pi >/dev/null && ! command -v gentle-shell >/dev/null; then
  pass "no real claude, codex or pi binary in the image (detection is by directory)"
else
  fail "no real claude, codex or pi binary in the image"
fi
printf '%s\n' "$PASSPHRASE" >"$QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE"
# the passphrase unlock cache lives in $XDG_RUNTIME_DIR (tmpfs); the hooks need it
mkdir -p -m 700 "$XDG_RUNTIME_DIR"

# ---- step 2: init registers the three hosts ----

step "2. init --passphrase registers claude-code, codex and pi"
answers
qbv init --passphrase
expect_rc "init exits 0" 0
expect_empty_err "init writes nothing to stderr"
expect_out "init: claude-code line" $'host claude-code: registered (mcp, hooks, deny, skill)\n'
expect_out "init: codex line" $'host codex: registered (mcp, skill)\n'
# Pi shares ~/.agents/skills with Codex, which already wrote the skill.
expect_out "init: pi line (no extension line while it is unpublished)" $'host pi: registered (mcp)\n'
CLAUDE_SKILL="$HOME/.claude/skills/qbit-vault/SKILL.md"
AGENTS_SKILL="$HOME/.agents/skills/qbit-vault/SKILL.md"
if [[ -f $CLAUDE_SKILL && -f $AGENTS_SKILL ]] && grep -q '^name: qbit-vault$' "$CLAUDE_SKILL" && cmp -s "$CLAUDE_SKILL" "$AGENTS_SKILL"; then pass "init installs the same skill for claude-code and for codex + pi"; else fail "init installs the same skill for claude-code and for codex + pi"; fi
if [[ ! -e $HOME/.pi/agent/skills/qbit-vault ]]; then pass "pi gets no second copy of the skill"; else fail "pi gets no second copy of the skill"; fi
if [[ $OUT == *healthy ]]; then pass "init ends with a healthy doctor report"; else fail "init ends with a healthy doctor report" "$(snippet "$OUT")"; fi
expect_no_out "init output holds no passphrase" "$PASSPHRASE"

jqt "claude.json: our MCP entry" "$CLAUDE_JSON" '.mcpServers["qbit-vault"].args == ["mcp"] and (.mcpServers["qbit-vault"].command | startswith("/"))'
jqt "claude.json: points the MCP server at our vault home" "$CLAUDE_JSON" ".mcpServers[\"qbit-vault\"].env.QBIT_VAULT_HOME == \"$VAULT\""
jqt "claude.json: the user's other MCP server is intact" "$CLAUDE_JSON" '.mcpServers["other-mcp"] == {"command":"npx","args":["-y","other-mcp"]}'
jqt "claude.json: unrelated keys intact" "$CLAUDE_JSON" '.numStartups == 42 and .theme == "dark" and (.projects["/work/x"].allowedTools == [])'
jqt "claude.json: the user's key order is kept" "$CLAUDE_JSON" '(keys_unsorted | .[0:2]) == ["numStartups","theme"]'
jqt "settings.json: four qbit-vault hook entries" "$SETTINGS" '[.hooks[][] | .hooks[] | select(.statusMessage? // "" | startswith("qbit-vault hook "))] | length == 4'
jqt "settings.json: pre-bash is a PreToolUse hook on Bash|PowerShell" "$SETTINGS" '[.hooks.PreToolUse[] | select(.matcher == "Bash|PowerShell") | .hooks[] | select(.args == ["hook","pre-bash"])] | length == 1'
jqt "settings.json: the user's Gentle AI-looking hook is intact" "$SETTINGS" '[.hooks.PreToolUse[] | select(.matcher == "Bash") | .hooks[] | select(.command == "gentle-ai hook guard")] | length == 1'
jqt "settings.json: the user's Stop hook is intact" "$SETTINGS" '[.hooks.Stop[].hooks[] | select(.command == "notify-send done")] | length == 1'
jqt "settings.json: the user's deny and allow entries are intact" "$SETTINGS" '(.permissions.deny | index("Read(./.env)")) != null and .permissions.allow == ["Bash(git status)"] and .model == "opus"'
jqt "settings.json: deny entries for the vault home (Claude's //absolute path form)" "$SETTINGS" ".permissions.deny | index(\"Read(/$VAULT/**)\") != null and index(\"Edit(/$VAULT/**)\") != null"
has "codex config: our table" "$CODEX" '[mcp_servers.qbit-vault]'
has "codex config: our env table" "$CODEX" '[mcp_servers.qbit-vault.env]'
has "codex config: the user's comment is intact" "$CODEX" '# my codex config'
has "codex config: the user's inline comment is intact" "$CODEX" 'model = "gpt-5"   # keep me'
has "codex config: the user's [mcp_servers.x] is intact" "$CODEX" '[mcp_servers.x]'
has "codex config: the user's [profiles.fast] is intact" "$CODEX" '[profiles.fast]'
# the original bytes are an unchanged prefix of the new file, CRLF included
if [[ $(head -c "$(stat -c %s "$WORK/codex.orig" 2>/dev/null || echo 0)" "$CODEX" | sha256sum | cut -d' ' -f1) == "" ]]; then :; fi
python3 - "$CODEX" "$VAULT" <<'PY' && pass "codex config is valid TOML with the user's tables and ours" || fail "codex config is valid TOML with the user's tables and ours"
import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
s = d["mcp_servers"]
assert s["x"] == {"command": "x-server", "args": ["--flag"]}, s["x"]
q = s["qbit-vault"]
assert q["args"] == ["mcp"] and q["env"]["QBIT_VAULT_HOME"] == sys.argv[2], q
assert d["model"] == "gpt-5" and d["profiles"]["fast"]["model"] == "small"
PY
python3 - "$CODEX" <<'PY' && pass "codex config keeps the user's CRLF line endings (no bare LF in the user's part)" || fail "codex config keeps the user's CRLF line endings"
import sys
b = open(sys.argv[1], "rb").read()
head = b.split(b"[mcp_servers.qbit-vault]")[0]
assert b"\r\n" in head and head.count(b"\n") == head.count(b"\r\n"), head
PY
jqt "pi mcp.json: our MCP entry" "$PI_MCP" '.mcpServers["qbit-vault"].args == ["mcp"]'
jqt "pi mcp.json: the user's other server is intact" "$PI_MCP" '.mcpServers["pi-other"] == {"command":"pi-other","args":[]}'

qbv doctor
expect_rc "doctor exits 0 after init" 0
if [[ $OUT == *healthy ]]; then pass "doctor says healthy"; else fail "doctor says healthy" "$(snippet "$OUT")"; fi
for chk in host.claude-code.mcp host.claude-code.hooks host.claude-code.deny host.codex.mcp host.pi.mcp; do
  if grep -qE "^ok +$chk " <<<"$OUT"; then pass "doctor: $chk ok"; else fail "doctor: $chk ok" "$(snippet "$OUT")"; fi
done

# ---- step 3: idempotence ----

step "3. second init and sync change nothing"
snap() { sha256sum "$CLAUDE_JSON" "$SETTINGS" "$CODEX" "$PI_MCP" "$VAULT/state.json" | sha256sum | cut -d' ' -f1; }
BEFORE=$(snap)
BACKUPS_BEFORE=$(ls "$VAULT/backups" | wc -l)
answers
qbv init
expect_rc "second init exits 0" 0
expect_out "second init: claude-code up to date" $'host claude-code: up to date\n'
expect_out "second init: codex up to date" $'host codex: up to date\n'
expect_out "second init: pi up to date" $'host pi: up to date\n'
qbv sync
expect_rc "sync exits 0" 0
expect_out "sync: claude-code up to date" $'host claude-code: up to date'
expect_out "sync: codex up to date" $'host codex: up to date'
expect_out "sync: pi up to date" $'host pi: up to date'
expect_eq "configs and state.json byte-identical after init + sync" "$(snap)" "$BEFORE"
expect_eq "no new snapshot taken by a no-op run" "$(ls "$VAULT/backups" | wc -l)" "$BACKUPS_BEFORE"

# ---- step 4: hooks against the real binary ----

step "4. hooks with recorded events"
pre() { runin "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":$(jq -Rn --arg c "$1" '$c')}}" qbit-vault hook pre-bash; }
pre 'qbit-vault set X'
expect_rc "pre-bash on 'qbit-vault set X' exits 0" 0
expect_out "pre-bash denies 'qbit-vault set X'" '"permissionDecision":"deny"'
pre 'qbit-vault remote join'
expect_rc "pre-bash on 'qbit-vault remote join' exits 0" 0
expect_out "pre-bash denies 'qbit-vault remote join'" '"permissionDecision":"deny"'
pre 'cd /tmp && FOO=1 qbit-vault set Y'
expect_out "pre-bash denies a chained, env-prefixed 'qbit-vault set'" '"permissionDecision":"deny"'
pre 'ls'
expect_rc "pre-bash on 'ls' exits 0" 0
expect_eq "pre-bash passes 'ls' silently" "$OUT$ERR" ""
pre 'qbit-vault list'
expect_eq "pre-bash passes the read-only 'qbit-vault list'" "$OUT$ERR" ""

answers "$SECRET"
qbv set "$SECRET_NAME" --global
expect_rc "set stores a TESTSECRET_ value (scripted prompt)" 0
expect_no_out "set prints no value" "$SECRET"
qbv unlock
expect_rc "unlock (passphrase from the scripted file)" 0

EV=$(jq -cn --arg s "API_KEY=$SECRET and more" '{session_id:"s1",hook_event_name:"PostToolUse",tool_name:"Bash",tool_input:{command:"cat .env"},tool_response:{stdout:$s,stderr:"",interrupted:false,isImage:false}}')
runin "$EV" qbit-vault hook post-bash
expect_rc "post-bash exits 0" 0
expect_out "post-bash returns updatedToolOutput" '"updatedToolOutput"'
expect_no_out "post-bash output does not hold the value" "$SECRET"
jqt "post-bash: stdout rewritten, structure kept" "$WORK/o" '.hookSpecificOutput.updatedToolOutput.stdout | startswith("API_KEY=") and endswith(" and more") and (contains("TESTSECRET_") | not)'
EV=$(jq -cn --arg s "line: $SECRET" '{session_id:"s1",hook_event_name:"PostToolUse",tool_name:"Read",tool_input:{file_path:"/x/.env"},tool_response:{file:{content:$s}}}')
runin "$EV" qbit-vault hook post-read
expect_no_out "post-read output does not hold the value" "$SECRET"

runin "$(jq -cn --arg p "my key is $SECRET please use it" '{session_id:"s1",hook_event_name:"UserPromptSubmit",prompt:$p}')" qbit-vault hook user-prompt
expect_rc "user-prompt exits 0" 0
expect_out "user-prompt blocks a prompt holding a stored value" '"decision":"block"'
expect_no_out "user-prompt does not echo the value" "$SECRET"
runin '{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"refactor the parser"}' qbit-vault hook user-prompt
expect_eq "user-prompt lets an ordinary prompt through" "$OUT$ERR" ""

qbv lock
expect_rc "lock drops the unlock cache" 0
runin "$EV" qbit-vault hook post-read
expect_rc "post-read with a locked vault exits 0 (fail open)" 0
expect_out "locked vault: the agent is told the vault is locked" "vault locked"
expect_no_out "locked vault: output holds no value" "$SECRET"
answers
qbv unlock
expect_rc "unlock again" 0

# ---- step 5: drift ----

step "5. drift: our hook entry removed from settings.json"
cp "$SETTINGS" "$WORK/settings.registered"
# delete the UserPromptSubmit block as text, so the user's formatting survives
python3 - "$SETTINGS" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().split("\n")
i = next(n for n, l in enumerate(lines) if l.strip().startswith('"UserPromptSubmit"'))
j = next(n for n in range(i + 1, len(lines)) if lines[n] == "\t\t]")
del lines[i:j + 1]
lines[i - 1] = lines[i - 1].rstrip(",")
open(p, "w").write("\n".join(lines))
PY
jqt "drift set up: our user-prompt hook is gone, the others stay" "$SETTINGS" '(.hooks | has("UserPromptSubmit") | not) and ([.hooks.PreToolUse[].hooks[] | select(.statusMessage? == "qbit-vault hook pre-bash")] | length == 1)'
qbv doctor
expect_rc "doctor exits 1 on drift" 1
expect_out "doctor warns to run sync" "run 'qbit-vault sync'"
if grep -qE "^warn +host.claude-code.hooks " <<<"$OUT"; then pass "doctor: the hooks check is the warning"; else fail "doctor: the hooks check is the warning" "$(snippet "$OUT")"; fi
qbv sync
expect_rc "sync exits 0" 0
expect_out "sync repairs claude-code" $'host claude-code: repaired (hooks)'
expect_eq "sync restores settings.json byte for byte" "$(sha "$SETTINGS")" "$(sha "$WORK/settings.registered")"
qbv doctor
expect_rc "doctor exits 0 after the repair" 0
if [[ $OUT == *healthy ]]; then pass "doctor healthy again"; else fail "doctor healthy again" "$(snippet "$OUT")"; fi
jqt "settings.json: the user's hooks survived the repair" "$SETTINGS" '([.hooks.PreToolUse[].hooks[] | select(.command == "gentle-ai hook guard")] | length == 1) and ([.hooks.Stop[]] | length == 1)'

# ---- step 5b: a real agent's MCP session ----

step "5b. MCP end to end: the calls Claude Code makes, over stdio, with a scripted approval"
TOKEN_NAME=QBIT_TEST_TOKEN
TOKEN=TESTSECRET_mcp_e2e_token_7d2b9e41
MCP_SESSION=claude-code:e2e-5b-session
answers "$TOKEN"
qbv set "$TOKEN_NAME" --global
expect_rc "set stores $TOKEN_NAME (scripted prompt)" 0
answers
# the value must not stay in the answers file after the prompt read it
if grep -qF "$TOKEN" "$QBIT_VAULT_SCRIPTED_ANSWERS"; then fail "the answers file no longer holds the value"; else pass "the answers file no longer holds the value"; fi

mcp_call() { jq -cn --arg n "$1" --argjson a "$2" '{method:"tools/call",name:$n,arguments:$a}'; }
EXEC_LEN=$(jq -cn '{command:"printf %s \"${#QBIT_TEST_TOKEN}\"",secrets:[{name:"QBIT_TEST_TOKEN"}]}')
EXEC_DUMP=$(jq -cn '{command:"echo $QBIT_TEST_TOKEN",secrets:[{name:"QBIT_TEST_TOKEN"}]}')
EXEC_SH=$(jq -cn '{command:"sh -c '"'"'printf \"%s\" \"${#QBIT_TEST_TOKEN}\"'"'"'",secrets:[{name:"QBIT_TEST_TOKEN"}]}')
REQ=$(jq -cn '{name:"QBIT_TEST_TOKEN",reason:"e2e: measure the length of the test token",suggested_scope:"once"}')
{
  printf '{"method":"tools/list"}\n'
  mcp_call secret_list '{}'
  mcp_call secret_exec "$EXEC_LEN"
  mcp_call secret_request "$REQ"
  mcp_call secret_exec "$EXEC_DUMP"
  mcp_call secret_exec "$EXEC_SH"
  mcp_call secret_exec "$EXEC_LEN"
} | jq -s . >"$WORK/mcp-script.json"

# exactly one scripted answer: "1" = once. A second prompt would find the
# queue empty, wait 3s and cancel, which the transcript check below catches.
answers 1
AUDIT_BEFORE=$(wc -l <"$VAULT/audit.jsonl")
QBIT_VAULT_SESSION=$MCP_SESSION QBIT_VAULT_SCRIPTED_WAIT=3s run mcpclient -server qbit-vault "$WORK/mcp-script.json"
expect_rc "mcpclient: all seven calls were answered" 0
expect_empty_err "the MCP server wrote nothing to stderr"
expect_eq "mcpclient printed one line per call" "$(wc -l <"$WORK/o" | tr -d ' ')" 7
for n in 1 2 3 4 5 6 7; do sed -n "${n}p" "$WORK/o" >"$WORK/l$n"; done
refused() { jq -e --arg t "$1" '.result.isError == true and ((.result.content[0].text | fromjson) | .ok == false and .refusal.type == $t)' "$2" >/dev/null 2>&1 && echo true || echo false; }

# 1. tools/list
jqt "1. tools/list returns exactly the four tools (no grant tool)" "$WORK/l1" '[.result.tools[].name] | sort == ["secret_exec","secret_list","secret_manage","secret_request"]'
jqt "1. the secret_exec description tells agents to write \${#NAME}" "$WORK/l1" '.result.tools[] | select(.name == "secret_exec") | .description | contains("${#NAME}")'
# 2. secret_list
jqt "2. secret_list shows $TOKEN_NAME by name" "$WORK/l2" '.result.isError != true and ((.result.content[0].text | fromjson) | .ok == true and ([.secrets[].name] | index("QBIT_TEST_TOKEN")) != null)'
jqt "2. secret_list: $TOKEN_NAME carries no grant yet and no value field" "$WORK/l2" '(.result.content[0].text | fromjson | .secrets[] | select(.name == "QBIT_TEST_TOKEN")) | .grant == null and (keys | index("value") == null)'
# 3. exec without a grant
expect_eq "3. secret_exec without a grant is refused grant_required" "$(refused grant_required "$WORK/l3")" true
# 4. request, approved once by the scripted backend
jqt "4. secret_request is granted with scope once" "$WORK/l4" '.result.isError != true and ((.result.content[0].text | fromjson) | .ok == true and .grant.scope == "once" and .ref == "secret://QBIT_TEST_TOKEN")'
# 5. dump command, grant kept (D3)
expect_eq "5. secret_exec 'echo \$$TOKEN_NAME' is refused dump_command" "$(refused dump_command "$WORK/l5")" true
# 6. the length through sh -c (D1 quoting), same once grant
jqt "6. secret_exec sh -c 'printf ... \${#NAME}' exits 0 on the grant the refusal did not spend (D3)" "$WORK/l6" '.result.isError != true and ((.result.content[0].text | fromjson) | .ok == true and .exit_code == 0)'
expect_eq "6. its stdout is the length of the value (D1 quoting)" "$(jq -r '.result.content[0].text | fromjson | .stdout' "$WORK/l6")" "${#TOKEN}"
# 7. the once grant is spent
expect_eq "7. a further secret_exec needs a new grant (once is consumed)" "$(refused grant_required "$WORK/l7")" true

# one prompt only: the approval of step 4, nothing was asked again
expect_eq "one prompt in the whole session (the scope choice of step 4)" "$(grep -c '^ASK ' "$QBIT_VAULT_SCRIPTED_TRANSCRIPT")" 1
has "the only prompt was the scope choice for $TOKEN_NAME" "$QBIT_VAULT_SCRIPTED_TRANSCRIPT" "ASK choose q=\"Allow the agent to use $TOKEN_NAME (all projects)? Why: e2e: measure the length of the test token\""
if grep -q '^EXHAUSTED' "$QBIT_VAULT_SCRIPTED_TRANSCRIPT"; then fail "no prompt ran out of scripted answers"; else pass "no prompt ran out of scripted answers"; fi

# audit (D4): the refusals of this MCP session are recorded, names only
tail -n +$((AUDIT_BEFORE + 1)) "$VAULT/audit.jsonl" >"$WORK/audit.new"
auditq() { jq -cs "[.[] | select(.session == \"$MCP_SESSION\")] | $1" "$WORK/audit.new"; }
expect_eq "audit: two grant_required refusals for the MCP session (steps 3 and 7)" "$(auditq '[.[] | select(.event == "refusal" and .refusal == "grant_required" and .names == ["QBIT_TEST_TOKEN"])] | length')" 2
expect_eq "audit: one dump_command refusal for the MCP session (step 5)" "$(auditq '[.[] | select(.event == "refusal" and .refusal == "dump_command")] | length')" 1
expect_eq "audit: refusals are attributed to the agent" "$(auditq '[.[] | select(.event == "refusal") | .by] | unique')" '["agent"]'
expect_eq "audit: the grant and the prompt of step 4 are there" "$(auditq '[.[] | select(.event == "grant" or (.event == "prompt" and .outcome == "issued")) | .event] | sort')" '["grant","prompt"]'
run qbit-vault audit --verify
expect_rc "audit chain still verifies after the MCP session" 0

# 7. leak: nothing the agent could read, nothing on disk outside the vault's encrypted files
if grep -qF "$TOKEN" "$WORK/o" "$WORK/e"; then fail "7. no mcpclient output or server stderr holds the value"; else pass "7. no mcpclient output or server stderr holds the value"; fi
if grep -qF "$TOKEN" "$VAULT/audit.jsonl"; then fail "7. the audit log does not hold the value"; else pass "7. the audit log does not hold the value"; fi
if grep -rlF "$TOKEN" /home/qbv /dev/shm /tmp 2>/dev/null | grep .; then
  fail "7. no file outside the vault's encrypted files holds the value"
else
  pass "7. no file outside the vault's encrypted files holds the value (home, /dev/shm, /tmp)"
fi
printf 'x %s y' "$TOKEN" >"$HOME/.canary5b"
if grep -rlF "$TOKEN" /home/qbv >/dev/null 2>&1; then pass "7. scan self-check: a planted value is found"; else fail "7. scan self-check: a planted value is found"; fi
rm -f "$HOME/.canary5b"

# ---- step 6: uninstall ----

step "6. a later user edit, then uninstall (answer: yes)"
jq '. + {"addedLater": "user-edit"}' "$CLAUDE_JSON" >"$WORK/c.json"
cat "$WORK/c.json" >"$CLAUDE_JSON"
answers y
qbv uninstall
expect_rc "uninstall exits 0" 0
expect_out "uninstall reports claude-code" "host claude-code: "
expect_out "uninstall reports codex" "host codex: "
expect_out "uninstall reports pi" "host pi: "
expect_out "uninstall keeps the vault" "vault kept at $VAULT"
# settings.json was edited by the user in step 5 (drift) and repaired by sync:
# the strip route removes our entries and every empty container we created
# (odd/tasks/hosts.md L18), so the file is again the original, byte for byte.
if grep -q 'qbit-vault' "$SETTINGS"; then fail "settings.json: nothing of ours is left"; else pass "settings.json: nothing of ours is left"; fi
jqt "settings.json: every user entry is intact" "$SETTINGS" '.model == "opus" and .permissions.deny == ["Read(./.env)"] and .permissions.allow == ["Bash(git status)"] and ([.hooks.PreToolUse[].hooks[].command] == ["gentle-ai hook guard"]) and ([.hooks.Stop[].hooks[].command] == ["notify-send done"])'
expect_eq "settings.json byte-identical to the original after drift + sync + uninstall" "$(sha "$SETTINGS")" "$ORIG_SETTINGS"
SETTINGS_BASE=$(sha "$SETTINGS")
expect_eq "codex config.toml byte-identical to the original (CRLF, comments)" "$(sha "$CODEX")" "$ORIG_CODEX"
expect_eq "pi mcp.json byte-identical to the original" "$(sha "$PI_MCP")" "$ORIG_PI"
jqt "claude.json: the later user key is kept" "$CLAUDE_JSON" '.addedLater == "user-edit"'
jqt "claude.json: our entry is gone, the user's server is not" "$CLAUDE_JSON" '(.mcpServers | has("qbit-vault") | not) and .mcpServers["other-mcp"].command == "npx"'
jqt "claude.json: only our entry (plus the later key) differs from the original" "$CLAUDE_JSON" ". == ($(jq -c . "$WORK/claude.json.orig") + {addedLater: \"user-edit\"})"
if [[ ! -e $HOME/.claude/skills/qbit-vault && ! -e $HOME/.agents/skills/qbit-vault ]]; then pass "uninstall removes both skill copies"; else fail "uninstall removes both skill copies"; fi
if [[ -f $VAULT/vault.enc && -f $VAULT/state.json ]]; then pass "the vault is still there"; else fail "the vault is still there"; fi
qbv list
expect_rc "the vault still opens after uninstall" 0
expect_out "the stored secret is still listed (by name)" "$SECRET_NAME"

# ---- step 7: purge ----

step "7. uninstall --purge: wrong word changes nothing, 'purge' deletes only the vault"
answers
qbv init
expect_rc "init again registers the hosts" 0
expect_out "init again: claude-code registered" $'host claude-code: registered'
tree() { find "$HOME" -type f -exec sha256sum {} + | sort -k2 | sha256sum | cut -d' ' -f1; }
vsnap() { sha256sum "$VAULT/vault.enc" "$VAULT/key.enc" "$VAULT/state.json" | sha256sum | cut -d' ' -f1; }
HOME_BEFORE=$(tree) VAULT_BEFORE=$(vsnap)
answers nope
qbv uninstall --purge
if [[ $RC -ne 0 ]]; then pass "purge with a wrong word fails (exit $RC)"; else fail "purge with a wrong word fails" "$(snippet "$OUT$ERR")"; fi
expect_eq "wrong word: the fake HOME is unchanged" "$(tree)" "$HOME_BEFORE"
expect_eq "wrong word: the vault is unchanged" "$(vsnap)" "$VAULT_BEFORE"
answers purge
qbv uninstall --purge
expect_rc "purge with the word exits 0" 0
expect_out "purge reports the vault deleted" "vault purged: $VAULT"
if [[ ! -e $VAULT ]]; then pass "the vault home is gone"; else fail "the vault home is gone" "$(ls -A "$VAULT" | tr '\n' ' ')"; fi
for f in "$CLAUDE_JSON" "$SETTINGS" "$CODEX" "$PI_MCP"; do
  if [[ -f $f ]]; then pass "kept: ${f#$HOME/}"; else fail "kept: ${f#$HOME/}"; fi
done
expect_eq "settings.json byte-identical to its state before the second init (init -> purge round trip)" "$(sha "$SETTINGS")" "$SETTINGS_BASE"
expect_eq "codex config.toml byte-identical to the original after purge" "$(sha "$CODEX")" "$ORIG_CODEX"
expect_eq "pi mcp.json byte-identical to the original after purge" "$(sha "$PI_MCP")" "$ORIG_PI"
jqt "claude.json: the later user key is kept after purge" "$CLAUDE_JSON" '.addedLater == "user-edit" and (.mcpServers | has("qbit-vault") | not)'
if [[ -d $HOME/.claude && -d $HOME/.codex && -d $HOME/.pi/agent ]]; then pass "the host directories are intact"; else fail "the host directories are intact"; fi

# ---- step 8: leak scan ----

step "8. leak scan: stdout/stderr and the fake HOME"
if grep -qF -e "$SECRET" -e "$PASSPHRASE" -e "$TOKEN" "$LOG"; then
  fail "no captured stdout/stderr holds the value or the passphrase"
else
  pass "no captured stdout/stderr holds the value or the passphrase ($(wc -l <"$LOG" | tr -d ' ') lines)"
fi
if grep -rlF -e "$SECRET" -e "$PASSPHRASE" -e "$TOKEN" "$HOME" "$QBIT_VAULT_SCRIPTED_TRANSCRIPT" 2>/dev/null | grep .; then
  fail "no file under the fake HOME or the transcript holds the value or the passphrase"
else
  pass "no file under the fake HOME or the transcript holds the value or the passphrase ($(find "$HOME" -type f | wc -l | tr -d ' ') files)"
fi
# self-check: the scan must be able to see a planted value
printf 'x %s y' "$SECRET" >"$HOME/.canary"
if grep -rlF "$SECRET" "$HOME" >/dev/null 2>&1; then pass "scan self-check: a planted value is found"; else fail "scan self-check: a planted value is found"; fi
rm -f "$HOME/.canary"

rm -rf "$WORK"
printf '\n%d passed, %d failed\n' "$PASSES" "$FAILS"
[[ $FAILS -eq 0 ]]
