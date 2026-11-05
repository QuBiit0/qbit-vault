#!/usr/bin/env bash
# Runs INSIDE the install container (e2e/install/Dockerfile), driven by
# e2e/install-test.sh. A fresh non-root user, an empty HOME, the source tree in
# ~/src and no qbit-vault binary yet. Prints PASS or FAIL per check and
# "N passed, M failed"; exits non-zero on any failure.
#
# Two builds are used on purpose:
#   1. plain `go install ./cmd/qbit-vault`: what a user gets. Checks that need
#      no prompt (version, help, tui without a TTY, doctor before init) run on it.
#   2. `go install -tags e2eprompt ./cmd/qbit-vault`: the same code plus the
#      scripted prompt backend, because `set`, `init --passphrase` unlock, the
#      uninstall confirmation and the grant prompt are out-of-band user actions
#      (a real dialog or tty) that the container cannot give. It replaces the
#      plain binary in GOPATH/bin for the rest of the flow. A plain build
#      refuses QBIT_VAULT_PROMPT=scripted, which check 2.4 proves.
set -euo pipefail

VAULT=$QBIT_VAULT_HOME
SRC=/home/qbv/src
PASSPHRASE=TESTSECRET_passphrase_install_5c1d7a
SECRET_NAME=INSTALL_API_KEY
SECRET=TESTSECRET_value_install_9f8e7d6c5b4a3210
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
  "$@" >"$WORK/o" 2>"$WORK/e" </dev/null || RC=$?
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
expect_err() { if grep -qF -- "$2" <<<"$ERR"; then pass "$1"; else fail "$1" "stderr lacks [$2]: $(snippet "$ERR")"; fi; }
expect_no_out() { if grep -qF -- "$2" <<<"$OUT$ERR"; then fail "$1" "output holds [$2]: $(snippet "$OUT$ERR")"; else pass "$1"; fi; }
expect_empty_err() { if [[ -z $ERR ]]; then pass "$1"; else fail "$1" "stderr: $(snippet "$ERR")"; fi; }
expect_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "got [$2], want [$3]"; fi; }
jqt() { if [[ $(jq -r "$3" "$2" 2>&1) == true ]]; then pass "$1"; else fail "$1" "jq $3 on $2 => $(jq -c "$3" "$2" 2>&1 | head -c 300)"; fi; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

CLAUDE_JSON=$HOME/.claude.json
SETTINGS=$HOME/.claude/settings.json
CODEX=$HOME/.codex/config.toml
PI_MCP=$HOME/.pi/agent/mcp.json

# ---- step 1: a clean machine ----

step "1. a clean machine: fresh non-root user, empty HOME, source copied in, no qbit-vault"
if [[ $(id -u) -ne 0 && $(id -un) == qbv ]]; then pass "running as the non-root user qbv (uid $(id -u))"; else fail "running as the non-root user qbv" "$(id)"; fi
if [[ -z $(ls -A "$HOME") ]]; then pass "HOME ($HOME) is empty"; else fail "HOME is empty" "$(ls -A "$HOME" | tr '\n' ' ')"; fi
if [[ ! -e $VAULT ]]; then pass "no vault exists yet"; else fail "no vault exists yet"; fi
if ! command -v qbit-vault >/dev/null; then pass "qbit-vault is not installed yet"; else fail "qbit-vault is not installed yet" "$(command -v qbit-vault)"; fi
if ! command -v claude >/dev/null && ! command -v codex >/dev/null && ! command -v pi >/dev/null; then
  pass "no claude, codex or pi binary (hosts are detected by directory)"
else
  fail "no claude, codex or pi binary"
fi
if [[ -f $SRC/go.mod && -f $SRC/cmd/qbit-vault/main.go ]] && head -n1 "$SRC/go.mod" | grep -qF 'github.com/QuBiit0/qbit-vault'; then
  pass "the source tree is in $SRC (module github.com/QuBiit0/qbit-vault)"
else
  fail "the source tree is in $SRC"
fi
mkdir -p -m 700 "$XDG_RUNTIME_DIR"

# ---- step 2: go install (what a user gets) ----

step "2. go install ./cmd/qbit-vault (plain build) and the checks that need no prompt"
cd "$SRC"
RC=0
go install ./cmd/qbit-vault >"$WORK/gi.out" 2>&1 || RC=$?
cat "$WORK/gi.out" >>"$LOG"
if [[ $RC -eq 0 ]]; then pass "go install ./cmd/qbit-vault exits 0"; else fail "go install ./cmd/qbit-vault exits 0" "$(snippet "$(cat "$WORK/gi.out")")"; fi
if [[ -x $GOPATH/bin/qbit-vault ]]; then pass "the binary is in \$GOPATH/bin"; else fail "the binary is in \$GOPATH/bin"; fi
if [[ $(command -v qbit-vault) == "$GOPATH/bin/qbit-vault" ]]; then pass "\$GOPATH/bin is on PATH and resolves qbit-vault"; else fail "qbit-vault resolves from \$GOPATH/bin" "$(command -v qbit-vault || true)"; fi
PLAIN_SHA=$(sha "$GOPATH/bin/qbit-vault")
cd "$HOME"

qbv version
expect_rc "2.1 version exits 0" 0
if grep -qE '^qbit-vault [^ ]+ \([^)]*, linux/(amd64|arm64)\)$' <<<"$OUT"; then pass "2.1 version prints 'qbit-vault <version> (<commit>, linux/<arch>)'"; else fail "2.1 version prints its line" "$(snippet "$OUT")"; fi
expect_empty_err "2.1 version writes nothing to stderr"

# no arguments and no TTY: the help, never a TUI (stdin is /dev/null, stdout a file)
qbv
expect_rc "2.2 no arguments without a TTY exits 0" 0
expect_out "2.2 no arguments prints the usage" "Usage:"
expect_out "2.2 the help lists the tui command" "tui"
expect_out "2.2 the help lists init" "init"
expect_out "2.2 the help lists uninstall" "uninstall"

qbv tui
expect_rc "2.3 tui without a TTY exits 2 (usage)" 2
expect_err "2.3 tui explains that it needs a terminal" "interactive terminal"
expect_eq "2.3 tui printed nothing on stdout" "$OUT" ""

# the plain build must not honour the test prompt: scripted input in a release
# binary would be a way around invariant 6
printf '%s\n' "$PASSPHRASE" >"$QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE"
answers
qbv init --passphrase
if [[ $RC -ne 0 ]]; then pass "2.4 the plain build ignores the scripted prompt: init --passphrase fails (exit $RC)"; else fail "2.4 the plain build refuses the scripted prompt" "$(snippet "$OUT")"; fi
if [[ ! -e $VAULT/vault.enc ]]; then pass "2.4 ...and created no vault"; else fail "2.4 the failed init created no vault"; fi
expect_no_out "2.4 the failed init printed no passphrase" "$PASSPHRASE"
rm -rf "$VAULT" 2>/dev/null || true

qbv doctor
expect_rc "2.5 doctor before init exits 1 (a problem, not a crash)" 1
expect_out "2.5 doctor names the missing vault and the fix" "no vault here; run 'qbit-vault init'"
if [[ ! -e $VAULT ]]; then pass "2.5 doctor created nothing (read-only)"; else fail "2.5 doctor created nothing" "$(ls -A "$VAULT" | tr '\n' ' ')"; fi

# ---- step 3: the test build ----

step "3. go install -tags e2eprompt (same code plus the scripted prompt) and the tools"
cd "$SRC"
RC=0
go install -tags e2eprompt ./cmd/qbit-vault ./e2e/mcpclient ./e2e/leakscan >"$WORK/gi2.out" 2>&1 || RC=$?
cat "$WORK/gi2.out" >>"$LOG"
if [[ $RC -eq 0 ]]; then pass "3.1 go install -tags e2eprompt ./cmd/qbit-vault ./e2e/mcpclient ./e2e/leakscan exits 0"; else fail "3.1 go install with -tags e2eprompt" "$(snippet "$(cat "$WORK/gi2.out")")"; fi
cd "$HOME"
if [[ $(sha "$GOPATH/bin/qbit-vault") != "$PLAIN_SHA" ]]; then pass "3.2 the tagged binary replaced the plain one (different build)"; else fail "3.2 the tagged binary differs from the plain build"; fi

# ---- step 4: fake hosts, init ----

step "4. the user's own host configs (directories only, no host binary), then init --passphrase"
mkdir -p "$HOME/.claude" "$HOME/.codex" "$HOME/.pi/agent"
printf '{\n\t"numStartups": 42,\n\t"theme": "dark",\n\t"mcpServers": {\n\t\t"other-mcp": { "command": "npx", "args": ["-y", "other-mcp"] }\n\t}\n}\n' >"$CLAUDE_JSON"
printf '{\n\t"model": "opus",\n\t"permissions": { "deny": ["Read(./.env)"], "allow": ["Bash(git status)"] },\n\t"hooks": {\n\t\t"Stop": [ { "hooks": [{ "type": "command", "command": "notify-send done" }] } ]\n\t}\n}\n' >"$SETTINGS"
printf '# my codex config\r\nmodel = "gpt-5"   # keep me\r\n\r\n[mcp_servers.x]\r\ncommand = "x-server"\r\n' >"$CODEX"
printf '{\n  "mcpServers": {\n    "pi-other": { "command": "pi-other", "args": [] }\n  }\n}\n' >"$PI_MCP"
ORIG_CLAUDE=$(sha "$CLAUDE_JSON") ORIG_SETTINGS=$(sha "$SETTINGS") ORIG_CODEX=$(sha "$CODEX") ORIG_PI=$(sha "$PI_MCP")
mkdir -p "$WORK/orig"
cp "$CLAUDE_JSON" "$WORK/orig/claude.json"
cp "$SETTINGS" "$WORK/orig/settings.json"
cp "$CODEX" "$WORK/orig/config.toml"
cp "$PI_MCP" "$WORK/orig/mcp.json"

printf '%s\n' "$PASSPHRASE" >"$QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE"
answers
qbv init --passphrase
expect_rc "4.1 init --passphrase exits 0" 0
expect_empty_err "4.1 init writes nothing to stderr"
expect_out "4.1 init: claude-code registered" $'host claude-code: registered (mcp, hooks, deny)\n'
expect_out "4.1 init: codex registered" $'host codex: registered (mcp)\n'
expect_out "4.1 init: pi registered" $'host pi: registered (mcp)\n'
if [[ $OUT == *healthy ]]; then pass "4.1 init ends with a healthy doctor report"; else fail "4.1 init ends with a healthy doctor report" "$(snippet "$OUT")"; fi
expect_no_out "4.1 init output holds no passphrase" "$PASSPHRASE"
if [[ -f $VAULT/vault.enc && -f $VAULT/key.enc ]]; then pass "4.2 the vault exists (vault.enc, key.enc) with no OS keychain"; else fail "4.2 the vault exists" "$(ls -A "$VAULT" 2>&1 | tr '\n' ' ')"; fi
qbv list
expect_rc "4.3 list on the fresh vault exits 0" 0
jqt "4.4 claude.json: our MCP entry, the user's server intact" "$CLAUDE_JSON" '.mcpServers["qbit-vault"].args == ["mcp"] and .mcpServers["other-mcp"].command == "npx" and .numStartups == 42'
jqt "4.4 settings.json: our hooks, the user's Stop hook and lists intact" "$SETTINGS" '([.hooks[][] | .hooks[] | select(.statusMessage? // "" | startswith("qbit-vault hook "))] | length == 4) and ([.hooks.Stop[].hooks[].command] == ["notify-send done"]) and .permissions.allow == ["Bash(git status)"] and .model == "opus"'
if grep -qF '[mcp_servers.qbit-vault]' "$CODEX" && grep -qF '[mcp_servers.x]' "$CODEX"; then pass "4.4 codex config: our table, the user's [mcp_servers.x] intact"; else fail "4.4 codex config tables"; fi
jqt "4.4 pi mcp.json: our MCP entry, the user's server intact" "$PI_MCP" '.mcpServers["qbit-vault"].args == ["mcp"] and .mcpServers["pi-other"].command == "pi-other"'
jqt "4.4 the MCP entry runs the installed binary from GOPATH/bin" "$CLAUDE_JSON" ".mcpServers[\"qbit-vault\"].command == \"$GOPATH/bin/qbit-vault\""

# ---- step 5: set, list ----

step "5. set a TESTSECRET_ value through the scripted prompt, list it"
answers "$SECRET"
qbv set "$SECRET_NAME" --global
expect_rc "5.1 set exits 0" 0
expect_no_out "5.1 set prints no value" "$SECRET"
expect_eq "5.1 the scripted prompt asked once" "$(grep -c '^ASK ' "$QBIT_VAULT_SCRIPTED_TRANSCRIPT")" 1
qbv list
expect_rc "5.2 list exits 0" 0
expect_out "5.2 list shows the name" "$SECRET_NAME"
expect_no_out "5.2 list shows no value" "$SECRET"
qbv --json list
expect_rc "5.3 list --json exits 0" 0
expect_no_out "5.3 list --json shows no value" "$SECRET"

# ---- step 6: the agent over MCP ----

step "6. MCP session as an agent runs it: list, request (approved), exec with redacted output"
mcp_call() { jq -cn --arg n "$1" --argjson a "$2" '{method:"tools/call",name:$n,arguments:$a}'; }
# The dump guard refuses every inline way of printing a variable (call 5 below
# proves it), so the exec that must come back redacted runs a script of the
# user's, a tool that logs its own credential: the command text holds no
# variable name, the script prints the value raw and base64-encoded, and the
# redactor is the only thing between the value and the agent.
cat >"$WORK/tool.sh" <<'TOOL'
#!/bin/sh
printf 'token=%s
' "$INSTALL_API_KEY"
printf 'b64=%s
' "$(printf '%s' "$INSTALL_API_KEY" | base64 | tr -d '
')"
printf 'len=%s
' "${#INSTALL_API_KEY}"
TOOL
CMD="sh $WORK/tool.sh"
EXEC_USE=$(jq -cn --arg c "$CMD" --arg n "$SECRET_NAME" '{command:$c,secrets:[{name:$n}]}')
EXEC_DUMP=$(jq -cn --arg n "$SECRET_NAME" '{command:("echo $" + $n),secrets:[{name:$n}]}')
REQ=$(jq -cn --arg n "$SECRET_NAME" '{name:$n,reason:"e2e install: use the installed key",suggested_scope:"once"}')
{
  printf '{"method":"tools/list"}\n'
  mcp_call secret_list '{}'
  mcp_call secret_exec "$EXEC_USE"
  mcp_call secret_request "$REQ"
  mcp_call secret_exec "$EXEC_DUMP"
  mcp_call secret_exec "$EXEC_USE"
  mcp_call secret_exec "$EXEC_USE"
} | jq -s . >"$WORK/mcp-script.json"
answers 1
AUDIT_BEFORE=$(wc -l <"$VAULT/audit.jsonl")
QBIT_VAULT_SESSION=claude-code:e2e-install-session QBIT_VAULT_SCRIPTED_WAIT=3s run mcpclient -server qbit-vault "$WORK/mcp-script.json"
expect_rc "6.0 mcpclient: all seven calls were answered" 0
expect_empty_err "6.0 the MCP server wrote nothing to stderr"
expect_eq "6.0 mcpclient printed one line per call" "$(wc -l <"$WORK/o" | tr -d ' ')" 7
cp "$WORK/o" "$WORK/mcp.out"
for n in 1 2 3 4 5 6 7; do sed -n "${n}p" "$WORK/mcp.out" >"$WORK/l$n"; done
refused() { jq -e --arg t "$1" '.result.isError == true and ((.result.content[0].text | fromjson) | .ok == false and .refusal.type == $t)' "$2" >/dev/null 2>&1 && echo true || echo false; }

jqt "6.1 tools/list returns exactly the four tools" "$WORK/l1" '[.result.tools[].name] | sort == ["secret_exec","secret_list","secret_manage","secret_request"]'
jqt "6.2 secret_list shows $SECRET_NAME by name, no value field" "$WORK/l2" ".result.isError != true and ((.result.content[0].text | fromjson) | .ok == true and ([.secrets[].name] | index(\"$SECRET_NAME\")) != null and ([.secrets[] | keys | index(\"value\")] | all(. == null)))"
expect_eq "6.3 secret_exec without a grant is refused grant_required" "$(refused grant_required "$WORK/l3")" true
jqt "6.4 secret_request is approved by the scripted prompt (scope once)" "$WORK/l4" ".result.isError != true and ((.result.content[0].text | fromjson) | .ok == true and .grant.scope == \"once\" and .ref == \"secret://$SECRET_NAME\")"
expect_eq "6.5 secret_exec 'echo \$$SECRET_NAME' is refused dump_command (the grant is kept)" "$(refused dump_command "$WORK/l5")" true
jqt "6.6 secret_exec of the tool script with the grant exits 0" "$WORK/l6" '.result.isError != true and ((.result.content[0].text | fromjson) | .ok == true and .exit_code == 0)'
jqt "6.6 the command used the value: its length came back (${#SECRET})" "$WORK/l6" "(.result.content[0].text | fromjson | .stdout) | contains(\"len=${#SECRET}\")"
jqt "6.6 the raw value in the output came back redacted" "$WORK/l6" '(.result.content[0].text | fromjson | .stdout) | contains("token=") and (contains("TESTSECRET_") | not)'
jqt "6.6 both occurrences carry the [REDACTED:NAME] marker (redactions == 2, name only)" "$WORK/l6" '(.result.content[0].text | fromjson) | (.stdout | contains("token=[REDACTED:INSTALL_API_KEY]") and contains("b64=[REDACTED:INSTALL_API_KEY]")) and .redactions == 2'
jqt "6.6 the base64 form of the value came back redacted too" "$WORK/l6" '(.result.content[0].text | fromjson | .stdout) | contains("b64=") and (contains("VEVTVFNFQ1JFVF9") | not)'
expect_eq "6.7 the once grant is spent: the next secret_exec is refused grant_required" "$(refused grant_required "$WORK/l7")" true
expect_eq "6.8 one prompt in the whole session (the scope choice)" "$(grep -c '^ASK ' "$QBIT_VAULT_SCRIPTED_TRANSCRIPT")" 1
if grep -q '^EXHAUSTED' "$QBIT_VAULT_SCRIPTED_TRANSCRIPT"; then fail "6.8 no prompt ran out of scripted answers"; else pass "6.8 no prompt ran out of scripted answers"; fi
if grep -qF "$SECRET" "$WORK/mcp.out"; then fail "6.9 no MCP answer holds the value"; else pass "6.9 no MCP answer holds the value"; fi
cat "$WORK/mcp.out" >>"$LOG"

# ---- step 7: audit, doctor ----

step "7. audit --verify and doctor"
tail -n +$((AUDIT_BEFORE + 1)) "$VAULT/audit.jsonl" >"$WORK/audit.new"
expect_eq "7.1 the audit log recorded the session's grant" "$(jq -cs '[.[] | select(.event == "grant")] | length' "$WORK/audit.new")" 1
qbv audit --verify
expect_rc "7.2 audit --verify exits 0" 0
qbv doctor
expect_rc "7.3 doctor exits 0" 0
if [[ $OUT == *healthy ]]; then pass "7.3 doctor says healthy"; else fail "7.3 doctor says healthy" "$(snippet "$OUT")"; fi
for chk in host.claude-code.mcp host.claude-code.hooks host.claude-code.deny host.codex.mcp host.pi.mcp; do
  if grep -qE "^ok +$chk " <<<"$OUT"; then pass "7.3 doctor: $chk ok"; else fail "7.3 doctor: $chk ok" "$(snippet "$OUT")"; fi
done

# ---- step 8: uninstall, purge ----

step "8. uninstall restores the configs byte for byte; uninstall --purge deletes the vault"
answers y
qbv uninstall
expect_rc "8.1 uninstall exits 0" 0
expect_out "8.1 uninstall keeps the vault" "vault kept at $VAULT"
expect_eq "8.2 claude.json byte-identical to the pre-install file" "$(sha "$CLAUDE_JSON")" "$ORIG_CLAUDE"
expect_eq "8.2 settings.json byte-identical to the pre-install file" "$(sha "$SETTINGS")" "$ORIG_SETTINGS"
expect_eq "8.2 codex config.toml byte-identical (CRLF, comments)" "$(sha "$CODEX")" "$ORIG_CODEX"
expect_eq "8.2 pi mcp.json byte-identical to the pre-install file" "$(sha "$PI_MCP")" "$ORIG_PI"
if cmp -s "$CLAUDE_JSON" "$WORK/orig/claude.json" && cmp -s "$SETTINGS" "$WORK/orig/settings.json" && cmp -s "$CODEX" "$WORK/orig/config.toml" && cmp -s "$PI_MCP" "$WORK/orig/mcp.json"; then pass "8.2 cmp: all four files equal their saved copies"; else fail "8.2 cmp: all four files equal their saved copies"; fi
if [[ -d $HOME/.claude && -d $HOME/.codex && -d $HOME/.pi/agent ]]; then pass "8.3 the host directories are intact"; else fail "8.3 the host directories are intact"; fi
if [[ -f $VAULT/vault.enc ]]; then pass "8.4 the vault is still there"; else fail "8.4 the vault is still there"; fi
qbv list
expect_rc "8.4 the vault still opens after uninstall" 0
expect_out "8.4 the secret is still listed (by name)" "$SECRET_NAME"

answers purge
qbv uninstall --purge
expect_rc "8.5 uninstall --purge exits 0" 0
expect_out "8.5 purge reports the vault deleted" "vault purged: $VAULT"
if [[ ! -e $VAULT ]]; then pass "8.5 the vault home is gone"; else fail "8.5 the vault home is gone" "$(ls -A "$VAULT" | tr '\n' ' ')"; fi
expect_eq "8.6 claude.json still equals the pre-install file after purge" "$(sha "$CLAUDE_JSON")" "$ORIG_CLAUDE"
expect_eq "8.6 settings.json still equals the pre-install file after purge" "$(sha "$SETTINGS")" "$ORIG_SETTINGS"
expect_eq "8.6 codex config.toml still equals the pre-install file after purge" "$(sha "$CODEX")" "$ORIG_CODEX"
expect_eq "8.6 pi mcp.json still equals the pre-install file after purge" "$(sha "$PI_MCP")" "$ORIG_PI"

# ---- step 9: leak scan ----

step "9. leak scan: every captured stdout, stderr and MCP byte, the transcript and every file under HOME"
printf 'value\t%s\npassphrase\t%s\n' "$SECRET" "$PASSPHRASE" >"$WORK/needles"
if grep -qF -e "$SECRET" -e "$PASSPHRASE" "$LOG"; then
  fail "9.1 no captured stdout/stderr/MCP byte holds the value or the passphrase"
else
  pass "9.1 no captured stdout/stderr/MCP byte holds the value or the passphrase ($(wc -c <"$LOG" | tr -d ' ') bytes)"
fi
RC=0
leakscan -needles "$WORK/needles" "$LOG" "$QBIT_VAULT_SCRIPTED_TRANSCRIPT" "$HOME" >"$WORK/leak.out" 2>&1 || RC=$?
if [[ $RC -eq 0 ]]; then pass "9.2 leakscan (raw, base64, base64url, percent, JSON forms): clean ($(find "$HOME" -type f | wc -l | tr -d ' ') files under HOME)"; else fail "9.2 leakscan: clean" "exit $RC: $(snippet "$(cat "$WORK/leak.out")")"; fi
# self-check: the scan must be able to see a planted value, in a file and in the log
printf 'x %s y' "$SECRET" >"$HOME/.canary"
RC=0
leakscan -needles "$WORK/needles" "$HOME" >/dev/null 2>&1 || RC=$?
if [[ $RC -eq 1 ]]; then pass "9.3 scan self-check: a planted value under HOME is found"; else fail "9.3 scan self-check: a planted value under HOME is found" "exit $RC"; fi
rm -f "$HOME/.canary"
printf 'x %s y' "$(printf '%s' "$SECRET" | base64 -w0)" >"$WORK/canary.b64"
RC=0
leakscan -needles "$WORK/needles" "$WORK/canary.b64" >/dev/null 2>&1 || RC=$?
if [[ $RC -eq 1 ]]; then pass "9.3 scan self-check: a base64-encoded value is found"; else fail "9.3 scan self-check: a base64-encoded value is found" "exit $RC"; fi

rm -rf "$WORK"
printf '\n%d passed, %d failed\n' "$PASSES" "$FAILS"
[[ $FAILS -eq 0 ]]
