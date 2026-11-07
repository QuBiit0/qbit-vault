package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bashEvent renders the recorded Bash event with another command.
func bashEvent(t testing.TB, command string) []byte {
	t.Helper()
	old := `"command": "npm test"`
	raw := string(fixture(t, "pretooluse_bash.json"))
	if !strings.Contains(raw, old) {
		t.Fatal("fixture changed")
	}
	return []byte(strings.Replace(raw, old, `"command": `+jsonString(command), 1))
}

func run(t testing.TB, in []byte) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := RunPreBash(bytes.NewReader(in), &out, &errb)
	return out.String(), errb.String(), code
}

const wantDeny = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"This qbit-vault command is user-only: ask the user to run it in their own terminal. The agent's shell cannot run it."}}` + "\n"

const wantWarn = `{"systemMessage":"qbit-vault hook failed; the command ran without its checks; run 'qbit-vault doctor'","hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"qbit-vault hook failed; the command ran without its checks; run 'qbit-vault doctor'"}}` + "\n"

var passCommands = []string{
	"npm test",
	"",
	"qbit-vault list",
	"qbit-vault list --layer all --json",
	"qbit-vault --json list",
	"qbit-vault --home /tmp/v describe A_KEY",
	"qbit-vault --home=/tmp/v --session claude:abcd1234 grants",
	"qbit-vault audit --verify",
	"qbit-vault doctor --json",
	"qbit-vault version",
	"qbit-vault --version",
	"qbit-vault --help",
	"qbit-vault",
	"qbit-vault.exe list",
	"/usr/local/bin/qbit-vault list",
	"qbit-vault exec --secret A_KEY -- curl https://example.com",
	"echo hi | qbit-vault list",
	"npx qbit-vault list",
	"grep qbit-vault README.md",
	"cat docs/qbit-vault.md",
	"ls ~/.qbit-vault",
	`git commit -m "document qbit-vault set"`,
	`echo "run qbit-vault set later"`,
	"qbit-vault-server --help",
	"echo 'oops",
	"pwsh -NoProfile -Command Get-Date",
	"pwsh -File build.ps1",
	"echo -e hi",
}

var denyCommands = []string{
	"qbit-vault set A_KEY",
	"qbit-vault rm A_KEY",
	"qbit-vault mv A_KEY --to global",
	"qbit-vault edit A_KEY --description x",
	"qbit-vault relink /a /b",
	"qbit-vault link label",
	"qbit-vault import --from-env A_KEY",
	"qbit-vault restore --from ID",
	"qbit-vault rekey",
	"qbit-vault lock",
	"qbit-vault unlock",
	"qbit-vault grant A_KEY --scope once",
	"qbit-vault revoke --all",
	"qbit-vault init",
	"qbit-vault uninstall --purge",
	"qbit-vault sync",
	"qbit-vault update",
	"qbit-vault prompt --name A_KEY --reason r",
	"qbit-vault mcp",
	"qbit-vault broker --op grant",
	"qbit-vault hook pre-bash",
	"qbit-vault remote status",
	"qbit-vault remote sync",
	"qbit-vault remote",
	"qbit-vault frobnicate",
	"qbit-vault --home /x set A_KEY",
	"qbit-vault --home=/x set A_KEY",
	"qbit-vault --json set A_KEY",
	"'qbit-vault' set A_KEY",
	`"qbit-vault" "set" A_KEY`,
	`qbit-vault 's'et A_KEY`,
	`qbit-vault \set A_KEY`,
	"ls && qbit-vault set A_KEY",
	"ls || qbit-vault set A_KEY",
	"ls; qbit-vault rm A_KEY",
	"ls | qbit-vault import",
	"ls\nqbit-vault set A_KEY",
	"ls &\nqbit-vault set A_KEY",
	"(qbit-vault set A_KEY)",
	"echo $(qbit-vault set A_KEY)",
	"echo `qbit-vault set A_KEY`",
	`echo "$(qbit-vault set A_KEY)"`,
	`echo "a ` + "`qbit-vault set A_KEY`" + ` b"`,
	"{ qbit-vault set A_KEY; }",
	"if true; then qbit-vault set A_KEY; fi",
	"> /dev/null qbit-vault set A_KEY",
	"qbit-vault set A_KEY > /dev/null",
	"FOO=1 qbit-vault set A_KEY",
	`FOO="a b" BAR=2 qbit-vault set A_KEY`,
	"sudo qbit-vault set A_KEY",
	"sudo -u root qbit-vault set A_KEY",
	"env FOO=1 qbit-vault set A_KEY",
	"env -u X qbit-vault grant A_KEY",
	"exec qbit-vault lock",
	"command qbit-vault unlock",
	"nohup qbit-vault set A_KEY &",
	"time qbit-vault set A_KEY",
	"xargs qbit-vault set",
	"/usr/local/bin/qbit-vault set A_KEY",
	"$HOME/bin/qbit-vault set A_KEY",
	"./qbit-vault.exe remote sync",
	`C:\bin\qbit-vault.exe set A_KEY`,
	`.\qbit-vault.exe set A_KEY`,
	"Qbit-Vault.EXE set A_KEY",
	"& 'qbit-vault.exe' set A_KEY",
	"npx qbit-vault set A_KEY",
	"npx -y qbit-vault@1.2.3 rekey",
	"npx --yes qbit-vault@latest remote sync",
	"npm exec qbit-vault set A_KEY",
	"pnpm dlx qbit-vault@1 set A_KEY",
	`bash -c "qbit-vault set A_KEY"`,
	`sh -c 'ls; qbit-vault rm A_KEY'`,
	`pwsh -Command "qbit-vault set A_KEY"`,
	`cmd /c qbit-vault set A_KEY`,
	`eval "qbit-vault set A_KEY"`,
	`bash -o pipefail -c "qbit-vault set A_KEY"`,
	// An encoded PowerShell command hides what it runs: denied (A-F2).
	"pwsh -e cQBiAGkAdAA=",
	"pwsh -ec cQBiAGkAdAA=",
	"pwsh -NoProfile -EncodedCommand cQBiAGkAdAA=",
	"pwsh -ExecutionPolicy Bypass -EncodedCommand cQBiAGkAdAA=",
	"powershell -NoProfile -ExecutionPolicy Bypass -enc cQBiAGkAdAA=",
	"powershell -WindowStyle Hidden -e cQBiAGkAdAA=",
	"powershell.exe -ENC cQBiAGkAdAA=",
	"POWERSHELL /enc cQBiAGkAdAA=",
	"sudo pwsh -en cQBiAGkAdAA=",
	"ls; pwsh -encodedcommand cQBiAGkAdAA=",
	`iex 'qbit-vault set A_KEY'`,
	"qbit-vault exec -- qbit-vault set A_KEY",
	`qbit-vault exec --secret A_KEY -- sh -c "qbit-vault rm A_KEY"`,
	// Unparseable and mentioning qbit-vault: denied.
	"echo 'unbalanced; qbit-vault list",
	`echo "unbalanced $(qbit-vault list`,
	"cat <<MARK\nqbit-vault list\nMARK",
	"echo `qbit-vault list",
	"qbit-vault list )",
}

func TestPreBashPassesWithEmptyStdout(t *testing.T) {
	for _, c := range passCommands {
		out, errb, code := run(t, bashEvent(t, c))
		if out != "" || errb != "" || code != 0 {
			t.Errorf("%q: out=%q err=%q code=%d", c, out, errb, code)
		}
	}
}

func TestPreBashDenies(t *testing.T) {
	for _, c := range denyCommands {
		out, errb, code := run(t, bashEvent(t, c))
		if out != wantDeny || errb != "" || code != 0 {
			t.Errorf("%q: out=%q err=%q code=%d", c, out, errb, code)
		}
	}
}

func TestPreBashPowerShellToolIsChecked(t *testing.T) {
	out, _, code := run(t, fixture(t, "pretooluse_powershell.json"))
	if out != wantDeny || code != 0 {
		t.Fatalf("out=%q code=%d", out, code)
	}
}

func TestPreBashOtherToolsPass(t *testing.T) {
	out, errb, code := run(t, fixture(t, "pretooluse_read.json"))
	if out != "" || errb != "" || code != 0 {
		t.Fatalf("out=%q err=%q code=%d", out, errb, code)
	}
}

func TestPreBashFailsOpen(t *testing.T) {
	cases := map[string][]byte{
		"malformed json":     fixture(t, "malformed.json"),
		"empty stdin":        nil,
		"not an object":      []byte(`["qbit-vault set A"]`),
		"wrong command type": fixture(t, "wrongtype.json"),
		"oversized":          append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), maxEvent+1)...),
	}
	for name, in := range cases {
		out, errb, code := run(t, in)
		if out != wantWarn || errb != "" || code != 0 {
			t.Errorf("%s: out=%q err=%q code=%d", name, out, errb, code)
		}
	}
}

func TestRunRecoversPanicAndFailsOpen(t *testing.T) {
	var out, errb bytes.Buffer
	boom := func(Event) (*Output, error) { panic("TESTSECRET_PANIC_VALUE") }
	code := Run(bytes.NewReader(fixture(t, "pretooluse_bash.json")), &out, &errb, "PreToolUse", boom)
	if out.String() != wantWarn || code != 0 || errb.Len() != 0 {
		t.Fatalf("out=%q err=%q code=%d", out.String(), errb.String(), code)
	}
}

func TestRunHandlerErrorFailsOpen(t *testing.T) {
	var out, errb bytes.Buffer
	bad := func(Event) (*Output, error) { return nil, os.ErrInvalid }
	code := Run(bytes.NewReader(fixture(t, "pretooluse_bash.json")), &out, &errb, "PreToolUse", bad)
	if out.String() != wantWarn || code != 0 || errb.Len() != 0 {
		t.Fatalf("out=%q err=%q code=%d", out.String(), errb.String(), code)
	}
}

func TestNoCommandTextEverReachesOutput(t *testing.T) {
	cmds := []string{
		"qbit-vault set TESTSECRET_NAME",
		"echo TESTSECRET_VALUE && qbit-vault rm TESTSECRET_NAME",
		"echo 'TESTSECRET_UNBALANCED; qbit-vault list",
		"echo TESTSECRET_VALUE",
	}
	inputs := [][]byte{fixture(t, "malformed.json"), fixture(t, "wrongtype.json")}
	for _, c := range cmds {
		inputs = append(inputs, bashEvent(t, c))
	}
	for _, in := range inputs {
		out, errb, _ := run(t, in)
		if strings.Contains(out+errb, "TESTSECRET_") {
			t.Errorf("leaked: out=%q err=%q", out, errb)
		}
	}
}

func TestPreBashLatency(t *testing.T) {
	in := bashEvent(t, "cd /repo && FOO=1 sudo qbit-vault list --json | jq .secrets && go test ./...")
	const n = 200
	start := time.Now()
	for i := 0; i < n; i++ {
		run(t, in)
	}
	per := time.Since(start) / n
	t.Logf("pre-bash in-process latency: %v per event", per)
	if per > 5*time.Millisecond {
		t.Fatalf("too slow: %v", per)
	}
}

func BenchmarkPreBash(b *testing.B) {
	in := bashEvent(b, "cd /repo && FOO=1 sudo qbit-vault list --json | jq .secrets && go test ./...")
	for i := 0; i < b.N; i++ {
		run(b, in)
	}
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
