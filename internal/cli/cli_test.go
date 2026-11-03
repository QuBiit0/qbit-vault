package cli

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
)

const fixture = "TESTSECRET_panic_value_0123456789"

const (
	helpHint    = "Run 'gentle-vault --help' for usage.\n"
	sessionHelp = "invalid --session: must match ^[a-z0-9-]+:[A-Za-z0-9._-]{4,128}$"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func run(t *testing.T, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return runWith(t, env, nil, args...)
}

func runWith(t *testing.T, env map[string]string, extra []func(*globals) *cobra.Command, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := execute(args, &out, &errb, envFrom(env), extra...)
	return code, out.String(), errb.String()
}

func TestVersionHuman(t *testing.T) {
	code, out, errs := run(t, nil, "version")
	want := "gentle-vault " + Version + " (" + Commit + ", " + runtime.GOOS + "/" + runtime.GOARCH + ")\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestVersionJSON(t *testing.T) {
	code, out, errs := run(t, nil, "version", "--json")
	if code != exitcode.OK || errs != "" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	dec := json.NewDecoder(strings.NewReader(out))
	var got map[string]any
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if dec.More() || !strings.HasSuffix(out, "\n") {
		t.Fatalf("stdout must be exactly one JSON object: %q", out)
	}
	want := map[string]any{"ok": true, "version": Version, "commit": Commit, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
	if len(got) != len(want) {
		t.Fatalf("unexpected keys: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("key %s = %v, want %v", k, got[k], v)
		}
	}
}

func jsonUsage(msg string) string {
	b, _ := json.Marshal(errorBody{OK: false, Error: errorDetail{Code: "usage", Message: msg}})
	return string(b) + "\n"
}

func TestUsageErrors(t *testing.T) {
	unknownCmd := `unknown command "bogus" for "gentle-vault"`
	extraArg := `unknown command "extra" for "gentle-vault version"`
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		wantStdout string
		wantStderr string
	}{
		{"unknown command human", []string{"bogus"}, nil, "", "error: " + unknownCmd + "\n" + helpHint},
		{"unknown command json", []string{"--json", "bogus"}, nil, jsonUsage(unknownCmd), ""},
		{"unknown flag human", []string{"version", "--bogus"}, nil, "", "error: unknown flag: --bogus\n" + helpHint},
		{"unknown flag json", []string{"version", "--bogus", "--json"}, nil, jsonUsage("unknown flag: --bogus"), ""},
		{"bad args human", []string{"version", "extra"}, nil, "", "error: " + extraArg + "\n" + helpHint},
		{"bad args json", []string{"version", "extra", "--json"}, nil, jsonUsage(extraArg), ""},
		{"invalid session human", []string{"--session", "nope", "version"}, nil, "", "error: " + sessionHelp + "\n" + helpHint},
		{"invalid session json", []string{"--session", "nope", "version", "--json"}, nil, jsonUsage(sessionHelp), ""},
		{"invalid session from env", []string{"version"}, map[string]string{"GENTLE_VAULT_SESSION": "BAD"}, "", "error: " + sessionHelp + "\n" + helpHint},
		{"no command json", []string{"--json"}, nil, jsonUsage("no command given"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errs := run(t, tt.env, tt.args...)
			if code != exitcode.Usage || out != tt.wantStdout || errs != tt.wantStderr {
				t.Fatalf("code=%d\nstdout=%q\nstderr=%q", code, out, errs)
			}
		})
	}
}

func TestSessionValidation(t *testing.T) {
	valid := []string{"claude-code:abcd", "pi:Session_1.2-x", "codex:" + strings.Repeat("a", 128)}
	for _, s := range valid {
		code, _, errs := run(t, nil, "--session", s, "version")
		if code != exitcode.OK || errs != "" {
			t.Fatalf("session %q rejected: code=%d err=%q", s, code, errs)
		}
	}
	if code, _, _ := run(t, map[string]string{"GENTLE_VAULT_SESSION": "pi:abcd1234"}, "version"); code != exitcode.OK {
		t.Fatalf("valid session from env rejected: %d", code)
	}
	// An explicit flag overrides an invalid env default.
	if code, _, _ := run(t, map[string]string{"GENTLE_VAULT_SESSION": "BAD"}, "--session", "pi:abcd1234", "version"); code != exitcode.OK {
		t.Fatalf("flag did not override env: %d", code)
	}
	invalid := []string{"pi:abc", "Pi:abcd", "pi:" + strings.Repeat("a", 129), "pi:ab cd", ":abcd"}
	for _, s := range invalid {
		if code, _, _ := run(t, nil, "--session", s, "version"); code != exitcode.Usage {
			t.Fatalf("invalid session accepted (len %d)", len(s))
		}
	}
}

func TestNoCommand(t *testing.T) {
	code, out, errs := run(t, nil)
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "Usage:") || !strings.Contains(out, "version") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestHelpIsHumanEvenWithJSON(t *testing.T) {
	code, out, errs := run(t, nil, "--help", "--json")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "Usage:") || strings.HasPrefix(out, "{") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestGlobalsResolution(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		args        []string
		wantHome    string
		wantJSON    bool
		wantNoColor bool
	}{
		{"home from env", map[string]string{"GENTLE_VAULT_HOME": "/env/home"}, nil, "/env/home", false, false},
		{"home flag wins", map[string]string{"GENTLE_VAULT_HOME": "/env/home"}, []string{"--home", "/flag/home"}, "/flag/home", false, false},
		{"NO_COLOR env", map[string]string{"NO_COLOR": "1"}, nil, "", false, true},
		{"no-color flag", nil, []string{"--no-color"}, "", false, true},
		{"json flag", nil, []string{"--json"}, "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen *globals
			probe := func(g *globals) *cobra.Command {
				return &cobra.Command{Use: "probe", RunE: func(*cobra.Command, []string) error { seen = g; return nil }}
			}
			args := append(append([]string{}, tt.args...), "probe")
			code, _, errs := runWith(t, tt.env, []func(*globals) *cobra.Command{probe}, args...)
			if code != exitcode.OK || seen == nil {
				t.Fatalf("code=%d err=%q", code, errs)
			}
			if tt.wantHome != "" && seen.Home() != tt.wantHome {
				t.Fatalf("home = %q", seen.Home())
			}
			if tt.wantHome == "" && !strings.HasSuffix(seen.Home(), ".gentle-vault") {
				t.Fatalf("default home = %q", seen.Home())
			}
			if seen.JSON != tt.wantJSON || seen.NoColorEnabled() != tt.wantNoColor {
				t.Fatalf("json=%v nocolor=%v", seen.JSON, seen.NoColorEnabled())
			}
		})
	}
}

func TestPanicRecovery(t *testing.T) {
	boom := func(*globals) *cobra.Command {
		return &cobra.Command{Use: "boom", RunE: func(*cobra.Command, []string) error { panic(fixture) }}
	}
	extra := []func(*globals) *cobra.Command{boom}

	code, out, errs := runWith(t, nil, extra, "boom")
	if code != exitcode.Failure || out != "" || errs != "error: internal error\n" {
		t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = runWith(t, nil, extra, "boom", "--json")
	want := `{"ok":false,"error":{"code":"internal","message":"internal error"}}` + "\n"
	if code != exitcode.Failure || out != want || errs != "" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

func TestInternalError(t *testing.T) {
	fail := func(*globals) *cobra.Command {
		return &cobra.Command{Use: "fail", RunE: func(*cobra.Command, []string) error { return errBoom{} }}
	}
	extra := []func(*globals) *cobra.Command{fail}
	code, out, errs := runWith(t, nil, extra, "fail")
	if code != exitcode.Failure || out != "" || errs != "error: boom\n" {
		t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = runWith(t, nil, extra, "--json", "fail")
	want := `{"ok":false,"error":{"code":"internal","message":"boom"}}` + "\n"
	if code != exitcode.Failure || out != want || errs != "" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
}
