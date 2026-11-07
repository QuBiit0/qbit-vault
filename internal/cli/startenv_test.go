package cli

import (
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
)

// S12.3 (A-F10): names that change how a child starts are never injected.
var startupEnvNames = []string{
	"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
	"BASH_ENV", "ENV", "PATH", "PATHEXT", "PYTHONSTARTUP", "NODE_OPTIONS", "PERL5OPT",
	"RUBYOPT", "COMSPEC", "PROMPT_COMMAND",
}

func startupMsg(name string) string {
	return name + " cannot be used as a secret or variable name: it changes how a command starts"
}

func TestExecRefusesStartupEnvNames(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	mk := marker(t)
	run := child(t, "mark", mk, 0)
	for _, name := range startupEnvNames {
		for _, spec := range []string{name + "=GITHUB_TOKEN", name} {
			code, out, errs := w.run("", execArgs(sessA, []string{spec}, run)...)
			if code != exitcode.Usage || out != "" || errs != usageErr(startupMsg(name)) {
				t.Errorf("%s: code=%d stdout=%q stderr=%q", spec, code, out, errs)
			}
			if strings.Contains(out+errs, "TESTSECRET_") {
				t.Errorf("%s: a value reached the output", spec)
			}
		}
	}
	if ran(mk) {
		t.Fatal("a refused exec started the child")
	}
	if n := len(w.auditEvents(audit.EventExec)); n != 0 {
		t.Fatalf("refused exec was audited as exec (%d records)", n)
	}
}

func TestExecAllowsNamesThatOnlyLookLikeStartupVariables(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	for _, env := range []string{"PATH_TOKEN", "ENVIRONMENT", "MY_ENV", "DYLD", "LD_TOKEN", "NODE_TOKEN"} {
		if err := checkStartupEnv(env); err != nil {
			t.Errorf("%s must be allowed: %v", env, err)
		}
	}
	mk := marker(t)
	code, _, errs := w.run("", execArgs(sessA, []string{"GH_TOKEN=GITHUB_TOKEN"}, child(t, "mark", mk, 0))...)
	if code != 0 || !ran(mk) {
		t.Fatalf("a normal exec stopped working: code=%d stderr=%q", code, errs)
	}
}

func TestSetRefusesStartupEnvNames(t *testing.T) {
	for _, name := range append(startupEnvNames, "DYLD_FALLBACK_LIBRARY_PATH") {
		w := newWorld(t)
		w.mustRun(fxVal, "set", "KEEP_ME", "--global", "--stdin")
		before := w.snapshot()
		code, out, errs := w.run(fxVal, "set", name, "--global", "--stdin")
		if code != exitcode.Usage || out != "" || errs != usageErr(startupMsg(name)) {
			t.Errorf("%s: code=%d out=%q err=%q", name, code, out, errs)
		}
		code, out, errs = w.run(fxVal, "--json", "set", name, "--global", "--stdin")
		wantJSON := `{"ok":false,"error":{"code":"usage","message":"` + startupMsg(name) + `"}}` + "\n"
		if code != exitcode.Usage || out != wantJSON || errs != "" {
			t.Errorf("%s json: code=%d out=%q err=%q", name, code, out, errs)
		}
		if strings.Contains(out+errs, "TESTSECRET_") || w.snapshot() != before {
			t.Errorf("%s: a value was echoed or the vault changed", name)
		}
	}
}
