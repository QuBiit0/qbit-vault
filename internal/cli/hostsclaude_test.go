package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/hosts/claude"
)

// releaseHostRegistry is the registry of a release build, captured before
// init() empties it for the whole test binary: the release registry holds the
// Claude Code adapter, which would write to the real ~/.claude.json and
// ~/.claude/settings.json of whoever runs the tests. Tests that exercise the
// adapter install their own through withHosts, with a temporary user home.
var releaseHostRegistry = hostRegistry

func init() {
	hostRegistry = func(*globals) *hosts.Registry { return hosts.NewRegistry() }
}

// isolateUserHome points the user home at a temporary directory and fails the
// test if the process would still see another one.
func isolateUserHome(t *testing.T) string {
	t.Helper()
	uh := t.TempDir()
	t.Setenv("USERPROFILE", uh) // Windows
	t.Setenv("HOME", uh)
	if got, err := os.UserHomeDir(); err != nil || got != uh {
		t.Fatalf("user home is %q (%v), want the temporary %q", got, err, uh)
	}
	return uh
}

func noClaudeBinary(string) (string, error) { return "", errors.New("not found") }

func claudeHost(uh string) *claude.Adapter {
	return claude.NewWithExe(filepath.Join(uh, "bin", "qbit-vault")).WithLookPath(noClaudeBinary)
}

// doctorStatus returns the status word of the doctor line for a check.
func doctorStatus(out, check string) string {
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[1] == check {
			return f[0]
		}
	}
	return ""
}

func TestInitRegistersClaudeCodeAndDoctorIsHealthy(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, claudeHost(uh))
	code, out, errs := w.run("", "init", "--agents", "claude-code")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host claude-code: registered (mcp, hooks, deny, skill)\n") || !strings.HasSuffix(out, "healthy\n"+restartAgentsLine+"\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	for _, step := range []string{"mcp", "hooks", "deny", "skill"} {
		if s := doctorStatus(out, "host.claude-code."+step); s != "ok" {
			t.Fatalf("host.claude-code.%s is %q:\n%s", step, s, out)
		}
	}
	mcp := readFile(t, uh, ".claude.json")
	settings := readFile(t, uh, ".claude", "settings.json")
	for _, want := range []string{`"qbit-vault"`, `"mcp"`, `"QBIT_VAULT_HOME"`} {
		if !strings.Contains(mcp, want) {
			t.Fatalf("mcp entry lacks %s:\n%s", want, mcp)
		}
	}
	for _, sub := range []string{"pre-bash", "post-bash", "post-read", "user-prompt"} {
		if !strings.Contains(settings, `"statusMessage": "qbit-vault hook `+sub+`"`) {
			t.Fatalf("hook %s missing:\n%s", sub, settings)
		}
	}
	noFixtures(t, "claude config", mcp+settings+readFile(t, w.home, "state.json"))

	// Second run: nothing changes, no new snapshot.
	state, backups := readFile(t, w.home, "state.json"), dirNames(t, filepath.Join(w.home, "backups"))
	code, out, errs = w.run("", "init", "--agents", "claude-code")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host claude-code: up to date\n") {
		t.Fatalf("second run: code=%d out=%q err=%q", code, out, errs)
	}
	if readFile(t, uh, ".claude.json") != mcp || readFile(t, uh, ".claude", "settings.json") != settings ||
		readFile(t, w.home, "state.json") != state || strings.Join(dirNames(t, filepath.Join(w.home, "backups")), ",") != strings.Join(backups, ",") {
		t.Fatal("the second run wrote something")
	}

	// The user removes our hook: doctor warns and exits 1, init repairs it.
	cut := strings.Replace(settings, `"UserPromptSubmit"`, `"UserPromptSubmitGone"`, 1)
	if err := os.WriteFile(filepath.Join(uh, ".claude", "settings.json"), []byte(cut), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = w.run("", "doctor")
	if code != exitcode.Failure || doctorStatus(out, "host.claude-code.hooks") != "warn" || doctorStatus(out, "host.claude-code.mcp") != "ok" {
		t.Fatalf("drift: code=%d\n%s", code, out)
	}
	if code, out, errs = w.run("", "init", "--agents", "claude-code"); code != exitcode.OK || !strings.Contains(out, "host claude-code: registered (hooks)\n") {
		t.Fatalf("repair: code=%d out=%q err=%q", code, out, errs)
	}
	if code, out, _ = w.run("", "doctor"); code != exitcode.OK || doctorStatus(out, "host.claude-code.hooks") != "ok" {
		t.Fatalf("after repair: code=%d\n%s", code, out)
	}
}

func TestInitDetectsClaudeCodeByItsConfigDirectory(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, claudeHost(uh))
	code, out, errs := w.run("", "init")
	if code != exitcode.OK || errs != "" || strings.Contains(out, "host claude-code") {
		t.Fatalf("not installed: code=%d out=%q err=%q", code, out, errs)
	}
	for _, f := range []string{".claude.json", filepath.Join(".claude", "settings.json")} {
		if _, err := os.Stat(filepath.Join(uh, f)); !os.IsNotExist(err) {
			t.Fatalf("%s written for a host that is not installed", f)
		}
	}
	if err := os.MkdirAll(filepath.Join(uh, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs = w.run("", "init")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host claude-code: registered (mcp, hooks, deny, skill)\n") {
		t.Fatalf("installed: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestInitKeepsAnExistingClaudeConfiguration(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, claudeHost(uh))
	settings := "{\n  \"hooks\": {\"PreToolUse\": [{\"matcher\": \"Bash\", \"hooks\": [{\"type\": \"command\", \"command\": \"gentle-ai hook guard\"}]}]},\n  \"permissions\": {\"deny\": [\"Read(.env)\"]}\n}\n"
	if err := os.MkdirAll(filepath.Join(uh, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uh, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	w.mustRun("", "init", "--agents", "claude-code")
	got := readFile(t, uh, ".claude", "settings.json")
	if !strings.Contains(got, `"command": "gentle-ai hook guard"`) || !strings.Contains(got, `"Read(.env)"`) {
		t.Fatalf("user entries lost:\n%s", got)
	}
	if len(dirNames(t, filepath.Join(w.home, "backups"))) == 0 {
		t.Fatal("no snapshot of the existing settings")
	}
}
