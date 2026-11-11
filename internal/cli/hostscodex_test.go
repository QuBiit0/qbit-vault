package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/hosts/codex"
)

const codexTrust = "  Codex skips new hooks until you trust them: open /hooks in Codex and trust the qbit-vault hooks."

func codexHost(uh string) *codex.Adapter {
	return codex.NewWithExe(filepath.Join(uh, "bin", "qbit-vault")).WithLookPath(noClaudeBinary)
}

func TestReleaseRegistryIsClaudeCodeCodexAndPi(t *testing.T) {
	names := releaseHostRegistry(&globals{}).Names()
	if strings.Join(names, ",") != "claude-code,codex,pi" {
		t.Fatalf("release registry: %v", names)
	}
}

func TestInitRegistersCodexAndDoctorIsHealthy(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, codexHost(uh))
	code, out, errs := w.run("", "init", "--agents", "codex")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host codex: registered (mcp, hooks, skill)\n"+codexTrust+"\n") || !strings.HasSuffix(out, "healthy\n"+restartAgentsLine+"\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	for _, c := range []string{"host.codex.mcp", "host.codex.hooks"} {
		if s := doctorStatus(out, c); s != "ok" {
			t.Fatalf("%s is %q:\n%s", c, s, out)
		}
	}
	hooks := readFile(t, uh, ".codex", "hooks.json")
	for _, want := range []string{`"matcher": "Bash"`, ` hook post-bash --host codex`, `"matcher": "apply_patch"`, ` hook pre-write --host codex`} {
		if !strings.Contains(hooks, want) {
			t.Fatalf("hooks.json lacks %q:\n%s", want, hooks)
		}
	}
	noFixtures(t, "codex hooks", hooks)
	cfg := readFile(t, uh, ".codex", "config.toml")
	for _, want := range []string{"[mcp_servers.qbit-vault]\n", "args = [\"mcp\"]\n", "[mcp_servers.qbit-vault.env]\n", "QBIT_VAULT_HOME = "} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config lacks %q:\n%s", want, cfg)
		}
	}
	noFixtures(t, "codex config", cfg+readFile(t, w.home, "state.json"))

	// Second run: nothing changes, no new snapshot.
	state, backups := readFile(t, w.home, "state.json"), dirNames(t, filepath.Join(w.home, "backups"))
	code, out, errs = w.run("", "init", "--agents", "codex")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host codex: up to date\n") {
		t.Fatalf("second run: code=%d out=%q err=%q", code, out, errs)
	}
	if readFile(t, uh, ".codex", "config.toml") != cfg || readFile(t, uh, ".codex", "hooks.json") != hooks || readFile(t, w.home, "state.json") != state ||
		strings.Join(dirNames(t, filepath.Join(w.home, "backups")), ",") != strings.Join(backups, ",") {
		t.Fatal("the second run wrote something")
	}

	// The user deletes our table: doctor warns and exits 1, init repairs it.
	if err := os.WriteFile(filepath.Join(uh, ".codex", "config.toml"), []byte("model = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = w.run("", "doctor")
	if code != exitcode.Failure || doctorStatus(out, "host.codex.mcp") != "warn" {
		t.Fatalf("drift: code=%d\n%s", code, out)
	}
	if code, out, errs = w.run("", "init", "--agents", "codex"); code != exitcode.OK || !strings.Contains(out, "host codex: registered (mcp)\n") {
		t.Fatalf("repair: code=%d out=%q err=%q", code, out, errs)
	}
	if got := readFile(t, uh, ".codex", "config.toml"); !strings.HasPrefix(got, "model = \"x\"\n\n[mcp_servers.qbit-vault]\n") {
		t.Fatalf("repair changed the user's bytes:\n%s", got)
	}
}

// The user deletes hooks.json entries: doctor warns about the hooks only, and
// init puts them back and asks for the trust review again.
func TestDoctorReportsMissingCodexHooksAndInitRepairsThem(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, codexHost(uh))
	if code, out, errs := w.run("", "init", "--agents", "codex"); code != exitcode.OK {
		t.Fatalf("init: code=%d out=%q err=%q", code, out, errs)
	}
	if err := os.WriteFile(filepath.Join(uh, ".codex", "hooks.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := w.run("", "doctor")
	if code != exitcode.Failure || doctorStatus(out, "host.codex.hooks") != "warn" || doctorStatus(out, "host.codex.mcp") != "ok" {
		t.Fatalf("drift: code=%d\n%s", code, out)
	}
	code, out, errs := w.run("", "init", "--agents", "codex")
	if code != exitcode.OK || !strings.Contains(out, "host codex: registered (hooks)\n"+codexTrust+"\n") {
		t.Fatalf("repair: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestInitDetectsCodexByItsConfigDirectory(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, codexHost(uh))
	code, out, errs := w.run("", "init")
	if code != exitcode.OK || errs != "" || strings.Contains(out, "host codex") {
		t.Fatalf("not installed: code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(uh, ".codex")); !os.IsNotExist(err) {
		t.Fatal("~/.codex created for a host that is not installed")
	}
	if err := os.MkdirAll(filepath.Join(uh, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs = w.run("", "init")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host codex: registered (mcp, hooks, skill)\n") {
		t.Fatalf("installed: code=%d out=%q err=%q", code, out, errs)
	}
}
