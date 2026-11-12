package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/hosts/pi"
)

// The extension ships as the git tag pi-v0.2.3 of this repository, not on npm
// (odd/tasks/pi-extension.md S12.4): init and sync print the install commands
// as a suggestion for the Pi host and never run them.
const piInstallLine = "  Pi extension (optional, run it yourself): gentle-shell -- install git:github.com/qbitdevz/qbit-vault@pi-v0.2.3\n" +
	"  with plain Pi: pi install git:github.com/qbitdevz/qbit-vault@pi-v0.2.3\n"

func noPiEnv(string) string { return "" }

func piHost(uh string) *pi.Adapter {
	return pi.NewWithExe(filepath.Join(uh, "bin", "qbit-vault")).WithLookPath(noClaudeBinary).WithGetenv(noPiEnv)
}

func TestInitRegistersPiAndSuggestsTheExtensionCommand(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, piHost(uh))
	code, out, errs := w.run("", "init", "--agents", "pi")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host pi: registered (mcp, skill)\n"+piInstallLine) || !strings.HasSuffix(out, "healthy\n"+restartAgentsLine+"\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if s := doctorStatus(out, "host.pi.mcp"); s != "ok" {
		t.Fatalf("host.pi.mcp is %q:\n%s", s, out)
	}
	cfg := readFile(t, uh, ".pi", "agent", "mcp.json")
	for _, want := range []string{`"qbit-vault": {`, `"mcp"`, `"QBIT_VAULT_HOME"`} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config lacks %q:\n%s", want, cfg)
		}
	}
	noFixtures(t, "pi config", cfg+readFile(t, w.home, "state.json"))

	// Second run: nothing changes; the suggestion is still printed.
	state, backups := readFile(t, w.home, "state.json"), dirNames(t, filepath.Join(w.home, "backups"))
	code, out, errs = w.run("", "init", "--agents", "pi")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host pi: up to date\n"+piInstallLine) {
		t.Fatalf("second run: code=%d out=%q err=%q", code, out, errs)
	}
	if readFile(t, uh, ".pi", "agent", "mcp.json") != cfg || readFile(t, w.home, "state.json") != state ||
		strings.Join(dirNames(t, filepath.Join(w.home, "backups")), ",") != strings.Join(backups, ",") {
		t.Fatal("the second run wrote something")
	}

	// The user deletes our entry: doctor warns and exits 1, init repairs it.
	if err := os.WriteFile(filepath.Join(uh, ".pi", "agent", "mcp.json"), []byte("{\"mcpServers\": {}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = w.run("", "doctor")
	if code != exitcode.Failure || doctorStatus(out, "host.pi.mcp") != "warn" {
		t.Fatalf("drift: code=%d\n%s", code, out)
	}
	if code, out, errs = w.run("", "init", "--agents", "pi"); code != exitcode.OK || !strings.Contains(out, "host pi: registered (mcp)\n") {
		t.Fatalf("repair: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestInitPiJSONCarriesNoExtensionCommand(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, piHost(uh))
	code, out, errs := w.run("", "--json", "init", "--agents", "pi")
	if code != exitcode.OK || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	var body struct {
		Hosts []map[string]any `json:"hosts"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil || len(body.Hosts) != 1 || body.Hosts[0]["name"] != "pi" {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if _, ok := body.Hosts[0]["install_command"]; ok || strings.Contains(out, "pi install") {
		t.Fatalf("json carries an extension command:\n%s", out)
	}
}

func TestInitDoesNotSuggestTheExtensionForOtherHostsOrAFailedPi(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, claudeHost(uh), codexHost(uh))
	code, out, _ := w.run("", "init", "--agents", "claude-code,codex")
	if code != exitcode.OK || strings.Contains(out, "pi install") || strings.Contains(out, "Pi extension") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	// A config Pi cannot use (not JSON) fails the step: no command is printed.
	cfgDir := filepath.Join(uh, ".pi", "agent")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "mcp.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	withHosts(t, piHost(uh))
	code, out, _ = w.run("", "init", "--agents", "pi")
	if code == exitcode.OK || strings.Contains(out, "pi install") || strings.Contains(out, "Pi extension") {
		t.Fatalf("failed registration: code=%d out=%q", code, out)
	}
}

func TestInitDetectsPiByItsConfigDirectory(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, piHost(uh))
	code, out, errs := w.run("", "init")
	if code != exitcode.OK || errs != "" || strings.Contains(out, "host pi") {
		t.Fatalf("not installed: code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(uh, ".pi")); !os.IsNotExist(err) {
		t.Fatal("~/.pi created for a host that is not installed")
	}
	if err := os.MkdirAll(filepath.Join(uh, ".pi"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs = w.run("", "init")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host pi: registered (mcp, skill)\n"+piInstallLine) {
		t.Fatalf("installed: code=%d out=%q err=%q", code, out, errs)
	}
}

// A `pi` binary on PATH marks Pi as installed, but init must never run it
// (invariant 8: the extension install is the user's command).
func TestInitNeverExecutesPi(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "pi-was-run")
	name, script := "pi", "#!/bin/sh\ntouch '"+marker+"'\n"
	if runtime.GOOS == "windows" {
		name, script = "pi.bat", "@echo off\r\necho x> \""+marker+"\"\r\n"
	}
	if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	withHosts(t, pi.NewWithExe(filepath.Join(uh, "bin", "qbit-vault")).WithGetenv(noPiEnv)) // real PATH lookup
	for _, args := range [][]string{{"init"}, {"init"}, {"doctor"}} {
		code, out, errs := w.run("", args...)
		if code != exitcode.OK || errs != "" {
			t.Fatalf("%v: code=%d out=%q err=%q", args, code, out, errs)
		}
		if args[0] == "init" && !strings.Contains(out, "host pi: ") {
			t.Fatalf("pi on PATH not detected:\n%s", out)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("init or doctor executed pi")
	}
}

func TestSyncSuggestsTheExtensionCommandForARecordedPiAndNeverRunsIt(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, piHost(uh))
	if code, out, errs := w.run("", "init", "--agents", "pi"); code != exitcode.OK {
		t.Fatalf("init: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs := w.run("", "sync")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host pi: up to date\n"+piInstallLine) {
		t.Fatalf("sync: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("", "--json", "sync")
	if code != exitcode.OK || errs != "" || strings.Contains(out, "pi install") || strings.Contains(out, "gentle-shell") {
		t.Fatalf("sync --json: code=%d out=%q err=%q", code, out, errs)
	}
}

// The suggested tag is the version of the package in this repository, so a
// version bump cannot forget the constant.
func TestExtensionInstallCommandMatchesThePackageVersion(t *testing.T) {
	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(repoFile(t, "packages", "qbit-vault-pi", "package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	if pi.ExtensionVersion != pkg.Version {
		t.Fatalf("internal/hosts/pi ExtensionVersion %q, packages/qbit-vault-pi/package.json %q", pi.ExtensionVersion, pkg.Version)
	}
	if pi.ExtensionInstallCommand != "gentle-shell -- install git:github.com/qbitdevz/qbit-vault@pi-v"+pkg.Version ||
		pi.ExtensionInstallCommandPi != "pi install git:github.com/qbitdevz/qbit-vault@pi-v"+pkg.Version {
		t.Fatalf("install commands %q, %q", pi.ExtensionInstallCommand, pi.ExtensionInstallCommandPi)
	}
}
