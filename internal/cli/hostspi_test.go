package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/hosts/pi"
)

const piInstallLine = "host pi: to add the extension, run: pi install npm:qbit-vault-pi\n"

func noPiEnv(string) string { return "" }

func piHost(uh string) *pi.Adapter {
	return pi.NewWithExe(filepath.Join(uh, "bin", "qbit-vault")).WithLookPath(noClaudeBinary).WithGetenv(noPiEnv)
}

func TestInitRegistersPiAndPrintsTheExtensionCommand(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, piHost(uh))
	code, out, errs := w.run("", "init", "--agents", "pi")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host pi: registered (mcp)\n"+piInstallLine) || !strings.HasSuffix(out, "healthy\n") {
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

	// Second run: nothing changes, and the command is still shown (the
	// extension is not something init can verify).
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

func TestInitPiJSONCarriesTheExtensionCommand(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, piHost(uh))
	code, out, errs := w.run("", "--json", "init", "--agents", "pi")
	if code != exitcode.OK || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	var body struct {
		Hosts []struct {
			Name           string `json:"name"`
			InstallCommand string `json:"install_command"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil || len(body.Hosts) != 1 ||
		body.Hosts[0].Name != "pi" || body.Hosts[0].InstallCommand != "pi install npm:qbit-vault-pi" {
		t.Fatalf("json: %v\n%s", err, out)
	}
}

func TestInitDoesNotPrintTheExtensionCommandForOtherHostsOrFailures(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, claudeHost(uh), codexHost(uh))
	code, out, _ := w.run("", "init", "--agents", "claude-code,codex")
	if code != exitcode.OK || strings.Contains(out, "pi install") {
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
	if code == exitcode.OK || strings.Contains(out, "pi install") {
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
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host pi: registered (mcp)\n"+piInstallLine) {
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
