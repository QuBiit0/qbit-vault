package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/hosts/codex"
)

// An executable path the Codex hook command cannot carry (not valid UTF-8) is
// reported by init, sync and doctor by name; the host's other steps still
// register (odd/tasks/output-guard.md S10.1).
const (
	wantCodexPathLine = "  Codex output guard not installed: the qbit-vault path cannot be written into a hook command (it is not valid UTF-8). Reinstall qbit-vault in another folder and run 'qbit-vault sync'."
	codexPathDoctor   = "the qbit-vault path cannot be written into a Codex hook command (not valid UTF-8), so the output guard is not installed; reinstall qbit-vault in another folder and run 'qbit-vault sync'"
	codexFailedError  = "error: host registration failed: codex (hooks); run 'qbit-vault doctor' for details\n"
)

func codexHostAt(uh, exe string) *codex.Adapter {
	return codex.NewWithExe(filepath.Join(uh, "bin", exe)).WithLookPath(noClaudeBinary)
}

func TestInitNamesAnExecutablePathTheCodexHookCannotCarry(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, codexHostAt(uh, "qbit\xffvault"))
	code, out, errs := w.run("", "init", "--agents", "codex")
	if code != exitcode.Failure || errs != codexFailedError || !strings.Contains(out, "host codex: failed at hooks\n"+wantCodexPathLine+"\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(uh, ".codex", "hooks.json")); err == nil {
		t.Fatal("hooks.json was created")
	}
	if s := doctorStatus(out, "host.codex.executable"); s != "warn" || !strings.Contains(out, codexPathDoctor) {
		t.Fatalf("doctor says %q:\n%s", s, out)
	}
	code, out, _ = w.run("", "doctor")
	if code != exitcode.Failure || doctorStatus(out, "host.codex.executable") != "warn" || !strings.Contains(out, codexPathDoctor) {
		t.Fatalf("doctor: code=%d\n%s", code, out)
	}
}

func TestSyncNamesAnExecutablePathTheCodexHookCannotCarry(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, codexHost(uh))
	if code, out, errs := w.run("", "init", "--agents", "codex"); code != exitcode.OK {
		t.Fatalf("init: code=%d out=%q err=%q", code, out, errs)
	}
	hooks := readFile(t, uh, ".codex", "hooks.json")
	withHosts(t, codexHostAt(uh, "qbit\xffvault"))
	code, out, errs := w.run("", "sync")
	if code != exitcode.Failure || errs != codexFailedError || !strings.HasPrefix(out, "host codex: failed at hooks\n"+wantCodexPathLine+"\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if readFile(t, uh, ".codex", "hooks.json") != hooks {
		t.Fatal("a failed sync changed hooks.json")
	}
}

// sync prints the trust reminder when it writes the Codex hooks, as init does
// (S10.4); a sync that writes nothing prints none.
func TestSyncAsksToTrustTheCodexHooksItWrites(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, codexHost(uh))
	if code, out, errs := w.run("", "init", "--agents", "codex"); code != exitcode.OK {
		t.Fatalf("init: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs := w.run("", "sync")
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "host codex: up to date\n") || strings.Contains(out, "trust") {
		t.Fatalf("nothing to write: code=%d out=%q err=%q", code, out, errs)
	}
	if err := os.WriteFile(filepath.Join(uh, ".codex", "hooks.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs = w.run("", "sync")
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "host codex: repaired (hooks)\n"+codexTrust+"\n") {
		t.Fatalf("repair: code=%d out=%q err=%q", code, out, errs)
	}
}
