package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/hosts/fake"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// registered returns a vault with the fake host registered by init.
func registered(t *testing.T) (*world, *fake.Adapter) {
	t.Helper()
	w := newBareWorld(t)
	h := fakeHost(t, w)
	withHosts(t, h)
	w.mustRun("", "init")
	return w, h
}

const healthyHostReport = "ok    vault            unlocked (keychain: %MODE%)\n" +
	"ok    permissions      owner-only\n" +
	"ok    host.fake.mcp    registered\n" +
	"ok    host.fake.hooks  registered\n" +
	"healthy\n"

func healthy() string {
	return strings.ReplaceAll(healthyHostReport, "%MODE%", keychain.NewOS().Name())
}

func TestSyncIsIdempotentAndWritesNothing(t *testing.T) {
	w, h := registered(t)
	before := tree(t, w.home, h.Dir)
	code, out, errs := w.run("", "sync")
	if code != exitcode.OK || errs != "" || out != "host fake: up to date\n"+healthy() {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if after := tree(t, w.home, h.Dir); after != before {
		t.Fatalf("a no-op sync wrote something:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestSyncRepairsDriftAndASecondRunIsQuiet(t *testing.T) {
	w, h := registered(t)
	cfg := filepath.Join(h.Dir, "config.json")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "sync")
	if code != exitcode.OK || errs != "" || out != "host fake: repaired (mcp)\n"+healthy() {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if !strings.Contains(readFile(t, cfg), "qbit-vault") {
		t.Fatal("the entry was not restored")
	}
	before := tree(t, w.home, h.Dir)
	if code, out, _ := w.run("", "sync"); code != exitcode.OK || out != "host fake: up to date\n"+healthy() {
		t.Fatalf("second run: code=%d out=%q", code, out)
	}
	if tree(t, w.home, h.Dir) != before {
		t.Fatal("the second run wrote something")
	}
}

func TestSyncOnlyTouchesRecordedHostsUnlessAskedTo(t *testing.T) {
	w, h := registered(t)
	otherDir := filepath.Join(filepath.Dir(w.home), "otherhost")
	if err := os.MkdirAll(otherDir, 0o700); err != nil { // detected, never registered
		t.Fatal(err)
	}
	other := fake.New("other", otherDir)
	withHosts(t, h, other)

	code, out, errs := w.run("", "sync")
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "host fake: up to date\n") || strings.Contains(out, "other") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(otherDir, "config.json")); !os.IsNotExist(err) {
		t.Fatal("sync registered a host that was only detected")
	}

	code, out, errs = w.run("", "sync", "--agents", "other")
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "host fake: up to date\nhost other: registered (mcp, hooks)\n") {
		t.Fatalf("--agents: code=%d out=%q err=%q", code, out, errs)
	}
	if hs, _ := vault.ReadHosts(w.home); len(hs) != 2 {
		t.Fatalf("hosts: %+v", hs)
	}
	if code, out, _ := w.run("", "sync", "--agents", "nope"); code != exitcode.Usage || out != "" {
		t.Fatalf("unknown agent: code=%d out=%q", code, out)
	}
}

func TestSyncReportsAHostWithoutAnAdapterAndKeepsIt(t *testing.T) {
	w, _ := registered(t)
	withHosts(t) // a build without that adapter
	state := readFile(t, w.home, "state.json")
	code, out, errs := w.run("", "sync")
	if code != exitcode.Failure || errs != "" ||
		!strings.HasPrefix(out, "host fake: no adapter in this build; left as is\n") ||
		!strings.Contains(out, "warn  host.fake    registered, but this build has no adapter for it\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if readFile(t, w.home, "state.json") != state {
		t.Fatal("the unknown host was removed from state.json")
	}
}

func TestSyncWithNothingRegistered(t *testing.T) {
	w := newWorld(t)
	code, out, errs := w.run("", "sync")
	want := "no hosts registered; run 'qbit-vault init'\n" +
		"ok    vault        unlocked (keychain: " + keychain.NewOS().Name() + ")\n" +
		"ok    permissions  owner-only\nhealthy\n"
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestSyncWithoutAVault(t *testing.T) {
	w := newBareWorld(t)
	code, out, errs := w.run("", "sync")
	if code != exitcode.Failure || out != "" || errs != "error: no vault here; run 'qbit-vault init'\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(w.home); !os.IsNotExist(err) {
		t.Fatal("sync created the vault home")
	}
}

func TestSyncFailingHostIsTypedAndLeavesTheFileAlone(t *testing.T) {
	w, h := registered(t)
	cfg := filepath.Join(h.Dir, "config.json")
	if err := os.WriteFile(cfg, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "sync")
	if code != exitcode.Failure || errs != "error: host registration failed: fake (mcp)\n" || !strings.HasPrefix(out, "host fake: failed at mcp\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if readFile(t, cfg) != "{not json" {
		t.Fatal("a file that cannot be merged was modified")
	}
	code, out, _ = w.run("", "--json", "sync")
	if code != exitcode.Failure || !strings.Contains(out, `"code":"host_failed"`) {
		t.Fatalf("json: code=%d out=%q", code, out)
	}
}

func TestSyncJSON(t *testing.T) {
	w, h := registered(t)
	if err := os.WriteFile(filepath.Join(h.Dir, "hooks.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "--json", "sync")
	var body struct {
		OK    bool `json:"ok"`
		Hosts []struct {
			Name   string
			Status string
			Steps  []string
		}
		Doctor struct{ OK bool }
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil || code != exitcode.OK || errs != "" {
		t.Fatalf("code=%d out=%q err=%v", code, out, err)
	}
	if !body.OK || len(body.Hosts) != 1 || body.Hosts[0].Name != "fake" || body.Hosts[0].Status != "repaired" ||
		strings.Join(body.Hosts[0].Steps, ",") != "hooks" || !body.Doctor.OK {
		t.Fatalf("body: %s", out)
	}
}

func TestSyncRepairsARealAdapterAfterTheUserWipedItsConfig(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, claudeHost(uh))
	w.mustRun("", "init", "--agents", "claude-code")
	settings := filepath.Join(uh, ".claude", "settings.json")
	if err := os.WriteFile(settings, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "sync")
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "host claude-code: repaired (") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	before := tree(t, w.home, uh)
	if code, out, _ := w.run("", "sync"); code != exitcode.OK || !strings.HasPrefix(out, "host claude-code: up to date\n") {
		t.Fatalf("second run: code=%d out=%q", code, out)
	}
	if tree(t, w.home, uh) != before {
		t.Fatal("the second run wrote something")
	}
}
