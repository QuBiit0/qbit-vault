package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/hosts/fake"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/refusal"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

var openProbe = []func(*globals) *cobra.Command{probe}

func TestInitCreatesEmptyVault(t *testing.T) {
	h := newHarness(t)
	mode := keychain.NewOS().Name()
	code, out, errs := h.run("", "init")
	want := "vault initialized at " + h.home + " (keychain: " + mode + ")\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	for _, f := range []string{"vault.enc", "state.json"} {
		if _, err := os.Stat(filepath.Join(h.home, f)); err != nil {
			t.Fatalf("%s missing: %v", f, err)
		}
	}
	if code, out, _ := h.runExtra("", openProbe, "probe"); code != exitcode.OK || out != "opened\n" {
		t.Fatalf("initialized vault does not open: code=%d out=%q", code, out)
	}
}

func TestInitJSON(t *testing.T) {
	h := newHarness(t)
	code, out, errs := h.run("", "--json", "init")
	want := initJSON(t, true, h.home, keychain.NewOS().Name())
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("code=%d out=%q err=%q want=%q", code, out, errs, want)
	}
}

func TestInitIsIdempotent(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "init")
	before, err := os.ReadFile(filepath.Join(h.home, "vault.enc"))
	if err != nil {
		t.Fatal(err)
	}
	code, out, errs := h.run("", "init")
	if code != exitcode.OK || out != "vault already initialized at "+h.home+"\n" || errs != "" {
		t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = h.run("", "--json", "init")
	want := initJSON(t, false, h.home, "")
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("json: code=%d out=%q err=%q want=%q", code, out, errs, want)
	}
	after, _ := os.ReadFile(filepath.Join(h.home, "vault.enc"))
	if string(before) != string(after) {
		t.Fatal("second init rewrote the vault")
	}
}

func TestInitRemovesOrphanKeyWhenVaultInitFails(t *testing.T) {
	h := newHarness(t)
	const id = "6f9619ff-8b86-4d11-b42d-00c04fc964ff"
	old := newVaultID
	newVaultID = func() string { return id }
	t.Cleanup(func() { newVaultID = old })
	// A vault file without state.json makes vault.Init refuse with ErrExists.
	if err := os.MkdirAll(h.home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.home, "vault.enc"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := h.run("", "--json", "init")
	want := jsonOf(t, refusal.New(refusal.VaultCorrupt, "").Envelope())
	if code != exitcode.Corrupt || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := keyring.Get("qbit-vault", "master:"+id); err == nil {
		t.Fatal("orphan key left in the keychain")
	}
	if b, _ := os.ReadFile(filepath.Join(h.home, "vault.enc")); string(b) != "x" {
		t.Fatal("existing vault file was modified")
	}
}

func TestInitPassphraseMode(t *testing.T) {
	h := newHarness(t)
	code, out, errs := h.run(fxPass+"\n", "--json", "init", "--passphrase", "--passphrase-stdin")
	want := initJSON(t, true, h.home, "passphrase-file")
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("code=%d out=%q err=%q want=%q", code, out, errs, want)
	}
	if strings.Contains(out+errs, "TESTSECRET_") {
		t.Fatal("passphrase echoed")
	}
	if _, err := os.Stat(filepath.Join(h.home, "key.enc")); err != nil {
		t.Fatalf("key.enc missing: %v", err)
	}
	// No prompt exists yet and no cache is available: opening is locked.
	code, _, errs = h.runExtra("", openProbe, "probe")
	if code != exitcode.Locked || errs != "error: vault is locked\n" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}

func TestInitPassphraseUsageErrors(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
		args  []string
		msg   string
	}{
		{"passphrase without stdin flag", "", []string{"init", "--passphrase"}, "no controlling terminal available; use --passphrase-stdin"},
		{"stdin flag without passphrase", fxPass + "\n", []string{"init", "--passphrase-stdin"}, "--passphrase-stdin requires --passphrase"},
		{"empty passphrase", "\n", []string{"init", "--passphrase", "--passphrase-stdin"}, "empty passphrase"},
		{"blank passphrase", "   \n", []string{"init", "--passphrase", "--passphrase-stdin"}, "empty passphrase"},
		{"extra argument", "", []string{"init", "TESTSECRET_x"}, "unexpected arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			code, out, errs := h.run(tt.stdin, tt.args...)
			if code != exitcode.Usage || out != "" || errs != "error: "+tt.msg+"\n"+helpHint {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if _, err := os.Stat(filepath.Join(h.home, "vault.enc")); !os.IsNotExist(err) {
				t.Fatal("rejected input created a vault")
			}
			if _, err := os.Stat(filepath.Join(h.home, "key.enc")); !os.IsNotExist(err) {
				t.Fatal("rejected input created a key file")
			}
		})
	}
}

// initJSON is the exact expected stdout of a successful init.
func initJSON(t *testing.T, initialized bool, home, kc string) string {
	t.Helper()
	return jsonOf(t, initBody{OK: true, Initialized: initialized, Home: home, Keychain: kc})
}

// ---- P2: host registration ----

// withHosts makes adapters the registry of this build for one test.
func withHosts(t *testing.T, a ...hosts.Adapter) {
	t.Helper()
	old := hostRegistry
	hostRegistry = func(*globals) *hosts.Registry { return hosts.NewRegistry(a...) }
	t.Cleanup(func() { hostRegistry = old })
}

func fakeHost(t *testing.T, w *world) *fake.Adapter {
	t.Helper()
	dir := filepath.Join(filepath.Dir(w.home), "fakehost")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return fake.New("fake", dir)
}

func readFile(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestInitAgentsNoneKeepsTheVaultOnlyOutput(t *testing.T) {
	w := newBareWorld(t)
	h := fakeHost(t, w)
	withHosts(t, h)
	mode := keychain.NewOS().Name()
	code, out, errs := w.run("", "init", "--agents", "none")
	if code != exitcode.OK || out != "vault initialized at "+w.home+" (keychain: "+mode+")\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if hs, _ := vault.ReadHosts(w.home); len(hs) != 0 {
		t.Fatalf("hosts registered: %+v", hs)
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "config.json")); !os.IsNotExist(err) {
		t.Fatal("host config written with --agents none")
	}
}

func TestInitRegistersDetectedHostsAndFinishesWithDoctor(t *testing.T) {
	t.Setenv("TESTSECRET_ENV_VALUE", fxVal) // init must never look at it
	w := newBareWorld(t)
	h := fakeHost(t, w)
	withHosts(t, h, fake.New("absent", filepath.Join(filepath.Dir(w.home), "nothere")))
	mode := keychain.NewOS().Name()
	code, out, errs := w.run("", "init")
	want := "vault initialized at " + w.home + " (keychain: " + mode + ")\n" +
		"host fake: registered (mcp, hooks)\n" +
		"ok    vault            unlocked (keychain: " + mode + ")\n" +
		"ok    permissions      owner-only\n" +
		"ok    host.fake.mcp    registered\n" +
		"ok    host.fake.hooks  registered\n" +
		"healthy\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d\nout=%q\nwant=%q\nerr=%q", code, out, want, errs)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(w.home), "nothere")); !os.IsNotExist(err) {
		t.Fatal("an undetected host was registered without --agents")
	}
	hs, err := vault.ReadHosts(w.home)
	if err != nil || len(hs["fake"].Receipts) != 2 {
		t.Fatalf("hosts: %+v %v", hs, err)
	}
	noFixtures(t, "state", readFile(t, w.home, "state.json"))
	noFixtures(t, "host config", readFile(t, h.Dir, "config.json")+readFile(t, h.Dir, "hooks.json"))
}

func TestInitRerunsHostStepsOnAnExistingVaultAndChangesNothingTwice(t *testing.T) {
	w := newWorld(t) // vault exists, no host registered
	h := fakeHost(t, w)
	withHosts(t, h)
	code, out, errs := w.run("", "init")
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "vault already initialized at "+w.home+"\nhost fake: registered (mcp, hooks)\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	state, vaultEnc := readFile(t, w.home, "state.json"), readFile(t, w.home, "vault.enc")
	cfg, hooks := readFile(t, h.Dir, "config.json"), readFile(t, h.Dir, "hooks.json")
	backups := dirNames(t, filepath.Join(w.home, "backups"))

	code, out, errs = w.run("", "init")
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "vault already initialized at "+w.home+"\nhost fake: up to date\n") || !strings.HasSuffix(out, "healthy\n") {
		t.Fatalf("second run: code=%d out=%q err=%q", code, out, errs)
	}
	if readFile(t, w.home, "state.json") != state || readFile(t, w.home, "vault.enc") != vaultEnc ||
		readFile(t, h.Dir, "config.json") != cfg || readFile(t, h.Dir, "hooks.json") != hooks {
		t.Fatal("the second run wrote something")
	}
	if got := dirNames(t, filepath.Join(w.home, "backups")); strings.Join(got, ",") != strings.Join(backups, ",") {
		t.Fatalf("the second run took a snapshot: %v -> %v", backups, got)
	}
}

func TestInitAgentsSelectsHostsExplicitly(t *testing.T) {
	w := newBareWorld(t)
	a := fakeHost(t, w)
	missing := fake.New("other", filepath.Join(filepath.Dir(w.home), "otherhost")) // not installed
	withHosts(t, a, missing)
	code, out, errs := w.run("", "init", "--agents", "other,other")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host other: registered (mcp, hooks)\n") || strings.Contains(out, "host fake") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(missing.Dir, "config.json")); err != nil {
		t.Fatalf("explicit host not registered: %v", err)
	}
	if _, err := os.Stat(filepath.Join(a.Dir, "config.json")); !os.IsNotExist(err) {
		t.Fatal("unselected host registered")
	}
}

func TestInitAgentsUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown agent":   {"init", "--agents", "TESTSECRET_nope"},
		"none and a host": {"init", "--agents", "none,fake"},
		"empty list":      {"init", "--agents", ""},
	} {
		t.Run(name, func(t *testing.T) {
			w := newBareWorld(t)
			withHosts(t, fakeHost(t, w))
			code, out, errs := w.run("", args...)
			if code != exitcode.Usage || out != "" || !strings.HasPrefix(errs, "error: ") || strings.Contains(errs, "TESTSECRET_") {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if _, err := os.Stat(filepath.Join(w.home, "vault.enc")); !os.IsNotExist(err) {
				t.Fatal("rejected input created a vault")
			}
		})
	}
	w := newBareWorld(t)
	withHosts(t, fakeHost(t, w))
	if _, _, errs := w.run("", "init", "--agents", "nope"); errs != usageErr("unknown agent; available: fake") {
		t.Fatalf("err=%q", errs)
	}
}

func TestInitFailingHostStepIsReportedAndEarlierStepsKept(t *testing.T) {
	w := newBareWorld(t)
	h := fakeHost(t, w)
	withHosts(t, h)
	const broken = "{ not json"
	if err := os.WriteFile(filepath.Join(h.Dir, "hooks.json"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "init")
	if code != exitcode.Failure || errs != "error: host registration failed: fake (hooks)\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if !strings.Contains(out, "host fake: failed at hooks\n") || !strings.Contains(out, "warn  host.fake.hooks") {
		t.Fatalf("out=%q", out)
	}
	if readFile(t, h.Dir, "hooks.json") != broken {
		t.Fatal("the failing file was modified")
	}
	hs, _ := vault.ReadHosts(w.home)
	if len(hs["fake"].Receipts) != 1 || hs["fake"].Receipts["mcp"].Path == "" {
		t.Fatalf("hosts: %+v", hs)
	}
	if _, err := os.Stat(filepath.Join(w.home, "vault.enc")); err != nil {
		t.Fatal("the vault was not kept")
	}
	// JSON: one error object, no init body.
	code, out, errs = w.run("", "--json", "init")
	if code != exitcode.Failure || errs != "" || !strings.HasPrefix(out, `{"ok":false,"error":{"code":"host_failed"`) || strings.Count(out, "\n") != 1 {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestInitJSONWithHosts(t *testing.T) {
	w := newBareWorld(t)
	withHosts(t, fakeHost(t, w))
	code, out, errs := w.run("", "--json", "init")
	if code != exitcode.OK || errs != "" || strings.Count(out, "\n") != 1 {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	var body struct {
		OK          bool `json:"ok"`
		Initialized bool `json:"initialized"`
		Hosts       []struct {
			Name    string   `json:"name"`
			Changed bool     `json:"changed"`
			Steps   []string `json:"steps"`
		} `json:"hosts"`
		Doctor struct {
			OK     bool `json:"ok"`
			Checks []struct {
				Name, Status string
			} `json:"checks"`
		} `json:"doctor"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || !body.Initialized || len(body.Hosts) != 1 || body.Hosts[0].Name != "fake" || !body.Hosts[0].Changed ||
		strings.Join(body.Hosts[0].Steps, ",") != "mcp,hooks" || !body.Doctor.OK || len(body.Doctor.Checks) != 4 {
		t.Fatalf("body: %s", out)
	}
}
