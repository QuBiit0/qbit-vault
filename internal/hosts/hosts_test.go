package hosts_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/filemerge"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/hosts/fake"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

type rig struct {
	t    *testing.T
	env  hosts.Env
	dir  string // the fake host's config directory
	host *fake.Adapter
}

func newRig(t *testing.T) *rig {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "vault-home")
	if _, err := vault.Init(home, vault.NewID(), secret.New("k", bytes.Repeat([]byte{7}, 32))); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "fakehost")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, env: hosts.Env{VaultHome: home, UserHome: base}, dir: dir, host: fake.New("fake", dir)}
}

func (r *rig) read(rel string) string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, rel))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func (r *rig) state() string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.env.VaultHome, "state.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func (r *rig) backups() []string {
	r.t.Helper()
	var out []string
	_ = filepath.Walk(filepath.Join(r.env.VaultHome, "backups"), func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func TestApplyRegistersAndRecordsReceipts(t *testing.T) {
	r := newRig(t)
	res := hosts.Apply(r.env, []hosts.Adapter{r.host})
	if len(res) != 1 || res[0].Err() != nil || !res[0].Changed() {
		t.Fatalf("result: %+v", res)
	}
	if got := res[0].Steps; len(got) != 2 || got[0].Name != "mcp" || got[1].Name != "hooks" {
		t.Fatalf("steps: %+v", got)
	}
	if !json.Valid([]byte(r.read("config.json"))) || !json.Valid([]byte(r.read("hooks.json"))) {
		t.Fatal("host config is not valid JSON")
	}
	hs, err := vault.ReadHosts(r.env.VaultHome)
	if err != nil {
		t.Fatal(err)
	}
	h := hs["fake"]
	if !reflect.DeepEqual(h.Registered, []string{"mcp", "hooks"}) || h.RegisteredAt == "" {
		t.Fatalf("host record: %+v", h)
	}
	for _, step := range []string{"mcp", "hooks"} {
		rc, ok := h.Receipts[step]
		if !ok || !filepath.IsAbs(rc.Path) || rc.SHA256 == "" || !rc.Created {
			t.Fatalf("receipt %s: %+v", step, rc)
		}
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	r := newRig(t)
	hosts.Apply(r.env, []hosts.Adapter{r.host})
	state, cfg, hooks, bk := r.state(), r.read("config.json"), r.read("hooks.json"), r.backups()

	res := hosts.Apply(r.env, []hosts.Adapter{r.host})
	if res[0].Err() != nil || res[0].Changed() {
		t.Fatalf("second run: %+v", res[0])
	}
	if r.state() != state || r.read("config.json") != cfg || r.read("hooks.json") != hooks {
		t.Fatal("second run wrote something")
	}
	if got := r.backups(); !reflect.DeepEqual(got, bk) {
		t.Fatalf("second run took a snapshot: %v -> %v", bk, got)
	}
}

func TestApplyPreservesTheUsersKeys(t *testing.T) {
	r := newRig(t)
	if err := os.WriteFile(filepath.Join(r.dir, "config.json"), []byte("{\n  \"theme\": \"dark\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := hosts.Apply(r.env, []hosts.Adapter{r.host})
	if res[0].Err() != nil {
		t.Fatal(res[0].Err())
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.read("config.json")), &m); err != nil || string(m["theme"]) != `"dark"` || m["mcpServers"] == nil {
		t.Fatalf("config: %v %v", m, err)
	}
	hs, _ := vault.ReadHosts(r.env.VaultHome)
	rc := hs["fake"].Receipts["mcp"]
	if rc.Created || !rc.Snapshot.Existed || !filepath.IsAbs(rc.Snapshot.Backup) {
		t.Fatalf("receipt: %+v", rc)
	}
}

func TestFailingStepKeepsEarlierStepsAndLeavesItsFileUntouched(t *testing.T) {
	r := newRig(t)
	const broken = "{ this is not json "
	if err := os.WriteFile(filepath.Join(r.dir, "hooks.json"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	res := hosts.Apply(r.env, []hosts.Adapter{r.host})
	if len(res) != 1 || res[0].Err() == nil {
		t.Fatalf("expected a failure: %+v", res)
	}
	if !errors.Is(res[0].Err(), filemerge.ErrInvalidJSON) {
		t.Fatalf("err = %v", res[0].Err())
	}
	if res[0].FailedStep() != "hooks" {
		t.Fatalf("failed step = %q", res[0].FailedStep())
	}
	if r.read("hooks.json") != broken {
		t.Fatal("the failing file was modified")
	}
	hs, _ := vault.ReadHosts(r.env.VaultHome)
	h := hs["fake"]
	if !reflect.DeepEqual(h.Registered, []string{"mcp"}) || h.Receipts["mcp"].Path == "" || len(h.Receipts) != 1 {
		t.Fatalf("host record after failure: %+v", h)
	}
	// Repair the file and re-run: only the missing step is applied.
	if err := os.WriteFile(filepath.Join(r.dir, "hooks.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = hosts.Apply(r.env, []hosts.Adapter{r.host})
	if res[0].Err() != nil || res[0].Steps[0].Changed || !res[0].Steps[1].Changed {
		t.Fatalf("re-run: %+v", res[0])
	}
}

func TestAFailingHostDoesNotStopTheNext(t *testing.T) {
	r := newRig(t)
	if err := os.WriteFile(filepath.Join(r.dir, "config.json"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := fake.New("other", filepath.Join(filepath.Dir(r.dir), "otherhost"))
	res := hosts.Apply(r.env, []hosts.Adapter{r.host, other})
	if len(res) != 2 || res[0].Err() == nil || res[1].Err() != nil || !res[1].Changed() {
		t.Fatalf("results: %+v", res)
	}
}

func TestVerifyReportsDriftAndMissingSteps(t *testing.T) {
	r := newRig(t)
	hosts.Apply(r.env, []hosts.Adapter{r.host})
	hs, _ := vault.ReadHosts(r.env.VaultHome)

	checks := hosts.Verify(r.env, r.host, hs["fake"])
	for _, c := range checks {
		if c.Err != nil {
			t.Fatalf("clean host reports %s: %v", c.Step, c.Err)
		}
	}
	// The user removes our entry.
	if err := os.WriteFile(filepath.Join(r.dir, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := r.read("config.json")
	checks = hosts.Verify(r.env, r.host, hs["fake"])
	if checks[0].Step != "mcp" || !errors.Is(checks[0].Err, hosts.ErrDrift) || checks[1].Err != nil {
		t.Fatalf("checks: %+v", checks)
	}
	if r.read("config.json") != before {
		t.Fatal("Verify wrote")
	}
	// A step with no receipt.
	h := hs["fake"]
	delete(h.Receipts, "hooks")
	checks = hosts.Verify(r.env, r.host, h)
	if !errors.Is(checks[1].Err, hosts.ErrNotRegistered) {
		t.Fatalf("checks: %+v", checks)
	}
}

func TestRevertRestoresTheHostAndForgetsIt(t *testing.T) {
	r := newRig(t)
	orig := "{\n  \"theme\": \"dark\"\n}\n"
	if err := os.WriteFile(filepath.Join(r.dir, "config.json"), []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts.Apply(r.env, []hosts.Adapter{r.host})
	if err := hosts.Revert(r.env, r.host); err != nil {
		t.Fatal(err)
	}
	if r.read("config.json") != orig {
		t.Fatalf("config not restored: %q", r.read("config.json"))
	}
	if _, err := os.Stat(filepath.Join(r.dir, "hooks.json")); !os.IsNotExist(err) {
		t.Fatal("a file we created survived the revert")
	}
	if hs, _ := vault.ReadHosts(r.env.VaultHome); len(hs) != 0 {
		t.Fatalf("host still recorded: %+v", hs)
	}
}

func TestRegistrySelect(t *testing.T) {
	a, b := fake.New("alpha", t.TempDir()), fake.New("beta", filepath.Join(t.TempDir(), "missing"))
	reg := hosts.NewRegistry(a, b)
	if got := reg.Names(); !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
		t.Fatalf("names: %v", got)
	}
	env := hosts.Env{}
	if got := reg.Detected(env); len(got) != 1 || got[0].Name() != "alpha" {
		t.Fatalf("detected: %v", got)
	}
	got, err := reg.Pick([]string{"beta", "alpha", "beta"})
	if err != nil || len(got) != 2 || got[0].Name() != "beta" {
		t.Fatalf("pick: %v %v", got, err)
	}
	if _, err := reg.Pick([]string{"zeta"}); !errors.Is(err, hosts.ErrUnknownHost) {
		t.Fatalf("pick unknown: %v", err)
	}
}
