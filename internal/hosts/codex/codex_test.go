package codex_test

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/filemerge"
	"github.com/qbitdevz/qbit-vault/internal/hosts"
	"github.com/qbitdevz/qbit-vault/internal/hosts/codex"
	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const fakeExe = "/opt/qbit/bin/qbit-vault"

type rig struct {
	t    *testing.T
	env  hosts.Env
	host hosts.Adapter
}

func newRig(t *testing.T) *rig {
	t.Helper()
	home := filepath.Join(t.TempDir(), "user")
	vh := filepath.Join(home, ".qbit-vault")
	if _, err := vault.Init(vh, vault.NewID(), secret.New("k", bytes.Repeat([]byte{7}, 32))); err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, env: hosts.Env{VaultHome: vh, UserHome: home}, host: codex.NewWithExe(fakeExe)}
}

func (r *rig) config() string { return filepath.Join(r.env.UserHome, ".codex", "config.toml") }

func (r *rig) write(path, content string) {
	r.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) read(path string) string {
	r.t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func (r *rig) apply() hosts.Result {
	r.t.Helper()
	res := hosts.Apply(r.env, []hosts.Adapter{r.host})
	if len(res) != 1 || res[0].Err() != nil {
		r.t.Fatalf("apply: %+v", res)
	}
	return res[0]
}

func (r *rig) backups() int {
	n := 0
	_ = filepath.Walk(filepath.Join(r.env.VaultHome, "backups"), func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// lf reads a testdata file with LF endings whatever git checked out.
func lf(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func (r *rig) golden(name string) {
	r.t.Helper()
	got := strings.ReplaceAll(r.read(r.config()), r.env.UserHome, "{HOME}")
	file := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	if got != lf(r.t, name) {
		r.t.Fatalf("config differs from %s:\n%s", file, got)
	}
}

func TestName(t *testing.T) {
	if got := codex.New().Name(); got != "codex" {
		t.Fatalf("name %q", got)
	}
	steps := codex.NewWithExe(fakeExe).Steps(hosts.Env{})
	if len(steps) != 2 || steps[0].Name != "mcp" || steps[1].Name != "skill" {
		t.Fatalf("steps %+v", steps)
	}
}

func TestApplyOnAbsentFile(t *testing.T) {
	r := newRig(t)
	if res := r.apply(); !res.Changed() || len(res.Steps) != 2 {
		t.Fatalf("result %+v", res)
	}
	r.golden("absent.config.toml.golden")
}

func TestApplyKeepsEverythingTheUserHas(t *testing.T) {
	r := newRig(t)
	orig := lf(t, "existing.config.toml")
	r.write(r.config(), orig)
	r.apply()
	r.golden("existing.config.toml.golden")
	got := r.read(r.config())
	if !strings.HasPrefix(got, orig) {
		t.Fatalf("user bytes changed:\n%s", got)
	}
}

func TestCRLFAndMissingTrailingNewline(t *testing.T) {
	r := newRig(t)
	orig := strings.ReplaceAll(strings.TrimSuffix(lf(t, "existing.config.toml"), "\n"), "\n", "\r\n")
	r.write(r.config(), orig)
	r.apply()
	got := r.read(r.config())
	if !strings.HasPrefix(got, orig) {
		t.Fatalf("user bytes changed:\n%q", got)
	}
	if strings.Count(got, "\n") != strings.Count(got, "\r\n") {
		t.Fatalf("mixed line endings:\n%q", got)
	}
	if !strings.Contains(got, "[mcp_servers.qbit-vault]\r\ncommand = ") {
		t.Fatalf("our table is missing:\n%q", got)
	}
	if err := hosts.Revert(r.env, r.host); err != nil {
		t.Fatal(err)
	}
	if r.read(r.config()) != orig {
		t.Fatalf("not restored:\n%q", r.read(r.config()))
	}
}

func TestSecondApplyChangesNothing(t *testing.T) {
	r := newRig(t)
	r.write(r.config(), lf(t, "existing.config.toml"))
	r.apply()
	a := r.read(r.config())
	state, nb := r.read(filepath.Join(r.env.VaultHome, "state.json")), r.backups()
	if res := r.apply(); res.Changed() {
		t.Fatalf("second apply wrote: %+v", res)
	}
	if r.read(r.config()) != a || r.read(filepath.Join(r.env.VaultHome, "state.json")) != state {
		t.Fatal("second apply changed bytes")
	}
	if r.backups() != nb {
		t.Fatal("second apply took a snapshot")
	}
}

func TestRevertRestoresByteForByte(t *testing.T) {
	for _, existing := range []bool{true, false} {
		r := newRig(t)
		want := ""
		if existing {
			want = lf(t, "existing.config.toml")
			r.write(r.config(), want)
		}
		r.apply()
		if err := hosts.Revert(r.env, r.host); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(r.config())
		switch {
		case existing && (err != nil || string(got) != want):
			t.Fatalf("not restored: %v\n%s", err, got)
		case !existing && err == nil:
			t.Fatal("a file we created is still there")
		}
	}
}

func TestRevertKeepsAUserEditMadeAfterUs(t *testing.T) {
	r := newRig(t)
	r.write(r.config(), lf(t, "existing.config.toml"))
	r.apply()
	r.write(r.config(), strings.Replace(r.read(r.config()), `"gpt-5-codex"`, `"o4-mini"`, 1))
	if err := hosts.Revert(r.env, r.host); err != nil {
		t.Fatal(err)
	}
	got := r.read(r.config())
	if !strings.Contains(got, `model = "o4-mini"`) || !strings.Contains(got, "# Context7 docs server") || !strings.Contains(got, "[mcp_servers.context7.env]") {
		t.Fatalf("user edit or content lost:\n%s", got)
	}
	if strings.Contains(got, "qbit-vault") {
		t.Fatalf("our table is still there:\n%s", got)
	}
}

func checks(r *rig) map[string]error {
	all, err := vault.ReadHosts(r.env.VaultHome)
	if err != nil {
		r.t.Fatal(err)
	}
	out := map[string]error{}
	for _, c := range hosts.Verify(r.env, r.host, all["codex"]) {
		out[c.Step] = c.Err
	}
	return out
}

func TestCheckFindsDriftAndIsReadOnly(t *testing.T) {
	r := newRig(t)
	r.apply()
	if err := checks(r)["mcp"]; err != nil {
		t.Fatalf("fresh registration drifts: %v", err)
	}
	edited := strings.Replace(r.read(r.config()), `args = ["mcp"]`, `args = ["other"]`, 1)
	r.write(r.config(), edited)
	if err := checks(r)["mcp"]; !errors.Is(err, hosts.ErrDrift) {
		t.Fatalf("want drift, got %v", err)
	}
	if r.read(r.config()) != edited {
		t.Fatal("check wrote")
	}
	r.apply()
	if err := checks(r)["mcp"]; err != nil {
		t.Fatalf("not repaired: %v", err)
	}
	r.write(r.config(), "model = \"x\"\n")
	if err := checks(r)["mcp"]; !errors.Is(err, hosts.ErrDrift) {
		t.Fatalf("removed table: want drift, got %v", err)
	}
}

func TestEnvOnlyForANonDefaultHome(t *testing.T) {
	r := newRig(t)
	r.apply()
	if strings.Contains(r.read(r.config()), "QBIT_VAULT") {
		t.Fatalf("env written for the default home:\n%s", r.read(r.config()))
	}
	r2 := newRig(t)
	r2.env.VaultHome = filepath.Join(r2.env.UserHome, "elsewhere vault")
	if _, err := vault.Init(r2.env.VaultHome, vault.NewID(), secret.New("k", bytes.Repeat([]byte{7}, 32))); err != nil {
		t.Fatal(err)
	}
	r2.apply()
	got := r2.read(r2.config())
	if !strings.Contains(got, "[mcp_servers.qbit-vault.env]\nQBIT_VAULT_HOME = ") || !strings.Contains(got, "elsewhere vault") {
		t.Fatalf("no env for a custom home:\n%s", got)
	}
	if strings.Contains(got, "QBIT_VAULT_PROMPT") {
		t.Fatalf("prompt backend forced:\n%s", got)
	}
}

func TestWindowsPathsRenderAsValidTOML(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a Windows executable path is only ever written on Windows")
	}
	r := newRig(t)
	r.host = codex.NewWithExe(`C:\Program Files\QBit "Vault"\qbit-vault.exe`)
	r.apply()
	want := `command = "C:\\Program Files\\QBit \"Vault\"\\qbit-vault.exe"`
	if !strings.Contains(r.read(r.config()), want) {
		t.Fatalf("command not escaped:\n%s", r.read(r.config()))
	}
}

func TestRelativeExecutableIsRefused(t *testing.T) {
	r := newRig(t)
	r.host = codex.NewWithExe("qbit-vault")
	if res := hosts.Apply(r.env, []hosts.Adapter{r.host}); res[0].Err() == nil {
		t.Fatal("applied with a relative executable")
	}
}

func TestDetect(t *testing.T) {
	r := newRig(t)
	none := func(string) (string, error) { return "", errors.New("not found") }
	found := func(string) (string, error) { return "/usr/bin/codex", nil }
	if codex.NewWithExe(fakeExe).WithLookPath(none).Detect(r.env) {
		t.Fatal("detected with no ~/.codex and no binary")
	}
	if !codex.NewWithExe(fakeExe).WithLookPath(found).Detect(r.env) {
		t.Fatal("binary on PATH not detected")
	}
	if err := os.MkdirAll(filepath.Join(r.env.UserHome, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !codex.NewWithExe(fakeExe).WithLookPath(none).Detect(r.env) {
		t.Fatal("~/.codex not detected")
	}
	if _, err := os.Stat(r.config()); !os.IsNotExist(err) {
		t.Fatal("detect wrote a file")
	}
}

func TestAmbiguousConfigIsRefusedAndLeftAlone(t *testing.T) {
	r := newRig(t)
	doc := "[mcp_servers]\nqbit-vault = { command = \"x\" }\n"
	r.write(r.config(), doc)
	res := hosts.Apply(r.env, []hosts.Adapter{r.host})
	if !errors.Is(res[0].Err(), filemerge.ErrAmbiguous) {
		t.Fatalf("want ErrAmbiguous, got %v", res[0].Err())
	}
	if r.read(r.config()) != doc {
		t.Fatal("file modified")
	}
}

func TestNoUserHomeIsAnError(t *testing.T) {
	r := newRig(t)
	r.env.UserHome = ""
	if res := hosts.Apply(r.env, []hosts.Adapter{r.host}); res[0].Err() == nil {
		t.Fatal("applied without a user home")
	}
}
