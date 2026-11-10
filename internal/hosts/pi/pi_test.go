package pi_test

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/hosts"
	"github.com/qbitdevz/qbit-vault/internal/hosts/pi"
	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const fakeExe = "/opt/qbit/bin/qbit-vault"

func noEnv(string) string { return "" }

func notFound(string) (string, error) { return "", errors.New("not found") }

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
	return &rig{t: t, env: hosts.Env{VaultHome: vh, UserHome: home}, host: pi.NewWithExe(fakeExe).WithGetenv(noEnv).WithLookPath(notFound)}
}

func (r *rig) config() string { return filepath.Join(r.env.UserHome, ".pi", "agent", "mcp.json") }

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
	if got := pi.New().Name(); got != "pi" {
		t.Fatalf("name %q", got)
	}
	steps := pi.NewWithExe(fakeExe).Steps(hosts.Env{})
	if len(steps) != 2 || steps[0].Name != "mcp" || steps[1].Name != "skill" {
		t.Fatalf("steps %+v", steps)
	}
	if pi.ExtensionInstallCommand != "pi install npm:qbit-vault-pi" {
		t.Fatalf("install command %q", pi.ExtensionInstallCommand)
	}
}

func TestApplyOnAbsentFile(t *testing.T) {
	r := newRig(t)
	if res := r.apply(); !res.Changed() || len(res.Steps) != 2 {
		t.Fatalf("result %+v", res)
	}
	r.golden("absent.mcp.json.golden")
}

func TestApplyKeepsTheUsersOtherServersAndFormatting(t *testing.T) {
	r := newRig(t)
	orig := lf(t, "existing.mcp.json")
	r.write(r.config(), orig)
	r.apply()
	r.golden("existing.mcp.json.golden")
	got := r.read(r.config())
	for _, keep := range []string{`"args": ["-y", "@modelcontextprotocol/server-filesystem", "."]`, `"headers": {"Authorization": "Bearer ${DOCS_TOKEN}"}`, `"other": [1,   2]`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("user formatting lost (%s):\n%s", keep, got)
		}
	}
	if r.backups() == 0 {
		t.Fatal("no snapshot of the existing file")
	}
}

func TestSecondApplyChangesNothing(t *testing.T) {
	r := newRig(t)
	r.write(r.config(), lf(t, "existing.mcp.json"))
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
			want = lf(t, "existing.mcp.json")
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
	r.write(r.config(), lf(t, "existing.mcp.json"))
	r.apply()
	r.write(r.config(), strings.Replace(r.read(r.config()), `"enabled": false`, `"enabled": true`, 1))
	if err := hosts.Revert(r.env, r.host); err != nil {
		t.Fatal(err)
	}
	got := r.read(r.config())
	if !strings.Contains(got, `"enabled": true`) || !strings.Contains(got, `"filesystem"`) {
		t.Fatalf("user edit or content lost:\n%s", got)
	}
	if strings.Contains(got, "qbit-vault") {
		t.Fatalf("our entry is still there:\n%s", got)
	}
}

func checks(r *rig) map[string]error {
	all, err := vault.ReadHosts(r.env.VaultHome)
	if err != nil {
		r.t.Fatal(err)
	}
	out := map[string]error{}
	for _, c := range hosts.Verify(r.env, r.host, all["pi"]) {
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
	edited := strings.Replace(r.read(r.config()), `"mcp"`, `"other"`, 1)
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
	r.write(r.config(), "{\"mcpServers\": {}}\n")
	if err := checks(r)["mcp"]; !errors.Is(err, hosts.ErrDrift) {
		t.Fatalf("removed entry: want drift, got %v", err)
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
	if !strings.Contains(got, `"QBIT_VAULT_HOME"`) || !strings.Contains(got, "elsewhere vault") {
		t.Fatalf("no env for a custom home:\n%s", got)
	}
	if strings.Contains(got, "QBIT_VAULT_PROMPT") {
		t.Fatalf("prompt backend forced:\n%s", got)
	}
}

// Pi expands ${VAR} and a leading ! in env values, so a vault home that looks
// like either would not reach the server as written.
func TestVaultHomeThatPiWouldExpandIsRefused(t *testing.T) {
	for _, vh := range []string{"/data/${HOME}/vault", "!echo"} {
		r := newRig(t)
		r.env.VaultHome = vh
		if res := hosts.Apply(r.env, []hosts.Adapter{r.host}); res[0].Err() == nil {
			t.Fatalf("applied with vault home %q", vh)
		}
		if _, err := os.Stat(r.config()); err == nil {
			t.Fatalf("file written for vault home %q", vh)
		}
	}
}

func TestAgentDirFollowsPiCodingAgentDir(t *testing.T) {
	r := newRig(t)
	override := filepath.Join(t.TempDir(), "agent home")
	r.host = pi.NewWithExe(fakeExe).WithLookPath(notFound).WithGetenv(func(k string) string {
		if k == "PI_CODING_AGENT_DIR" {
			return override
		}
		return ""
	})
	r.apply()
	if got := r.read(filepath.Join(override, "mcp.json")); !strings.Contains(got, `"qbit-vault"`) {
		t.Fatalf("not written under the override:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(r.env.UserHome, ".pi")); !os.IsNotExist(err) {
		t.Fatal("the default directory was touched")
	}
	if err := hosts.Revert(r.env, r.host); err != nil {
		t.Fatal(err)
	}
}

func TestTildeAndRelativeOverrides(t *testing.T) {
	r := newRig(t)
	r.host = pi.NewWithExe(fakeExe).WithLookPath(notFound).WithGetenv(func(string) string { return "~/custom-agent" })
	r.apply()
	if got := r.read(filepath.Join(r.env.UserHome, "custom-agent", "mcp.json")); !strings.Contains(got, `"qbit-vault"`) {
		t.Fatalf("~ not expanded against the user home:\n%s", got)
	}
	r2 := newRig(t)
	r2.host = pi.NewWithExe(fakeExe).WithLookPath(notFound).WithGetenv(func(string) string { return "relative/agent" })
	if res := hosts.Apply(r2.env, []hosts.Adapter{r2.host}); res[0].Err() == nil {
		t.Fatal("applied with a relative PI_CODING_AGENT_DIR")
	}
}

func TestRelativeExecutableIsRefused(t *testing.T) {
	r := newRig(t)
	r.host = pi.NewWithExe("qbit-vault").WithGetenv(noEnv)
	if res := hosts.Apply(r.env, []hosts.Adapter{r.host}); res[0].Err() == nil {
		t.Fatal("applied with a relative executable")
	}
}

func TestDetect(t *testing.T) {
	r := newRig(t)
	only := func(name string) func(string) (string, error) {
		return func(n string) (string, error) {
			if n == name {
				return "/usr/bin/" + n, nil
			}
			return "", errors.New("not found")
		}
	}
	mk := func() *pi.Adapter { return pi.NewWithExe(fakeExe).WithGetenv(noEnv) }
	if mk().WithLookPath(notFound).Detect(r.env) {
		t.Fatal("detected with no ~/.pi and no binary")
	}
	for _, bin := range []string{"pi", "gentle-shell"} {
		if !mk().WithLookPath(only(bin)).Detect(r.env) {
			t.Fatalf("%s on PATH not detected", bin)
		}
	}
	if err := os.MkdirAll(filepath.Join(r.env.UserHome, ".pi"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !mk().WithLookPath(notFound).Detect(r.env) {
		t.Fatal("~/.pi not detected")
	}
	if _, err := os.Stat(r.config()); !os.IsNotExist(err) {
		t.Fatal("detect wrote a file")
	}
	// An agent directory named by the environment counts too.
	dir := t.TempDir()
	byEnv := pi.NewWithExe(fakeExe).WithLookPath(notFound).WithGetenv(func(string) string { return dir })
	if !byEnv.Detect(newRig(t).env) {
		t.Fatal("PI_CODING_AGENT_DIR directory not detected")
	}
}

func TestNoUserHomeIsAnError(t *testing.T) {
	r := newRig(t)
	r.env.UserHome = ""
	if res := hosts.Apply(r.env, []hosts.Adapter{r.host}); res[0].Err() == nil {
		t.Fatal("applied without a user home")
	}
}
