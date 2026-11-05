package claude_test

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/filemerge"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/hosts/claude"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
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
	base := t.TempDir()
	home := filepath.Join(base, "user")
	vh := filepath.Join(home, ".qbit-vault")
	if _, err := vault.Init(vh, vault.NewID(), secret.New("k", bytes.Repeat([]byte{7}, 32))); err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, env: hosts.Env{VaultHome: vh, UserHome: home}, host: claude.NewWithExe(fakeExe)}
}

func (r *rig) settings() string   { return filepath.Join(r.env.UserHome, ".claude", "settings.json") }
func (r *rig) claudeJSON() string { return filepath.Join(r.env.UserHome, ".claude.json") }

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

// denyHome is the `//` absolute form Claude Code expects, written
// independently of the adapter: C:\a\b -> //c/a/b, /a/b -> //a/b.
func denyHome(p string) string {
	p = filepath.ToSlash(p)
	if len(p) > 1 && p[1] == ':' {
		p = "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return "/" + p
}

func (r *rig) golden(path, name string) {
	r.t.Helper()
	got := strings.ReplaceAll(r.read(path), denyHome(r.env.UserHome), "{HOME}")
	file := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		r.t.Fatal(err)
	}
	if got != string(want) {
		r.t.Fatalf("%s differs from %s:\n%s", path, file, got)
	}
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestName(t *testing.T) {
	if got := claude.New().Name(); got != "claude-code" {
		t.Fatalf("name %q", got)
	}
	var names []string
	for _, s := range claude.NewWithExe(fakeExe).Steps(hosts.Env{}) {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "mcp,hooks,deny" {
		t.Fatalf("steps %v", names)
	}
}

func TestApplyOnAbsentFiles(t *testing.T) {
	r := newRig(t)
	res := r.apply()
	if !res.Changed() || len(res.Steps) != 3 {
		t.Fatalf("result %+v", res)
	}
	r.golden(r.claudeJSON(), "absent.claude.json.golden")
	r.golden(r.settings(), "absent.settings.json.golden")
}

func TestApplyKeepsEverythingTheUserHas(t *testing.T) {
	r := newRig(t)
	r.write(r.claudeJSON(), fixture(t, "existing.claude.json"))
	r.write(r.settings(), fixture(t, "existing.settings.json"))
	r.apply()
	r.golden(r.claudeJSON(), "existing.claude.json.golden")
	r.golden(r.settings(), "existing.settings.json.golden")
	got := r.read(r.settings())
	for _, keep := range []string{"gentle-ai hook guard", "prettier --write", "notify-send done", `"Read(~/.ssh/**)"`, `"Read(**/.env)"`, `"Bash(git status)"`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("lost %q:\n%s", keep, got)
		}
	}
	// The user's deny entries keep their order, ours come last.
	if i, j := strings.Index(got, "Read(~/.ssh/**)"), strings.Index(got, "Read(**/.env)"); i > j {
		t.Fatal("deny entries reordered")
	}
}

func TestSecondApplyChangesNothing(t *testing.T) {
	r := newRig(t)
	r.write(r.settings(), fixture(t, "existing.settings.json"))
	r.apply()
	a, b := r.read(r.settings()), r.read(r.claudeJSON())
	state, nb := r.read(filepath.Join(r.env.VaultHome, "state.json")), r.backups()
	res := r.apply()
	if res.Changed() {
		t.Fatalf("second apply wrote: %+v", res)
	}
	if r.read(r.settings()) != a || r.read(r.claudeJSON()) != b || r.read(filepath.Join(r.env.VaultHome, "state.json")) != state {
		t.Fatal("second apply changed bytes")
	}
	if r.backups() != nb {
		t.Fatal("second apply took a snapshot")
	}
}

func TestRevertRestoresByteForByte(t *testing.T) {
	for _, existing := range []bool{true, false} {
		r := newRig(t)
		var s, c string
		if existing {
			s, c = fixture(t, "existing.settings.json"), fixture(t, "existing.claude.json")
			r.write(r.settings(), s)
			r.write(r.claudeJSON(), c)
		}
		r.apply()
		if err := hosts.Revert(r.env, r.host); err != nil {
			t.Fatal(err)
		}
		for path, want := range map[string]string{r.settings(): s, r.claudeJSON(): c} {
			got, err := os.ReadFile(path)
			switch {
			case existing && (err != nil || string(got) != want):
				t.Fatalf("existing=%v %s not restored: %v\n%s", existing, path, err, got)
			case !existing && err == nil:
				t.Fatalf("a file we created is still there: %s", path)
			}
		}
	}
}

func TestRevertKeepsAUserEditMadeAfterUs(t *testing.T) {
	r := newRig(t)
	r.write(r.settings(), fixture(t, "existing.settings.json"))
	r.apply()
	edited := strings.Replace(r.read(r.settings()), `"model": "opus"`, `"model": "sonnet"`, 1)
	r.write(r.settings(), edited)
	if err := hosts.Revert(r.env, r.host); err != nil {
		t.Fatal(err)
	}
	got := r.read(r.settings())
	if !strings.Contains(got, `"model": "sonnet"`) || !strings.Contains(got, "gentle-ai hook guard") || !strings.Contains(got, "Read(~/.ssh/**)") {
		t.Fatalf("user edit or content lost:\n%s", got)
	}
	if strings.Contains(got, "qbit-vault") {
		t.Fatalf("our entries are still there:\n%s", got)
	}
}

func checks(r *rig) map[string]error {
	all, err := vault.ReadHosts(r.env.VaultHome)
	if err != nil {
		r.t.Fatal(err)
	}
	out := map[string]error{}
	for _, c := range hosts.Verify(r.env, r.host, all["claude-code"]) {
		out[c.Step] = c.Err
	}
	return out
}

func TestCheckFindsDriftWhenTheUserRemovesOurHook(t *testing.T) {
	r := newRig(t)
	r.apply()
	for step, err := range checks(r) {
		if err != nil {
			t.Fatalf("fresh registration drifts at %s: %v", step, err)
		}
	}
	doc := r.read(r.settings())
	start := strings.Index(doc, `"PreToolUse"`)
	end := strings.Index(doc, `"PostToolUse"`)
	r.write(r.settings(), doc[:start]+doc[end:])
	got := checks(r)
	if !errors.Is(got["hooks"], hosts.ErrDrift) || got["deny"] != nil || got["mcp"] != nil {
		t.Fatalf("checks: %v", got)
	}
	// Check is read-only.
	if r.read(r.settings()) != doc[:start]+doc[end:] {
		t.Fatal("check wrote")
	}
	// Apply repairs it.
	r.apply()
	for step, err := range checks(r) {
		if err != nil {
			t.Fatalf("not repaired at %s: %v", step, err)
		}
	}
}

func TestCheckFindsDriftWhenDenyOrMCPAreRemoved(t *testing.T) {
	r := newRig(t)
	r.apply()
	r.write(r.claudeJSON(), "{}\n")
	doc := strings.ReplaceAll(r.read(r.settings()), "Edit(", "Other(")
	r.write(r.settings(), doc)
	got := checks(r)
	if !errors.Is(got["mcp"], hosts.ErrDrift) || !errors.Is(got["deny"], hosts.ErrDrift) {
		t.Fatalf("checks: %v", got)
	}
}

func TestMCPEntryEnvOnlyForANonDefaultHome(t *testing.T) {
	r := newRig(t)
	r.apply()
	if strings.Contains(r.read(r.claudeJSON()), "QBIT_VAULT_HOME") {
		t.Fatal("env written for the default home")
	}
	r2 := newRig(t)
	r2.env.VaultHome = filepath.Join(r2.env.UserHome, "elsewhere vault")
	if _, err := vault.Init(r2.env.VaultHome, vault.NewID(), secret.New("k", bytes.Repeat([]byte{7}, 32))); err != nil {
		t.Fatal(err)
	}
	r2.apply()
	got := r2.read(r2.claudeJSON())
	if !strings.Contains(got, `"QBIT_VAULT_HOME"`) || !strings.Contains(got, "elsewhere vault") {
		t.Fatalf("no env for a custom home:\n%s", got)
	}
	if !strings.Contains(r2.read(r2.settings()), denyHome(r2.env.VaultHome)+"/**") {
		t.Fatal("deny does not use the resolved vault home")
	}
}

func TestWindowsPathsAreEscaped(t *testing.T) {
	r := newRig(t)
	r.host = claude.NewWithExe(`C:\Program Files\QBit Vault\qbit-vault.exe`)
	r.apply()
	want := `"command": "C:\\Program Files\\QBit Vault\\qbit-vault.exe"`
	if !strings.Contains(r.read(r.claudeJSON()), want) || !strings.Contains(r.read(r.settings()), want) {
		t.Fatalf("command not escaped:\n%s", r.read(r.claudeJSON()))
	}
}

func TestDetect(t *testing.T) {
	r := newRig(t)
	none := func(string) (string, error) { return "", errors.New("not found") }
	found := func(string) (string, error) { return "/usr/bin/claude", nil }
	if claude.NewWithExe(fakeExe).WithLookPath(none).Detect(r.env) {
		t.Fatal("detected with no ~/.claude and no binary")
	}
	if !claude.NewWithExe(fakeExe).WithLookPath(found).Detect(r.env) {
		t.Fatal("binary on PATH not detected")
	}
	if err := os.MkdirAll(filepath.Join(r.env.UserHome, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !claude.NewWithExe(fakeExe).WithLookPath(none).Detect(r.env) {
		t.Fatal("~/.claude not detected")
	}
	if _, err := os.Stat(r.settings()); !os.IsNotExist(err) {
		t.Fatal("detect wrote a file")
	}
}

func TestInvalidJSONIsRefusedAndLeftAlone(t *testing.T) {
	r := newRig(t)
	r.write(r.settings(), "{ // comment\n}")
	res := hosts.Apply(r.env, []hosts.Adapter{r.host})
	if !errors.Is(res[0].Err(), filemerge.ErrInvalidJSON) {
		t.Fatalf("want ErrInvalidJSON, got %v", res[0].Err())
	}
	if r.read(r.settings()) != "{ // comment\n}" {
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
