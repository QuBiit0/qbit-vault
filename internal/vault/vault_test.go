package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

func rec(value string) Record {
	return Record{Value: secret.New("n", []byte(value))}
}

func sameValue(r Record, want string) bool {
	got := r.Value.Reveal()
	defer clear(got)
	return string(got) == want
}

func newVault(t *testing.T) (*Vault, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	v, err := Init(home, testID, testKey(1))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return v, home
}

func mustPut(t *testing.T, v *Vault, l Layer, name string, r Record) {
	t.Helper()
	if err := v.Put(l, name, r); err != nil {
		t.Fatalf("Put(%s): %v", name, err)
	}
}

func layerOf(t *testing.T, cwd string) Layer {
	t.Helper()
	l, err := ProjectLayer(cwd)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestInitAndOpen(t *testing.T) {
	v, home := newVault(t)
	if all, err := v.ListAll(); err != nil || len(all) != 0 {
		t.Fatalf("new vault not empty: %v %v", all, err)
	}
	for _, f := range []string{"vault.enc", "state.json"} {
		if _, err := os.Stat(filepath.Join(home, f)); err != nil {
			t.Fatalf("%s missing: %v", f, err)
		}
	}
	if _, err := Init(home, testID, testKey(1)); !errors.Is(err, ErrExists) {
		t.Fatalf("second Init: %v, want ErrExists", err)
	}
	if _, err := Open(home, testKey(1)); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "none"), testKey(1)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open missing: %v", err)
	}
}

func TestInitDoesNotReadEnvironment(t *testing.T) {
	t.Setenv("TESTSECRET_ENV_VALUE", fixtureValue)
	_, home := newVault(t)
	for _, f := range []string{"vault.enc", "state.json"} {
		b, _ := os.ReadFile(filepath.Join(home, f))
		if bytes.Contains(b, []byte(fixtureValue)) {
			t.Fatal("environment value reached disk")
		}
	}
}

func TestRoundTripBothLayers(t *testing.T) {
	v, home := newVault(t)
	repo := mkRepo(t, t.TempDir(), "shop", false)
	pl := layerOf(t, repo)

	global := Record{
		Value: secret.New("g", []byte("TESTSECRET_global")), Description: "gh pat", Sensitive: true,
		Binaries: []string{"gh", "git"}, Hosts: []string{"api.github.com"},
	}
	mustPut(t, v, Global(), "GITHUB_TOKEN", global)
	mustPut(t, v, pl, "DATABASE_URL", rec("TESTSECRET_project"))

	reopened, err := Open(home, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	g, layer, err := reopened.Resolve("GITHUB_TOKEN", t.TempDir())
	if err != nil || layer.Project || !sameValue(g, "TESTSECRET_global") {
		t.Fatalf("global resolve: layer=%+v err=%v", layer, err)
	}
	if g.Description != "gh pat" || !g.Sensitive || strings.Join(g.Binaries, ",") != "gh,git" ||
		strings.Join(g.Hosts, ",") != "api.github.com" || g.CreatedAt == "" || g.UpdatedAt == "" {
		t.Fatalf("metadata lost: %+v", g)
	}
	p, layer, err := reopened.Resolve("DATABASE_URL", repo)
	if err != nil || !layer.Project || layer.Root != pl.Root || !sameValue(p, "TESTSECRET_project") {
		t.Fatalf("project resolve: layer=%+v err=%v", layer, err)
	}
}

func TestResolveLayering(t *testing.T) {
	v, _ := newVault(t)
	tmp := t.TempDir()
	repoA := mkRepo(t, tmp, "a", false)
	repoB := mkRepo(t, tmp, "b", false)
	worktree := mkRepo(t, tmp, "a-wt", true)
	plain := mkDir(t, t.TempDir(), "plain")
	skipIfInsideRepo(t, plain)

	mustPut(t, v, Global(), "DATABASE_URL", rec("TESTSECRET_global"))
	mustPut(t, v, layerOf(t, repoA), "DATABASE_URL", rec("TESTSECRET_a"))
	mustPut(t, v, layerOf(t, repoA), "ONLY_IN_A", rec("TESTSECRET_only_a"))
	mustPut(t, v, layerOf(t, worktree), "WT_SECRET", rec("TESTSECRET_wt"))

	tests := []struct {
		name      string
		secret    string
		cwd       string
		want      string
		wantProj  bool
		wantError error
	}{
		{"project overrides global inside repo", "DATABASE_URL", repoA, "TESTSECRET_a", true, nil},
		{"override applies in subdirectory", "DATABASE_URL", mkDir(t, repoA, "x", "y"), "TESTSECRET_a", true, nil},
		{"sibling repo sees global", "DATABASE_URL", repoB, "TESTSECRET_global", false, nil},
		{"outside any repo sees global", "DATABASE_URL", plain, "TESTSECRET_global", false, nil},
		{"project-only secret inside repo", "ONLY_IN_A", repoA, "TESTSECRET_only_a", true, nil},
		{"project-only secret hidden from sibling", "ONLY_IN_A", repoB, "", false, ErrNotFound},
		{"project-only secret hidden outside", "ONLY_IN_A", plain, "", false, ErrNotFound},
		{"worktree is its own project", "WT_SECRET", worktree, "TESTSECRET_wt", true, nil},
		{"main checkout does not see worktree secret", "WT_SECRET", repoA, "", false, ErrNotFound},
		{"unknown name", "NOPE", repoA, "", false, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, l, err := v.Resolve(tt.secret, tt.cwd)
			if !errors.Is(err, tt.wantError) {
				t.Fatalf("err = %v, want %v", err, tt.wantError)
			}
			if err != nil {
				if !strings.Contains(err.Error(), tt.secret) || strings.Contains(err.Error(), tt.cwd) {
					t.Fatalf("error must carry the name only: %v", err)
				}
				return
			}
			if !sameValue(r, tt.want) || l.Project != tt.wantProj {
				t.Fatalf("layer=%+v valueOK=%v", l, sameValue(r, tt.want))
			}
		})
	}
}

func TestPutKeepsCreatedAtOnReplace(t *testing.T) {
	v, _ := newVault(t)
	times := []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	i := 0
	prev := now
	now = func() time.Time { t := times[i]; i = min(i+1, len(times)-1); return t }
	t.Cleanup(func() { now = prev })

	mustPut(t, v, Global(), "TOKEN", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "TOKEN", rec("TESTSECRET_two"))
	r, _, err := v.Resolve("TOKEN", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if r.CreatedAt != "2026-01-01T00:00:00Z" || r.UpdatedAt != "2026-02-01T00:00:00Z" || !sameValue(r, "TESTSECRET_two") {
		t.Fatalf("created=%q updated=%q", r.CreatedAt, r.UpdatedAt)
	}
}

func TestMove(t *testing.T) {
	type setup struct{ globalVal, projVal string }
	tests := []struct {
		name      string
		setup     setup
		fromProj  bool // move project -> global when true
		overwrite bool
		wantErr   error
		wantLive  string // value that must be at the destination afterwards
	}{
		{"global to project", setup{"TESTSECRET_g", ""}, false, false, nil, "TESTSECRET_g"},
		{"project to global", setup{"", "TESTSECRET_p"}, true, false, nil, "TESTSECRET_p"},
		{"refuses to overwrite", setup{"TESTSECRET_g", "TESTSECRET_p"}, false, false, ErrExists, "TESTSECRET_p"},
		{"overwrites when asked", setup{"TESTSECRET_g", "TESTSECRET_p"}, false, true, nil, "TESTSECRET_g"},
		{"missing source", setup{"", ""}, false, false, ErrNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVault(t)
			repo := mkRepo(t, t.TempDir(), "r", false)
			pl := layerOf(t, repo)
			meta := Record{Description: "d", Sensitive: true, Binaries: []string{"gh"}, Hosts: []string{"h.example"}}
			if tt.setup.globalVal != "" {
				r := meta
				r.Value = secret.New("g", []byte(tt.setup.globalVal))
				mustPut(t, v, Global(), "TOKEN", r)
			}
			if tt.setup.projVal != "" {
				r := meta
				r.Value = secret.New("p", []byte(tt.setup.projVal))
				mustPut(t, v, pl, "TOKEN", r)
			}
			from, to := Global(), pl
			if tt.fromProj {
				from, to = pl, Global()
			}
			err := v.Move("TOKEN", from, to, tt.overwrite)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				if !strings.Contains(err.Error(), "TOKEN") {
					t.Fatalf("error must name the secret: %v", err)
				}
				if tt.wantLive != "" { // refusal must leave both layers untouched
					all, _ := v.ListAll()
					if len(all) != 2 {
						t.Fatalf("refused move changed layout: %d entries", len(all))
					}
				}
				return
			}
			all, _ := v.ListAll()
			if len(all) != 1 || !all[0].Layer.same(to) || !sameValue(all[0].Record, tt.wantLive) {
				t.Fatalf("after move: %d entries", len(all))
			}
			got := all[0].Record
			if got.Description != "d" || !got.Sensitive || len(got.Binaries) != 1 || len(got.Hosts) != 1 || got.CreatedAt == "" {
				t.Fatalf("metadata lost: %+v", got)
			}
		})
	}
}

func TestMoveKeepsTimestamps(t *testing.T) {
	v, _ := newVault(t)
	repo := mkRepo(t, t.TempDir(), "r", false)
	mustPut(t, v, Global(), "TOKEN", rec("TESTSECRET_x"))
	before, _, _ := v.Resolve("TOKEN", t.TempDir())
	if err := v.Move("TOKEN", Global(), layerOf(t, repo), false); err != nil {
		t.Fatal(err)
	}
	after, _, err := v.Resolve("TOKEN", repo)
	if err != nil || after.CreatedAt != before.CreatedAt || after.UpdatedAt != before.UpdatedAt {
		t.Fatalf("timestamps changed: err=%v", err)
	}
}

func TestRemove(t *testing.T) {
	v, _ := newVault(t)
	repo := mkRepo(t, t.TempDir(), "r", false)
	pl := layerOf(t, repo)
	mustPut(t, v, Global(), "TOKEN", rec("TESTSECRET_g"))
	mustPut(t, v, pl, "TOKEN", rec("TESTSECRET_p"))

	if err := v.Remove(pl, "TOKEN"); err != nil {
		t.Fatal(err)
	}
	r, l, err := v.Resolve("TOKEN", repo)
	if err != nil || l.Project || !sameValue(r, "TESTSECRET_g") {
		t.Fatalf("global should be visible again: %v", err)
	}
	if err := v.Remove(pl, "TOKEN"); !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "TOKEN") {
		t.Fatalf("second remove: %v", err)
	}
	if err := v.Remove(Global(), "TOKEN"); err != nil {
		t.Fatal(err)
	}
	if all, _ := v.ListAll(); len(all) != 0 {
		t.Fatalf("%d entries left", len(all))
	}
}

func TestEmptyProjectIsDropped(t *testing.T) {
	v, home := newVault(t)
	repo := mkRepo(t, t.TempDir(), "TESTSECRET_PROJ", false)
	pl := layerOf(t, repo)
	mustPut(t, v, pl, "TOKEN", rec("TESTSECRET_p"))
	if err := v.Remove(pl, "TOKEN"); err != nil {
		t.Fatal(err)
	}
	var b body
	pt, _, err := v.st.load()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pt)
	if err := json.Unmarshal(pt, &b); err != nil || len(b.Projects) != 0 {
		t.Fatalf("empty project kept: err=%v n=%d", err, len(b.Projects))
	}
	_ = home
}

func TestInvalidName(t *testing.T) {
	v, _ := newVault(t)
	repo := mkRepo(t, t.TempDir(), "r", false)
	bad := []string{"", "lower", "Mixed", "1ABC", "_ABC", "A-B", "A B", "A.B", "ÀBC", strings.Repeat("A", 65), "TESTSECRET_x\n"}
	for i, name := range bad {
		t.Run(fmt.Sprintf("bad/%d", i), func(t *testing.T) {
			errs := []error{
				v.Put(Global(), name, rec("TESTSECRET_v")),
				v.Remove(Global(), name),
				v.Move(name, Global(), layerOf(t, repo), false),
			}
			_, _, rerr := v.Resolve(name, repo)
			errs = append(errs, rerr)
			for i, err := range errs {
				if !errors.Is(err, ErrInvalidName) {
					t.Fatalf("call %d: err = %v", i, err)
				}
				if name != "" && strings.Contains(err.Error(), strings.TrimSpace(name)) {
					t.Fatalf("call %d: error echoes the rejected name", i)
				}
			}
		})
	}
	for _, name := range []string{"A", "GITHUB_TOKEN", "A1_B2", strings.Repeat("A", 64)} {
		if err := v.Put(Global(), name, rec("TESTSECRET_v")); err != nil {
			t.Fatalf("valid name %q rejected: %v", name, err)
		}
	}
}

func TestNoProject(t *testing.T) {
	v, _ := newVault(t)
	if err := v.Put(Layer{Project: true}, "TOKEN", rec("TESTSECRET_v")); !errors.Is(err, ErrNoProject) {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Move("TOKEN", Global(), Layer{Project: true}, false); !errors.Is(err, ErrNoProject) {
		t.Fatalf("Move: %v", err)
	}
}

func TestList(t *testing.T) {
	v, _ := newVault(t)
	tmp := t.TempDir()
	repoA := mkRepo(t, tmp, "a", false)
	repoB := mkRepo(t, tmp, "b", false)
	plain := mkDir(t, t.TempDir(), "plain")
	skipIfInsideRepo(t, plain)
	mustPut(t, v, Global(), "SHARED", rec("TESTSECRET_g1"))
	mustPut(t, v, Global(), "GLOBAL_ONLY", rec("TESTSECRET_g2"))
	mustPut(t, v, layerOf(t, repoA), "SHARED", rec("TESTSECRET_p1"))
	mustPut(t, v, layerOf(t, repoA), "PROJ_ONLY", rec("TESTSECRET_p2"))

	type row struct {
		name     string
		project  bool
		override bool
	}
	flat := func(es []Entry) []row {
		var out []row
		for _, e := range es {
			out = append(out, row{e.Name, e.Layer.Project, e.OverridesGlobal})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
		return out
	}
	tests := []struct {
		name string
		cwd  string
		want []row
	}{
		{"inside repo A", repoA, []row{{"GLOBAL_ONLY", false, false}, {"PROJ_ONLY", true, false}, {"SHARED", true, true}}},
		{"sibling repo B", repoB, []row{{"GLOBAL_ONLY", false, false}, {"SHARED", false, false}}},
		{"outside", plain, []row{{"GLOBAL_ONLY", false, false}, {"SHARED", false, false}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es, err := v.List(tt.cwd)
			if err != nil {
				t.Fatal(err)
			}
			got := flat(es)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
	all, err := v.ListAll()
	if err != nil || len(all) != 4 {
		t.Fatalf("ListAll: n=%d err=%v", len(all), err)
	}
	for _, e := range all {
		if e.Layer.Project && e.Layer.Label != "a" {
			t.Fatalf("label = %q", e.Layer.Label)
		}
	}
}

func TestOpenVaultRefusals(t *testing.T) {
	t.Run("wrong key", func(t *testing.T) {
		_, home := newVault(t)
		if _, err := Open(home, testKey(2)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tampered ct", func(t *testing.T) {
		_, home := newVault(t)
		tamperVault(t, home, func(m map[string]any) {
			raw, _ := base64.StdEncoding.DecodeString(m["ct"].(string))
			raw[len(raw)-1] ^= 1
			m["ct"] = base64.StdEncoding.EncodeToString(raw)
		})
		if _, err := Open(home, testKey(1)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tampered aad writes", func(t *testing.T) {
		_, home := newVault(t)
		tamperVault(t, home, func(m map[string]any) { m["aad"].(map[string]any)["writes"] = 99 })
		if _, err := Open(home, testKey(1)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("rollback to an older copy", func(t *testing.T) {
		v, home := newVault(t)
		path := filepath.Join(home, "vault.enc")
		old, _ := os.ReadFile(path)
		mustPut(t, v, Global(), "TOKEN", rec("TESTSECRET_v"))
		if err := os.WriteFile(path, old, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(home, testKey(1)); !errors.Is(err, ErrRollback) || !errors.Is(err, ErrCorrupt) {
			t.Fatalf("err = %v", err)
		}
	})
}

func tamperVault(t *testing.T, home string, fn func(map[string]any)) {
	t.Helper()
	path := filepath.Join(home, "vault.enc")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, mutate(t, b, fn), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCrashBetweenTempAndRename(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "TOKEN", rec("TESTSECRET_old"))

	boom := errors.New("simulated crash")
	prev := beforeRename
	beforeRename = func(string, string) error { return boom }
	err := v.Put(Global(), "TOKEN", rec("TESTSECRET_new"))
	beforeRename = prev
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	reopened, err := Open(home, testKey(1))
	if err != nil {
		t.Fatalf("vault unreadable after crash: %v", err)
	}
	r, _, err := reopened.Resolve("TOKEN", t.TempDir())
	if err != nil || !sameValue(r, "TESTSECRET_old") {
		t.Fatalf("old value lost: %v", err)
	}
}

func TestCrashBetweenVaultAndState(t *testing.T) {
	v, home := newVault(t)
	prev := beforeRename
	beforeRename = func(_, target string) error {
		if filepath.Base(target) == "state.json" {
			return errors.New("simulated crash")
		}
		return nil
	}
	err := v.Put(Global(), "TOKEN", rec("TESTSECRET_new"))
	beforeRename = prev
	if err == nil {
		t.Fatal("expected failure")
	}
	reopened, err := Open(home, testKey(1))
	if err != nil {
		t.Fatalf("vault ahead of state must be accepted: %v", err)
	}
	if r, _, err := reopened.Resolve("TOKEN", t.TempDir()); err != nil || !sameValue(r, "TESTSECRET_new") {
		t.Fatalf("write lost: %v", err)
	}
}

func TestBackupsCreatedAndPruned(t *testing.T) {
	v, home := newVault(t)
	v.st.keep = 3
	for i := range 6 {
		mustPut(t, v, Global(), "TOKEN", rec("TESTSECRET_"+string(rune('a'+i))))
	}
	dirs := backupDirs(t, home)
	if len(dirs) != 3 {
		t.Fatalf("backup dirs = %d, want 3", len(dirs))
	}
	for _, d := range dirs {
		if !backupDirRE.MatchString(d) {
			t.Fatalf("bad backup dir name %q", d)
		}
	}
}

// b64Variants returns substrings of s's base64 encoding that appear in any
// larger base64 stream regardless of byte alignment.
func b64Variants(s string) []string {
	var out []string
	for pad := 0; pad < 3; pad++ {
		enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", pad) + s))
		drop := []int{0, 2, 3}[pad]
		if len(enc) > drop+4 {
			out = append(out, strings.TrimRight(enc[drop:len(enc)-3], "="))
		}
	}
	return out
}

func TestLeakNothingReadableOnDisk(t *testing.T) {
	const marker = "TESTSECRET_PROJ_MARKER"
	v, home := newVault(t)
	repo := mkRepo(t, filepath.Join(t.TempDir(), marker), "shop", false)
	pl := layerOf(t, repo)

	values := []string{"TESTSECRET_global_value_aaa", "TESTSECRET_project_value_bbb", "TESTSECRET_replaced_value_ccc"}
	names := []string{"TESTSECRET_GLOBAL_NAME", "TESTSECRET_PROJECT_NAME"}
	mustPut(t, v, Global(), names[0], rec(values[0]))
	mustPut(t, v, pl, names[1], rec(values[1]))
	mustPut(t, v, pl, names[1], Record{Value: secret.New("x", []byte(values[2])), Description: "TESTSECRET_desc"})
	mustPut(t, v, Global(), "OTHER", rec("TESTSECRET_other"))
	if err := v.Move("OTHER", Global(), pl, false); err != nil {
		t.Fatal(err)
	}

	needles := append(append(append([]string{}, values...), names...), pl.Root, marker, "TESTSECRET_desc", "TESTSECRET_other")
	for _, n := range append([]string{}, needles...) {
		needles = append(needles, b64Variants(n)...)
	}

	files := 0
	err := filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for i, n := range needles {
			if n != "" && bytes.Contains(b, []byte(n)) {
				t.Errorf("%s leaks needle #%d (len %d)", strings.TrimPrefix(path, home), i, len(n))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 4 || len(backupDirs(t, home)) == 0 {
		t.Fatalf("leak test did not cover backups: files=%d", files)
	}
}
