package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	hlcRE = regexp.MustCompile(`^\d{13}\.\d+@[0-9a-f]{32}$`)
	idRE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// rawBody decrypts vault.enc into a generic map, for format assertions.
func rawBody(t *testing.T, home string) map[string]any {
	t.Helper()
	pt, _, err := (&store{home: home, key: testKey(1)}).load()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pt)
	var m map[string]any
	if err := json.Unmarshal(pt, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// writeBody seals body as the next vault write, bypassing the codec.
func writeBody(t *testing.T, home, body string) {
	t.Helper()
	if err := (&store{home: home, key: testKey(1)}).save([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

// fakeRepo makes a repository with an origin remote and returns its root.
func fakeRepo(t *testing.T, origin string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "shop-api")
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = " + origin + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	root, ok, err := ProjectRoot(dir)
	if err != nil || !ok {
		t.Fatal("repo not detected")
	}
	return root
}

func deviceOf(t *testing.T, home string) string {
	t.Helper()
	id, err := ReadDeviceID(home)
	if err != nil || !idRE.MatchString(id) {
		t.Fatalf("device id %q: %v", id, err)
	}
	return id
}

func TestDeviceIDCreatedAndStable(t *testing.T) {
	_, home := newVault(t)
	a := deviceOf(t, home)
	if _, err := Open(home, testKey(1)); err != nil {
		t.Fatal(err)
	}
	if b := deviceOf(t, home); a != b {
		t.Fatalf("device id changed: %s -> %s", a, b)
	}
}

func TestMigratesSchema1(t *testing.T) {
	_, home := newVault(t)
	root := fakeRepo(t, "https://GitHub.com/acme/shop-api.git")
	rootJSON, _ := json.Marshal(root)
	writeBody(t, home, `{"global":{"A":{"id":"r1","value":"TESTSECRET_a","description":"","sensitive":false,"binaries":[],"hosts":[],"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}},`+
		`"projects":{`+string(rootJSON)+`:{"label":"shop-api","secrets":{"DB":{"id":"r2","value":"TESTSECRET_db","description":"","sensitive":false,"binaries":[],"hosts":[],"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}}}}`)
	v, err := Open(home, testKey(1))
	if err != nil {
		t.Fatalf("Open schema 1: %v", err)
	}
	r, l, err := v.Resolve("DB", root)
	if err != nil || !l.Project || !sameValue(r, "TESTSECRET_db") || r.ID != "r2" {
		t.Fatalf("resolve migrated project secret: %v %+v", err, l)
	}
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b")) // first save writes schema 2
	m := rawBody(t, home)
	if m["schema"] != float64(2) {
		t.Fatalf("schema=%v", m["schema"])
	}
	dev := deviceOf(t, home)
	projects := m["projects"].(map[string]any)
	if len(projects) != 1 {
		t.Fatalf("projects=%v", projects)
	}
	for id, p := range projects {
		pm := p.(map[string]any)
		if !idRE.MatchString(id) || pm["label"] != "shop-api" || pm["origin"] != "github.com/acme/shop-api" {
			t.Fatalf("project %s=%v", id, pm)
		}
		if roots := pm["roots"].(map[string]any); roots[dev] != root || len(roots) != 1 {
			t.Fatalf("roots=%v", roots)
		}
		db := pm["secrets"].(map[string]any)["DB"].(map[string]any)
		if db["id"] != "r2" || !hlcRE.MatchString(db["hlc"].(string)) {
			t.Fatalf("DB record=%v", db)
		}
	}
	for _, k := range []string{"tombstones", "conflicts", "devices"} {
		if _, ok := m[k]; !ok {
			t.Errorf("schema 2 body lacks %q", k)
		}
	}
}

func TestUnlinkedProjectsAreInvisibleButKept(t *testing.T) {
	v, home := newVault(t)
	root := fakeRepo(t, "git@github.com:acme/shop-api.git")
	writeBody(t, home, `{"schema":2,"global":{},"tombstones":[],"conflicts":[],"devices":{},"projects":{"`+strings.Repeat("ab", 16)+`":{"label":"shop-api","origin":"github.com/acme/shop-api","roots":{"`+strings.Repeat("cd", 16)+`":"/elsewhere/shop-api"},"hlc":"","secrets":{"DB":{"id":"r9","value":"TESTSECRET_other","description":"","sensitive":false,"binaries":[],"hosts":[],"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}}}}`)
	if _, _, err := v.Resolve("DB", root); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unlinked project resolved: %v", err)
	}
	all, err := v.ListAll()
	if err != nil || len(all) != 1 || !all[0].Unlinked || all[0].Layer.Label != "shop-api" || all[0].Layer.Root != "" {
		t.Fatalf("ListAll=%+v err=%v", all, err)
	}
	all[0].Record.Value.Wipe()
	mustPut(t, v, Global(), "C", rec("TESTSECRET_c"))
	p := rawBody(t, home)["projects"].(map[string]any)[strings.Repeat("ab", 16)].(map[string]any)
	if p["roots"].(map[string]any)[strings.Repeat("cd", 16)] != "/elsewhere/shop-api" {
		t.Fatalf("unlinked project lost on save: %v", p)
	}
}

func hlcOf(t *testing.T, home, name string) string {
	t.Helper()
	return rawBody(t, home)["global"].(map[string]any)[name].(map[string]any)["hlc"].(string)
}

func TestHLCStampedOnChangeOnly(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	a1 := hlcOf(t, home, "A")
	if !hlcRE.MatchString(a1) {
		t.Fatalf("hlc=%q", a1)
	}
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b"))
	if hlcOf(t, home, "A") != a1 {
		t.Fatal("an untouched record got a new hlc")
	}
	if b := hlcOf(t, home, "B"); compareHLC(b, a1) <= 0 {
		t.Fatalf("hlc not increasing: %s then %s", a1, b)
	}
	r, _, _ := v.Resolve("A", t.TempDir())
	r.Description = "edited"
	if _, err := v.EditWithGrants(Global(), "A", r, nil); err != nil {
		t.Fatal(err)
	}
	if a2 := hlcOf(t, home, "A"); compareHLC(a2, a1) <= 0 {
		t.Fatalf("edit did not advance the hlc: %s -> %s", a1, a2)
	}
}

func TestTombstonesOnRemoveAndRecreate(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	if err := v.Remove(Global(), "A"); err != nil {
		t.Fatal(err)
	}
	ts := rawBody(t, home)["tombstones"].([]any)
	if len(ts) != 1 {
		t.Fatalf("tombstones=%v", ts)
	}
	tomb := ts[0].(map[string]any)
	if tomb["key"] != "global/A" || tomb["deleted_by"] != deviceOf(t, home) || !hlcRE.MatchString(tomb["hlc"].(string)) {
		t.Fatalf("tombstone=%v", tomb)
	}
	mustPut(t, v, Global(), "A", rec("TESTSECRET_again"))
	if ts := rawBody(t, home)["tombstones"].([]any); len(ts) != 0 {
		t.Fatalf("tombstone kept for a live record: %v", ts)
	}
}

func TestOldTombstonesArePurged(t *testing.T) {
	v, home := newVault(t)
	old := time.Now().Add(-181 * 24 * time.Hour).UnixMilli()
	writeBody(t, home, `{"schema":2,"global":{},"projects":{},"conflicts":[],"devices":{},"tombstones":[{"key":"global/OLD","hlc":"`+itoa(old)+`.0@`+strings.Repeat("ef", 16)+`","deleted_by":"x"},{"key":"global/NEW","hlc":"`+itoa(time.Now().UnixMilli())+`.0@`+strings.Repeat("ef", 16)+`","deleted_by":"x"}]}`)
	mustPut(t, v, Global(), "Z", rec("TESTSECRET_z"))
	ts := rawBody(t, home)["tombstones"].([]any)
	if len(ts) != 1 || ts[0].(map[string]any)["key"] != "global/NEW" {
		t.Fatalf("tombstones=%v", ts)
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	_, home := newVault(t)
	writeBody(t, home, `{"schema":3,"global":{}}`)
	_, err := Open(home, testKey(1))
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "newer gentle-vault") {
		t.Fatalf("err=%v", err)
	}
}

func TestNormalizeOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://GitHub.com/acme/shop-api.git": "github.com/acme/shop-api",
		"git@github.com:acme/shop-api.git":     "github.com/acme/shop-api",
		"ssh://git@gitlab.com:22/a/b.git":      "gitlab.com/a/b",
		"http://user:pw@host.example/x/y/":     "host.example/x/y",
		"":                                     "",
		"/srv/git/local-repo":                  "",
	} {
		if got := normalizeOrigin(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
