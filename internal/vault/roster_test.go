package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/merge"
)

func TestRosterRoundTrip(t *testing.T) {
	v, _ := newVault(t)
	got, err := v.Roster()
	if err != nil || len(got) != 0 {
		t.Fatalf("fresh vault: %v %v", got, err)
	}
	at := "2026-11-04T00:00:00Z"
	err = v.EditRoster(func(r map[string]merge.Device) {
		r["d1"] = merge.Device{Label: "laptop", SignPub: "c2ln", BoxPub: "Ym94", AddedAt: at, AddedBy: "register", LastSync: &merge.LastSync{Version: 1, At: at}}
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err = v.Roster()
	if err != nil || got["d1"].Label != "laptop" || got["d1"].AddedBy != "register" || got["d1"].LastSync.Version != 1 || got["d1"].RevokedAt != nil {
		t.Fatalf("roster: %+v %v", got, err)
	}
	// It lives in the schema 2 body that syncs.
	body, err := v.Body()
	if err != nil || !strings.Contains(string(body), `"laptop"`) {
		t.Fatalf("body: %v", err)
	}
	// A roster edit stamps no record.
	if err := v.Put(Global(), "A_KEY", rec("TESTSECRET_roster")); err != nil {
		t.Fatal(err)
	}
	before, _ := v.Body()
	if err := v.EditRoster(func(r map[string]merge.Device) { delete(r, "d1") }); err != nil {
		t.Fatal(err)
	}
	after, _ := v.Body()
	if got, _ := v.Roster(); len(got) != 0 || hlcsOf(before) != hlcsOf(after) {
		t.Fatalf("roster edit changed a clock or did not apply: %v", got)
	}
}

func TestApplyBodyHoldsTheLockAndSkipsNoChange(t *testing.T) {
	v, _ := newVault(t)
	if err := v.Put(Global(), "A_KEY", rec("TESTSECRET_apply")); err != nil {
		t.Fatal(err)
	}
	var seen string
	err := v.ApplyBody(func(local []byte) ([]byte, error) { seen = string(local); return nil, nil })
	if err != nil || !strings.Contains(seen, `"schema":2`) || !strings.Contains(seen, "A_KEY") {
		t.Fatalf("local body not offered: %v", err)
	}
	merged := strings.Replace(seen, "A_KEY", "B_KEY", 1)
	if err := v.ApplyBody(func([]byte) ([]byte, error) { return []byte(merged), nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Resolve("B_KEY", ""); err != nil {
		t.Fatalf("merged body not applied: %v", err)
	}
	if err := v.ApplyBody(func([]byte) ([]byte, error) { return []byte(`{"schema":1}`), nil }); err == nil {
		t.Fatal("a body that is not schema 2 was applied")
	}
}

func hlcsOf(body []byte) string {
	var out []string
	for _, p := range strings.Split(string(body), `"hlc":"`)[1:] {
		out = append(out, p[:strings.Index(p, `"`)])
	}
	return strings.Join(out, ",")
}

func TestConflictCountIsReadOnly(t *testing.T) {
	v, home := newVault(t)
	if n, err := v.ConflictCount(); err != nil || n != 0 {
		t.Fatalf("fresh vault: %d %v", n, err)
	}
	body, _ := v.Body()
	withOne := strings.Replace(string(body), `"conflicts":[]`, `"conflicts":[{"id":"c1","key":"global/A_KEY","lost_at":"2026-11-04T00:00:00Z"}]`, 1)
	if withOne == string(body) {
		t.Fatalf("body has no conflicts field: %s", body)
	}
	if err := v.ApplyBody(func([]byte) ([]byte, error) { return []byte(withOne), nil }); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(home, "vault.enc"))
	if n, err := v.ConflictCount(); err != nil || n != 1 {
		t.Fatalf("count: %d %v", n, err)
	}
	after, _ := os.ReadFile(filepath.Join(home, "vault.enc"))
	if !bytes.Equal(before, after) {
		t.Fatal("counting conflicts wrote the vault")
	}
}
