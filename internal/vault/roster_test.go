package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/merge"
	"github.com/QuBiit0/gentle-vault/internal/secret"
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

func TestDisableRemoteKeepsVaultAndKey(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_disable"))
	if err := v.SaveDeviceSecret(secret.New("dk", bytes.Repeat([]byte{5}, 32))); err != nil {
		t.Fatal(err)
	}
	if err := WriteRemote(home, &Remote{Server: "http://x", AccountID: strings.Repeat("a", 32), Generation: 2}); err != nil {
		t.Fatal(err)
	}
	if err := DisableRemote(home); err != nil {
		t.Fatal(err)
	}
	if r, _ := ReadRemote(home); r != nil {
		t.Fatalf("remote state left: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(home, "remote")); !os.IsNotExist(err) {
		t.Fatal("remote files left")
	}
	again, err := Open(home, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := again.Resolve("A_KEY", ""); err != nil || !sameValue(got, "TESTSECRET_disable") {
		t.Fatalf("vault changed: %v", err)
	}
	if err := DisableRemote(home); err != nil { // idempotent
		t.Fatal(err)
	}
}

// ResealRemoteFiles moves device.enc and base.enc to the current key from a
// retired one, and is a no-op when they already open (REMOTE_SYNC § 4.5).
func TestResealRemoteFilesFollowsARekey(t *testing.T) {
	v, home := newVault(t)
	dk := secret.New("dk", bytes.Repeat([]byte{5}, 32))
	if err := v.SaveDeviceSecret(dk); err != nil {
		t.Fatal(err)
	}
	if err := v.SaveBase([]byte(`{"schema":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := v.ResealRemoteFiles(); err != nil { // nothing to do
		t.Fatal(err)
	}
	if err := Rekey(home, testKey(1), testKey(2)); err != nil {
		t.Fatal(err)
	}
	nv, err := Open(home, testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nv.DeviceSecret(); err == nil {
		t.Fatal("device.enc should still be sealed with the old key")
	}
	if err := nv.ResealRemoteFiles(); err != nil {
		t.Fatal(err)
	}
	got, err := nv.DeviceSecret()
	if err != nil || string(got.Reveal()) != string(dk.Reveal()) {
		t.Fatalf("device secret after reseal: %v", err)
	}
	if b, err := nv.Base(); err != nil || string(b) != `{"schema":2}` {
		t.Fatalf("base after reseal: %q %v", b, err)
	}
	if err := nv.ResealRemoteFiles(); err != nil { // idempotent
		t.Fatal(err)
	}
	// A file no retired key opens is reported, not replaced.
	if err := os.WriteFile(filepath.Join(home, "remote", "device.enc"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := nv.ResealRemoteFiles(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("junk device.enc: %v", err)
	}
}
