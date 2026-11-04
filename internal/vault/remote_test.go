package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

func TestRemoteStateRoundTrip(t *testing.T) {
	_, home := newVault(t)
	if r, err := ReadRemote(home); err != nil || r != nil {
		t.Fatalf("fresh vault: %+v %v", r, err)
	}
	want := Remote{Server: "https://vault.example", AccountID: strings.Repeat("a", 32), Generation: 1, LastVersion: 3, PendingPush: true, LastPullAt: "2026-11-04T00:00:00Z"}
	if err := WriteRemote(home, &want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRemote(home)
	if err != nil || *got != want {
		t.Fatalf("got %+v %v", got, err)
	}
	// Other state survives: the vault still opens, the counter is intact.
	if _, err := Open(home, testKey(1)); err != nil {
		t.Fatal(err)
	}
	if err := WriteRemote(home, nil); err != nil {
		t.Fatal(err)
	}
	if r, _ := ReadRemote(home); r != nil {
		t.Fatalf("not cleared: %+v", r)
	}
}

func TestSealedRemoteFiles(t *testing.T) {
	v, home := newVault(t)
	dk := secret.New("dk", bytes.Repeat([]byte{5}, 32))
	if err := v.SaveDeviceSecret(dk); err != nil {
		t.Fatal(err)
	}
	got, err := v.DeviceSecret()
	if err != nil || string(got.Reveal()) != string(dk.Reveal()) {
		t.Fatalf("device secret: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(home, "remote", "device.enc"))
	if bytes.Contains(raw, bytes.Repeat([]byte{5}, 32)) {
		t.Fatal("device secret stored in clear")
	}
	if _, err := v.Base(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no base yet: %v", err)
	}
	base := []byte(`{"schema":2,"global":{"A":{"value":"TESTSECRET_base"}}}`)
	if err := v.SaveBase(base); err != nil {
		t.Fatal(err)
	}
	b, err := v.Base()
	if err != nil || !bytes.Equal(b, base) {
		t.Fatalf("base: %q %v", b, err)
	}
	if raw, _ := os.ReadFile(filepath.Join(home, "remote", "base.enc")); bytes.Contains(raw, []byte("TESTSECRET_")) {
		t.Fatal("base stored in clear")
	}
	v2, _ := Open(home, testKey(1))
	if _, err := (&Vault{st: &store{home: home, key: testKey(9)}}).DeviceSecret(); err == nil {
		t.Fatal("device secret opened with another key")
	}
	_ = v2
	if err := v.ClearRemoteFiles(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "remote")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("remote files left after clear")
	}
}

// A merged body is written as is: no clock is re-stamped, so applying a
// remote version does not invent local changes.
func TestBodyAndRawReplaceKeepClocks(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	body, err := v.Body()
	if err != nil || !strings.Contains(string(body), `"schema":2`) {
		t.Fatalf("body: %v", err)
	}
	remote := `{"schema":2,"global":{"R":{"id":"rr","value":"TESTSECRET_r","description":"","sensitive":false,"binaries":[],"hosts":[],"created_at":"x","updated_at":"x","hlc":"0000000000005.0@` + strings.Repeat("bb", 16) + `"}},"projects":{},"tombstones":[],"conflicts":[],"devices":{}}`
	if err := v.ReplaceBody([]byte(remote)); err != nil {
		t.Fatal(err)
	}
	if h := hlcOf(t, home, "R"); h != "0000000000005.0@"+strings.Repeat("bb", 16) {
		t.Fatalf("hlc re-stamped: %s", h)
	}
	r, _, err := v.Resolve("R", t.TempDir())
	if err != nil || !sameValue(r, "TESTSECRET_r") {
		t.Fatalf("resolve replaced body: %v", err)
	}
	if _, _, err := v.Resolve("A", t.TempDir()); !errors.Is(err, ErrNotFound) {
		t.Fatal("replace did not replace")
	}
	for _, bad := range []string{`nope`, `{"schema":3}`} {
		if err := v.ReplaceBody([]byte(bad)); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
