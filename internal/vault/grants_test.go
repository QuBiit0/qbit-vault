package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	grantsName    = "TESTSECRET_GRANT_NAME"
	grantsRoot    = "/home/me/TESTSECRET_shop-api"
	grantsSession = "pi:TESTSECRET_session_0123"
)

func grantsBody() []byte {
	return []byte(`{"grants":[{"name":"` + grantsName + `","layer":"project:` + grantsRoot + `","session":"` + grantsSession + `"}]}`)
}

func setGrants(t *testing.T, v *Vault, body []byte) bool {
	t.Helper()
	reset, err := v.MutateGrants(func(_ []byte, _ bool) ([]byte, error) { return body, nil })
	if err != nil {
		t.Fatalf("MutateGrants: %v", err)
	}
	return reset
}

func getGrants(t *testing.T, v *Vault) ([]byte, bool) {
	t.Helper()
	var got []byte
	reset, err := v.ReadGrants(func(b []byte) error { got = append([]byte(nil), b...); return nil })
	if err != nil {
		t.Fatalf("ReadGrants: %v", err)
	}
	return got, reset
}

func grantsPath(home string) string { return filepath.Join(home, "grants.enc") }

func TestGrantsEmptyByDefault(t *testing.T) {
	v, home := newVault(t)
	body, reset := getGrants(t, v)
	if body != nil || reset {
		t.Fatalf("body=%q reset=%v", body, reset)
	}
	if _, err := os.Stat(grantsPath(home)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("reading must not create grants.enc")
	}
}

func TestGrantsRoundTripAndCounter(t *testing.T) {
	v, home := newVault(t)
	if setGrants(t, v, grantsBody()) {
		t.Fatal("first write reported a reset")
	}
	got, reset := getGrants(t, v)
	if !bytes.Equal(got, grantsBody()) || reset {
		t.Fatalf("round trip: %q reset=%v", got, reset)
	}
	setGrants(t, v, []byte(`{"grants":[]}`))
	if w := readState(t, home)["grants_writes"]; w != float64(2) {
		t.Fatalf("grants_writes = %v, want 2", w)
	}
	if w := readState(t, home)["writes"]; w != float64(1) {
		t.Fatalf("grants writes must not touch the vault counter: %v", w)
	}
}

func TestGrantsNoChangeDoesNotWrite(t *testing.T) {
	v, home := newVault(t)
	if _, err := v.MutateGrants(func(_ []byte, _ bool) ([]byte, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(grantsPath(home)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a nil result must not write")
	}
}

func TestGrantsCallbackErrorWritesNothing(t *testing.T) {
	v, home := newVault(t)
	setGrants(t, v, grantsBody())
	before, _ := os.ReadFile(grantsPath(home))
	boom := errors.New("boom")
	if _, err := v.MutateGrants(func(_ []byte, _ bool) ([]byte, error) { return []byte(`{}`), boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if after, _ := os.ReadFile(grantsPath(home)); !bytes.Equal(before, after) {
		t.Fatal("grants.enc changed")
	}
}

func TestGrantsPreserveUnknownStateKeys(t *testing.T) {
	v, home := newVault(t)
	st, err := loadState(home)
	if err != nil {
		t.Fatal(err)
	}
	st.extra["hosts"] = json.RawMessage(`{"pi":{"x":1}}`)
	b, _ := st.marshal()
	if err := os.WriteFile(filepath.Join(home, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	setGrants(t, v, grantsBody())
	mustPut(t, v, Global(), "A_KEY", rec("x")) // a vault save must keep the counter too
	m := readState(t, home)
	if m["hosts"] == nil || m["grants_writes"] != float64(1) {
		t.Fatalf("state = %v", m)
	}
}

func TestGrantsTamperIsResetThenReplaced(t *testing.T) {
	v, home := newVault(t)
	setGrants(t, v, grantsBody())
	raw, _ := os.ReadFile(grantsPath(home))
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(grantsPath(home), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if body, reset := getGrants(t, v); body != nil || !reset {
		t.Fatalf("tampered file: body=%q reset=%v", body, reset)
	}
	var seen []byte
	reset, err := v.MutateGrants(func(b []byte, r bool) ([]byte, error) {
		seen = b
		if !r {
			t.Error("callback not told about the reset")
		}
		return []byte(`{"grants":[]}`), nil
	})
	if err != nil || !reset || seen != nil {
		t.Fatalf("mutate: reset=%v err=%v seen=%q", reset, err, seen)
	}
	if body, reset := getGrants(t, v); string(body) != `{"grants":[]}` || reset {
		t.Fatalf("after replace: body=%q reset=%v", body, reset)
	}
}

func TestGrantsWrongFormatIsReset(t *testing.T) {
	v, home := newVault(t)
	setGrants(t, v, grantsBody())
	vaultBytes, _ := os.ReadFile(filepath.Join(home, "vault.enc"))
	if err := os.WriteFile(grantsPath(home), vaultBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if body, reset := getGrants(t, v); body != nil || !reset {
		t.Fatalf("vault.enc used as grants.enc: body=%q reset=%v", body, reset)
	}
}

func TestGrantsRollbackIsReset(t *testing.T) {
	v, home := newVault(t)
	setGrants(t, v, grantsBody())
	older, _ := os.ReadFile(grantsPath(home))
	setGrants(t, v, []byte(`{"grants":[]}`)) // the user revoked everything
	if err := os.WriteFile(grantsPath(home), older, 0o600); err != nil {
		t.Fatal(err)
	}
	if body, reset := getGrants(t, v); body != nil || !reset {
		t.Fatalf("rolled-back file revived grants: body=%q reset=%v", body, reset)
	}
}

func TestGrantsMissingCounterIsAcceptedAndRepaired(t *testing.T) {
	v, home := newVault(t)
	setGrants(t, v, grantsBody())
	st, _ := loadState(home)
	delete(st.extra, "grants_writes")
	b, _ := st.marshal()
	if err := os.WriteFile(filepath.Join(home, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	body, reset := getGrants(t, v)
	if !bytes.Equal(body, grantsBody()) || reset {
		t.Fatalf("body=%q reset=%v", body, reset)
	}
	if readState(t, home)["grants_writes"] != float64(1) {
		t.Fatal("counter not repaired")
	}
}

func TestGrantsAheadOfCounterIsAccepted(t *testing.T) {
	v, home := newVault(t)
	setGrants(t, v, grantsBody())
	st, _ := loadState(home)
	st.extra["grants_writes"] = json.RawMessage(`0`) // crash between the two writes
	b, _ := st.marshal()
	if err := os.WriteFile(filepath.Join(home, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if body, reset := getGrants(t, v); !bytes.Equal(body, grantsBody()) || reset {
		t.Fatalf("body=%q reset=%v", body, reset)
	}
}

func TestGrantsDeletedFileIsEmpty(t *testing.T) {
	v, home := newVault(t)
	setGrants(t, v, grantsBody())
	if err := os.Remove(grantsPath(home)); err != nil {
		t.Fatal(err)
	}
	if body, reset := getGrants(t, v); body != nil || reset {
		t.Fatalf("body=%q reset=%v", body, reset)
	}
	// The counter is ahead of any file now; the next write must still work.
	setGrants(t, v, grantsBody())
	if body, reset := getGrants(t, v); !bytes.Equal(body, grantsBody()) || reset {
		t.Fatalf("after rewrite: body=%q reset=%v", body, reset)
	}
}

func TestGrantsFileLeaksNothingAndHasNoSnapshots(t *testing.T) {
	v, home := newVault(t)
	setGrants(t, v, grantsBody())
	setGrants(t, v, grantsBody())
	raw, _ := os.ReadFile(grantsPath(home))
	for _, s := range []string{grantsName, grantsRoot, grantsSession, "TESTSECRET_"} {
		for _, enc := range []string{s, base64.StdEncoding.EncodeToString([]byte(s)), base64.RawURLEncoding.EncodeToString([]byte(s))} {
			if bytes.Contains(raw, []byte(enc)) {
				t.Fatal("grants.enc holds plaintext")
			}
		}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 5 {
		t.Fatalf("not an envelope: %v", err)
	}
	if !strings.Contains(string(m["format"]), "gentle-vault-grants/1") {
		t.Fatalf("format = %s", m["format"])
	}
	_ = filepath.WalkDir(filepath.Join(home, "backups"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "grants.enc" {
			t.Errorf("grants.enc was snapshotted: %s", p)
		}
		return nil
	})
	if matches, _ := filepath.Glob(grantsPath(home) + ".tmp.*"); len(matches) != 0 {
		t.Fatal("leftover temp file")
	}
}

func TestGrantsFileIsOwnerOnlyAndTempIsPrivate(t *testing.T) {
	v, home := newVault(t)
	old := beforeRename
	sawTemp := false
	beforeRename = func(tmp, target string) error {
		if filepath.Base(target) == grantsFile {
			wantPrivate(t, "grants temp file", tmp)
			sawTemp = true
		}
		return nil
	}
	t.Cleanup(func() { beforeRename = old })
	setGrants(t, v, grantsBody())
	if !sawTemp {
		t.Fatal("rename hook never saw grants.enc")
	}
	wantPrivate(t, "grants.enc", grantsPath(home))
}
