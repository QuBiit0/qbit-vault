package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type dropAll struct{ dropped []string }

func (d *dropAll) DropRecord(body []byte, name, layer string) ([]byte, int, error) {
	d.dropped = append(d.dropped, name+"@"+layer)
	return []byte("edited"), 1, nil
}
func (*dropAll) DropNonOnce([]byte, string, string, string) ([]byte, int, error) { return nil, 0, nil }
func (*dropAll) DropLayer([]byte, string) ([]byte, int, error)                   { return nil, 0, nil }

func TestPutManyWithGrantsIsOneWriteAndKeepsMetadata(t *testing.T) {
	v, home := newVault(t)
	old := rec("TESTSECRET_old")
	old.Description, old.Binaries = "kept", []string{"gh"}
	mustPut(t, v, Global(), "B", old)
	before := len(backupsOf(t, home))
	ed := &dropAll{}
	res, replaced, err := v.PutManyWithGrants(Global(), []string{"A", "B"}, map[string]Record{
		"A": rec("TESTSECRET_a"), "B": rec("TESTSECRET_b"),
	}, ed)
	if err != nil {
		t.Fatal(err)
	}
	if len(backupsOf(t, home)) != before+1 {
		t.Fatal("not a single vault write")
	}
	if len(replaced) != 1 || replaced[0] != "B" || res.Changed != 1 || len(ed.dropped) != 1 || ed.dropped[0] != "B@global" {
		t.Fatalf("replaced=%v res=%+v dropped=%v", replaced, res, ed.dropped)
	}
	b, _, err := v.Resolve("B", t.TempDir())
	if err != nil || !sameValue(b, "TESTSECRET_b") || b.Description != "kept" || len(b.Binaries) != 1 {
		t.Fatalf("B=%+v err=%v", b, err)
	}
	if b.ID == "" {
		t.Fatal("no record id")
	}
}

func TestPutManyWithGrantsRejectsBadInputWithoutWriting(t *testing.T) {
	v, home := newVault(t)
	live, _ := os.ReadFile(filepath.Join(home, vaultFile))
	cases := map[string]struct {
		names []string
		recs  map[string]Record
	}{
		"invalid name": {[]string{"A", "bad"}, map[string]Record{"A": rec("x"), "bad": rec("y")}},
		"empty":        {nil, map[string]Record{}},
		"missing rec":  {[]string{"A", "B"}, map[string]Record{"A": rec("x")}},
	}
	for n, c := range cases {
		if _, _, err := v.PutManyWithGrants(Global(), c.names, c.recs, nil); err == nil {
			t.Errorf("%s accepted", n)
		}
	}
	if now, _ := os.ReadFile(filepath.Join(home, vaultFile)); string(now) != string(live) {
		t.Fatal("rejected input changed the vault")
	}
	if _, _, err := v.PutManyWithGrants(Global(), []string{"A"}, map[string]Record{"A": rec("x")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.PutManyWithGrants(Layer{Project: true}, []string{"B"}, map[string]Record{"B": rec("x")}, nil); !errors.Is(err, ErrNoProject) {
		t.Fatalf("project layer without root: %v", err)
	}
}

func TestPutMissingNeverReplacesAndWritesNothingOnAConflict(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "B", rec("TESTSECRET_old"))
	live, _ := os.ReadFile(filepath.Join(home, vaultFile))
	err := v.PutMissing(Global(), []string{"A", "B"}, map[string]Record{"A": rec("TESTSECRET_a"), "B": rec("TESTSECRET_b")})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v, want ErrExists", err)
	}
	if after, _ := os.ReadFile(filepath.Join(home, vaultFile)); string(after) != string(live) {
		t.Fatal("vault.enc changed on a refused store")
	}
	if _, _, err := v.Resolve("A", t.TempDir()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("A was stored: %v", err)
	}
	if err := v.PutMissing(Global(), []string{"A"}, map[string]Record{"A": rec("TESTSECRET_a")}); err != nil {
		t.Fatal(err)
	}
	if a, _, err := v.Resolve("A", t.TempDir()); err != nil || !sameValue(a, "TESTSECRET_a") || a.ID == "" {
		t.Fatalf("A=%+v err=%v", a, err)
	}
	if err := v.PutMissing(Global(), []string{"bad name"}, map[string]Record{"bad name": rec("TESTSECRET_x")}); err == nil {
		t.Fatal("invalid name accepted")
	}
}
