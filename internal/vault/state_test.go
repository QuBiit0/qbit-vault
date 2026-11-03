package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var uuidV4RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func newTestStore(t *testing.T) *store {
	t.Helper()
	return &store{home: t.TempDir(), key: testKey(1)}
}

func readState(t *testing.T, home string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSaveIncrementsWritesAndRoundTrips(t *testing.T) {
	s := newTestStore(t)
	for i := uint64(1); i <= 3; i++ {
		if err := s.save([]byte(fixtureValue)); err != nil {
			t.Fatal(err)
		}
		st := readState(t, s.home)
		if st["writes"] != float64(i) || st["format"] != "gentle-vault-state/1" {
			t.Fatalf("state after save %d: %v", i, st)
		}
		pt, snap, err := s.load()
		if err != nil || string(pt) != fixtureValue || snap.Writes != i {
			t.Fatalf("load: err=%v writes=%d ptlen=%d", err, snap.Writes, len(pt))
		}
	}
	if !uuidV4RE.MatchString(readState(t, s.home)["vault_id"].(string)) {
		t.Fatal("vault_id is not a uuid v4")
	}
}

func TestSaveKeepsVaultIDAndCreatedAt(t *testing.T) {
	s := newTestStore(t)
	if err := s.save([]byte("a")); err != nil {
		t.Fatal(err)
	}
	id := readState(t, s.home)["vault_id"]
	_, first, _ := s.load()
	if err := s.save([]byte("b")); err != nil {
		t.Fatal(err)
	}
	_, second, _ := s.load()
	if readState(t, s.home)["vault_id"] != id || first.CreatedAt != second.CreatedAt || first.CreatedAt == "" {
		t.Fatal("vault_id or created_at changed between saves")
	}
}

func TestStatePreservesUnknownKeys(t *testing.T) {
	s := newTestStore(t)
	if err := s.save([]byte("a")); err != nil {
		t.Fatal(err)
	}
	st := readState(t, s.home)
	st["keychain"] = "secret-service"
	st["hosts"] = map[string]any{"claude-code": map[string]any{"registered_at": "x"}}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(s.home, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.save([]byte("b")); err != nil {
		t.Fatal(err)
	}
	got := readState(t, s.home)
	if got["keychain"] != "secret-service" || got["hosts"] == nil || got["writes"] != float64(2) {
		t.Fatalf("state = %v", got)
	}
}

func TestLoadRollback(t *testing.T) {
	s := newTestStore(t)
	vaultPath := filepath.Join(s.home, "vault.enc")
	if err := s.save([]byte("v1")); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(vaultPath)
	if err := s.save([]byte("v2")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.load()
	if !errors.Is(err, ErrRollback) || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrRollback and ErrCorrupt", err)
	}
}

func TestLoadRepairsStateAfterCrash(t *testing.T) {
	s := newTestStore(t)
	if err := s.save([]byte("v1")); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(s.home, "state.json")
	oldState, _ := os.ReadFile(statePath)
	if err := s.save([]byte("v2")); err != nil {
		t.Fatal(err)
	}
	// Crash between the two writes: vault.enc is at 2, state.json still at 1.
	if err := os.WriteFile(statePath, oldState, 0o600); err != nil {
		t.Fatal(err)
	}
	pt, snap, err := s.load()
	if err != nil || string(pt) != "v2" || snap.Writes != 2 {
		t.Fatalf("load: err=%v writes=%d", err, snap.Writes)
	}
	if readState(t, s.home)["writes"] != float64(2) {
		t.Fatal("state.json not repaired")
	}
}

func TestLoadCorruptState(t *testing.T) {
	s := newTestStore(t)
	if err := s.save([]byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.home, "state.json"), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadMissingVault(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.load(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}

// snapshotWrites reads the writes counter of a snapshot's state.json and of
// the AAD of its vault.enc; both files must be present.
func snapshotWrites(t *testing.T, dir string) (stateWrites, vaultWrites uint64) {
	t.Helper()
	sb, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("snapshot lacks state.json: %v", err)
	}
	var st struct {
		Writes uint64 `json:"writes"`
	}
	if err := json.Unmarshal(sb, &st); err != nil {
		t.Fatal(err)
	}
	vb, err := os.ReadFile(filepath.Join(dir, "vault.enc"))
	if err != nil {
		t.Fatalf("snapshot lacks vault.enc: %v", err)
	}
	var env struct {
		AAD AAD `json:"aad"`
	}
	if err := json.Unmarshal(vb, &env); err != nil {
		t.Fatal(err)
	}
	return st.Writes, env.AAD.Writes
}

func TestSaveSnapshotsConsistentPairPerSave(t *testing.T) {
	tests := []struct {
		name  string
		keep  int
		saves int
		want  int // snapshot dirs: the first save has nothing to back up
	}{
		{"single save has no snapshot", 20, 1, 0},
		{"second save snapshots once", 20, 2, 1},
		{"below keep keeps N-1", 20, 6, 5},
		{"pruned to keep", 3, 8, 3},
		{"default keep is 20 saves", 0, 25, 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStore(t)
			s.keep = tt.keep
			for range tt.saves {
				if err := s.save([]byte("body")); err != nil {
					t.Fatal(err)
				}
			}
			dirs := backupDirs(t, s.home)
			if len(dirs) != tt.want {
				t.Fatalf("got %d snapshot dirs, want %d", len(dirs), tt.want)
			}
			for i, d := range dirs {
				entries, _ := os.ReadDir(filepath.Join(s.home, "backups", d))
				if len(entries) != 2 {
					t.Fatalf("snapshot %s holds %d files, want 2", d, len(entries))
				}
				sw, vw := snapshotWrites(t, filepath.Join(s.home, "backups", d))
				// Snapshots are the pairs as they stood before saves
				// (saves-len(dirs)+1 .. saves-1), oldest first.
				want := uint64(tt.saves - len(dirs) + i)
				if sw != vw || sw != want {
					t.Fatalf("snapshot %d: state writes=%d vault writes=%d, want both %d", i, sw, vw, want)
				}
			}
		})
	}
}
