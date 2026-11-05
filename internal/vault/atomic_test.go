package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"testing"
)

var backupDirRE = regexp.MustCompile(`^\d{8}T\d{6}\.\d{9}Z(-[0-9]{3})?$`)

func backupDirs(t *testing.T, home string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(home, "backups"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestWriteAtomicCreatesFile(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := writeAtomic(home, "vault.enc", []byte("one"), 20); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(home, "vault.enc"))
	if err != nil || string(got) != "one" {
		t.Fatalf("read: err=%v len=%d", err, len(got))
	}
	if len(backupDirs(t, home)) != 0 {
		t.Fatal("first write must not create a backup")
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(home, "vault.enc"))
		di, _ := os.Stat(home)
		if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
			t.Fatalf("modes: file=%v dir=%v", fi.Mode().Perm(), di.Mode().Perm())
		}
	}
	matches, _ := filepath.Glob(filepath.Join(home, "*.tmp.*"))
	if len(matches) != 0 {
		t.Fatalf("temp files left behind: %v", matches)
	}
}

func TestWriteAtomicBacksUpBeforeOverwrite(t *testing.T) {
	home := t.TempDir()
	for _, content := range []string{"old", "new"} {
		if err := writeAtomic(home, "vault.enc", []byte(content), 20); err != nil {
			t.Fatal(err)
		}
	}
	dirs := backupDirs(t, home)
	if len(dirs) != 1 || !backupDirRE.MatchString(dirs[0]) {
		t.Fatalf("backup dirs = %v", dirs)
	}
	old, err := os.ReadFile(filepath.Join(home, "backups", dirs[0], "vault.enc"))
	if err != nil || string(old) != "old" {
		t.Fatalf("backup content: err=%v len=%d", err, len(old))
	}
	cur, _ := os.ReadFile(filepath.Join(home, "vault.enc"))
	if string(cur) != "new" {
		t.Fatal("target not updated")
	}
}

func TestWriteAtomicPrunesBackups(t *testing.T) {
	tests := []struct {
		name   string
		keep   int
		writes int
		want   int
	}{
		{"keeps newest three", 3, 8, 3},
		{"under the limit keeps all", 20, 5, 4},
		{"default when keep is zero", 0, 25, 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			for i := range tt.writes {
				if err := writeAtomic(home, "vault.enc", []byte{byte('a' + i)}, tt.keep); err != nil {
					t.Fatal(err)
				}
			}
			dirs := backupDirs(t, home)
			if len(dirs) != tt.want {
				t.Fatalf("got %d backup dirs, want %d", len(dirs), tt.want)
			}
			// The newest snapshot holds the content just before the last write.
			last, err := os.ReadFile(filepath.Join(home, "backups", dirs[len(dirs)-1], "vault.enc"))
			if err != nil || string(last) != string([]byte{byte('a' + tt.writes - 2)}) {
				t.Fatalf("newest backup wrong: err=%v len=%d", err, len(last))
			}
		})
	}
}

func TestWriteAtomicCrashSeamKeepsTarget(t *testing.T) {
	home := t.TempDir()
	if err := writeAtomic(home, "vault.enc", []byte("intact"), 20); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("simulated crash")
	prev := beforeRename
	beforeRename = func(string, string) error { return boom }
	t.Cleanup(func() { beforeRename = prev })

	err := writeAtomic(home, "vault.enc", []byte("half-written"), 20)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	got, rerr := os.ReadFile(filepath.Join(home, "vault.enc"))
	if rerr != nil || string(got) != "intact" {
		t.Fatalf("target damaged: err=%v len=%d", rerr, len(got))
	}
	matches, _ := filepath.Glob(filepath.Join(home, "*.tmp.*"))
	if len(matches) != 0 {
		t.Fatalf("temp files left behind: %v", matches)
	}
}

// Config snapshots of host registration (internal/filemerge) share
// backups/ but are not vault backups: pruning must never remove them, or an
// uninstall could no longer restore a config file byte for byte.
func TestPruneKeepsConfigSnapshots(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "00000000T000000Z", "C", "Users", "u", ".claude")
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "settings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		d := filepath.Join(dir, fmt.Sprintf("2026010%dT000000Z", i+1))
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "vault.enc"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneBackups(dir, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg, "settings.json")); err != nil {
		t.Fatal("pruning removed a config snapshot")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 { // the config snapshot + the 2 newest vault backups
		t.Fatalf("%d entries left, want 3", len(entries))
	}
}

func TestListBackupsSkipsConfigSnapshots(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, "backups", "20260101T000000.000000000Z", "C", "Users", "u", ".codex")
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "config.toml"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	bs, err := ListBackups(home)
	if err != nil || len(bs) != 0 {
		t.Fatalf("backups = %+v, %v", bs, err)
	}
}
