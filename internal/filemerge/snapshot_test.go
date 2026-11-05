package filemerge

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncodePath(t *testing.T) {
	cases := []struct {
		in, want string
		err      error
	}{
		{`C:\Users\Ana\.claude\settings.json`, "C/Users/Ana/.claude/settings.json", nil},
		{`c:/Users/Ana/.codex/config.toml`, "C/Users/Ana/.codex/config.toml", nil},
		{`\\?\C:\Users\Ana\x.json`, "C/Users/Ana/x.json", nil},
		{`\\srv\share\dir\x.json`, "UNC/srv/share/dir/x.json", nil},
		{"/home/ana/.claude/settings.json", "home/ana/.claude/settings.json", nil},
		{"/home/a:na/we%rd\\name.json", "home/a%3Ana/we%25rd%5Cname.json", nil},
		{"/home/ana/../etc/x", "home/etc/x", nil},
		{"~/.claude/settings.json", "", ErrNotAbsolute},
		{"settings.json", "", ErrNotAbsolute},
		{`C:settings.json`, "", ErrNotAbsolute},
		{"/", "", ErrNotAbsolute},
		{"", "", ErrNotAbsolute},
	}
	for _, c := range cases {
		got, err := EncodePath(c.in)
		if !errors.Is(err, c.err) || got != c.want {
			t.Errorf("EncodePath(%q) = %q, %v; want %q, %v", c.in, got, err, c.want, c.err)
		}
	}
}

func newHome(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "vault-home")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTakeSnapshotCopiesFile(t *testing.T) {
	home := newHome(t)
	target := filepath.Join(t.TempDir(), ".claude", "settings.json")
	writeFile(t, target, "{\"a\": 1}\n")

	s, err := TakeSnapshot(home, target)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Existed || s.Path != target || !filepath.IsAbs(s.Backup) {
		t.Fatalf("bad handle: %+v", s)
	}
	if !strings.HasPrefix(s.Backup, filepath.Join(home, "backups")+string(filepath.Separator)) {
		t.Fatalf("backup outside backups/: %s", s.Backup)
	}
	if got := readFile(t, s.Backup); got != "{\"a\": 1}\n" {
		t.Fatalf("backup content = %q", got)
	}
	enc, _ := EncodePath(target)
	if !strings.HasSuffix(filepath.ToSlash(s.Backup), "/"+enc) {
		t.Fatalf("backup %s does not end with encoded path %s", s.Backup, enc)
	}
}

func TestTakeSnapshotRecordsAbsentFile(t *testing.T) {
	home := newHome(t)
	target := filepath.Join(t.TempDir(), "nope", "settings.json")
	s, err := TakeSnapshot(home, target)
	if err != nil {
		t.Fatal(err)
	}
	if s.Existed || s.Backup != "" || s.Path != target {
		t.Fatalf("bad handle for absent file: %+v", s)
	}
	if _, err := os.Stat(filepath.Join(home, "backups")); !os.IsNotExist(err) {
		t.Fatalf("absent file must not create a snapshot dir: %v", err)
	}
}

func TestTakeSnapshotRefusesRelativeAndSymlink(t *testing.T) {
	home := newHome(t)
	if _, err := TakeSnapshot(home, "~/.claude/settings.json"); !errors.Is(err, ErrNotAbsolute) {
		t.Fatalf("relative: %v", err)
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	writeFile(t, real, "{}")
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := TakeSnapshot(home, link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlink: %v", err)
	}
}

func TestSnapshotsGetDistinctDirsOnSameTick(t *testing.T) {
	home := newHome(t)
	target := filepath.Join(t.TempDir(), "c.json")
	writeFile(t, target, "{}")
	prev := snapshotClock
	snapshotClock = func() time.Time { return time.Date(2026, 11, 4, 1, 2, 3, 4, time.UTC) }
	defer func() { snapshotClock = prev }()

	a, err := TakeSnapshot(home, target)
	if err != nil {
		t.Fatal(err)
	}
	b, err := TakeSnapshot(home, target)
	if err != nil {
		t.Fatal(err)
	}
	if a.Backup == b.Backup {
		t.Fatal("two snapshots share a file")
	}
	if !strings.Contains(a.Backup, "20261104T010203.000000004Z") || !strings.Contains(b.Backup, "20261104T010203.000000004Z-001") {
		t.Fatalf("names: %s %s", a.Backup, b.Backup)
	}
}

func TestSnapshotPermissionsOwnerOnly(t *testing.T) {
	if runtimeIsWindows() {
		t.Skip("POSIX modes only")
	}
	home := newHome(t)
	target := filepath.Join(t.TempDir(), "c.json")
	writeFile(t, target, "{}")
	s, err := TakeSnapshot(home, target)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{s.Backup, filepath.Dir(s.Backup), filepath.Join(home, "backups")} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s mode %o is not owner-only", p, info.Mode().Perm())
		}
	}
}
