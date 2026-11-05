package filemerge

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const ownedMarker = "<!-- managed by qbit-vault -->"

var (
	ownedV1 = []byte("---\nname: x\n---\n" + ownedMarker + "\nversion one\n")
	ownedV2 = []byte("---\nname: x\n---\n" + ownedMarker + "\nversion two\n")
)

func TestWriteOwnedFileCreatesTheFileAndItsDirectories(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "skills", "qbit-vault", "SKILL.md")
	r, err := WriteOwnedFile(home, p, ownedV1, ownedMarker, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); got != string(ownedV1) {
		t.Fatalf("file = %q", got)
	}
	if !r.Changed || !r.Created || !r.Exact || r.SHA256 != digest(ownedV1) || r.Path != p || r.Snapshot.Existed {
		t.Fatalf("receipt = %+v", r)
	}
}

func TestWriteOwnedFileWritesNothingWhenTheBytesAreEqual(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "SKILL.md")
	r1, err := WriteOwnedFile(home, p, ownedV1, ownedMarker, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotCount(t, home)
	info, _ := os.Stat(p)
	r2, err := WriteOwnedFile(home, p, ownedV1, ownedMarker, &r1)
	if err != nil {
		t.Fatal(err)
	}
	r1.Changed = false
	if r2 != r1 {
		t.Fatalf("receipt changed: %+v -> %+v", r1, r2)
	}
	if after := snapshotCount(t, home); after != before {
		t.Fatalf("snapshots %d -> %d", before, after)
	}
	if info2, _ := os.Stat(p); !info2.ModTime().Equal(info.ModTime()) {
		t.Fatal("file was rewritten")
	}
}

func TestWriteOwnedFileReplacesAnOlderVersionAfterASnapshot(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "SKILL.md")
	r1, err := WriteOwnedFile(home, p, ownedV1, ownedMarker, nil)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := WriteOwnedFile(home, p, ownedV2, ownedMarker, &r1)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); got != string(ownedV2) {
		t.Fatalf("file = %q", got)
	}
	if !r2.Changed || !r2.Created || r2.Exact || !r2.Snapshot.Existed {
		t.Fatalf("receipt = %+v", r2)
	}
	if got := readFile(t, r2.Snapshot.Backup); got != string(ownedV1) {
		t.Fatalf("snapshot = %q, want the previous version", got)
	}
}

func TestWriteOwnedFileRefusesAFileItDoesNotManage(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "SKILL.md")
	writeFile(t, p, "the user's own skill\n")
	_, err := WriteOwnedFile(home, p, ownedV1, ownedMarker, nil)
	if !errors.Is(err, ErrForeignFile) {
		t.Fatalf("err = %v, want ErrForeignFile", err)
	}
	if got := readFile(t, p); got != "the user's own skill\n" {
		t.Fatalf("file changed: %q", got)
	}
	if n := snapshotCount(t, home); n != 0 {
		t.Fatalf("%d snapshots taken", n)
	}
}

func TestWriteOwnedFileRefusesContentWithoutTheMarker(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "SKILL.md")
	if _, err := WriteOwnedFile(home, p, []byte("no marker\n"), ownedMarker, nil); !errors.Is(err, ErrInvalidEdit) {
		t.Fatalf("err = %v, want ErrInvalidEdit", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file was written")
	}
}

func TestRemoveOwnedFileDeletesItAndTheEmptyDirectory(t *testing.T) {
	home := newHome(t)
	dir := filepath.Join(t.TempDir(), "qbit-vault")
	p := filepath.Join(dir, "SKILL.md")
	r, err := WriteOwnedFile(home, p, ownedV1, ownedMarker, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := RemoveOwnedFile(home, r, ownedMarker)
	if err != nil || out != Deleted {
		t.Fatalf("RemoveOwnedFile = %q, %v", out, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("the empty directory was kept")
	}
}

func TestRemoveOwnedFileKeepsAFileTheUserReplaced(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "SKILL.md")
	r, err := WriteOwnedFile(home, p, ownedV1, ownedMarker, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "now the user's own\n")
	out, err := RemoveOwnedFile(home, r, ownedMarker)
	if err != nil || out != Unchanged {
		t.Fatalf("RemoveOwnedFile = %q, %v", out, err)
	}
	if got := readFile(t, p); got != "now the user's own\n" {
		t.Fatalf("file = %q", got)
	}
}

func TestRemoveOwnedFileKeepsOtherFilesInTheDirectory(t *testing.T) {
	home := newHome(t)
	dir := filepath.Join(t.TempDir(), "qbit-vault")
	p := filepath.Join(dir, "SKILL.md")
	r, err := WriteOwnedFile(home, p, ownedV1, ownedMarker, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "notes.md"), "mine\n")
	if out, err := RemoveOwnedFile(home, r, ownedMarker); err != nil || out != Deleted {
		t.Fatalf("RemoveOwnedFile = %q, %v", out, err)
	}
	if got := readFile(t, filepath.Join(dir, "notes.md")); got != "mine\n" {
		t.Fatalf("notes.md = %q", got)
	}
}

func TestRemoveOwnedFileOfAMissingFileIsAbsent(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "SKILL.md")
	out, err := RemoveOwnedFile(home, Receipt{Path: p}, ownedMarker)
	if err != nil || out != Absent {
		t.Fatalf("RemoveOwnedFile = %q, %v", out, err)
	}
}

// snapshotCount counts the files under the vault home's backups directory.
func snapshotCount(t *testing.T, home string) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(filepath.Join(home, "backups"), func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			n++
		}
		return nil
	})
	return n
}
