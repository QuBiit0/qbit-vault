package filemerge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/perm"
)

const (
	backupTimeFormat = "20060102T150405.000000000Z" // same layout as internal/vault
	dirMode          = 0o700
	fileMode         = 0o600
)

// snapshotClock names snapshot directories; tests pin it.
var snapshotClock = time.Now

// Snapshot is the handle of one pre-change copy. It is plain data with
// absolute paths only, so a receipt can carry it in state.json.
type Snapshot struct {
	Path    string `json:"path"`             // absolute path of the config file
	Existed bool   `json:"existed"`          // false: the file did not exist, nothing was copied
	Backup  string `json:"backup,omitempty"` // absolute path of the copy when Existed
}

// EncodePath turns an absolute path into the relative, slash-separated name
// used under backups/<ts>/. It is a pure string function: Windows paths
// (C:\a\b, \\?\C:\a, \\srv\share\a) and POSIX paths both encode on any host.
// Drive C: becomes "C/…", a UNC share "UNC/srv/share/…", a POSIX root path
// drops the leading slash. ".", ".." and empty segments are cleaned away;
// %, :, \, and the characters Windows forbids in names are percent-escaped.
func EncodePath(abs string) (string, error) {
	var prefix string
	var rest string
	switch {
	case strings.HasPrefix(abs, `\\?\UNC\`):
		prefix, rest = "UNC", abs[len(`\\?\UNC\`):]
	case strings.HasPrefix(abs, `\\?\`) && isDriveAbs(abs[4:]):
		prefix, rest = strings.ToUpper(abs[4:5]), abs[7:]
	case strings.HasPrefix(abs, `\\`):
		prefix, rest = "UNC", abs[2:]
	case isDriveAbs(abs):
		prefix, rest = strings.ToUpper(abs[:1]), abs[3:]
	case strings.HasPrefix(abs, "/"):
		rest = abs[1:]
	default:
		return "", ErrNotAbsolute
	}
	var segs []string
	if prefix != "" {
		segs = append(segs, prefix)
	}
	for _, s := range strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == '\\' && prefix != "" }) {
		switch s {
		case ".":
		case "..":
			if len(segs) > 0 && (prefix == "" || len(segs) > 1) {
				segs = segs[:len(segs)-1]
			}
		default:
			segs = append(segs, escapeSegment(s))
		}
	}
	if len(segs) == 0 || (prefix != "" && len(segs) == 1) {
		return "", ErrNotAbsolute
	}
	return strings.Join(segs, "/"), nil
}

func isDriveAbs(s string) bool {
	return len(s) >= 3 && (s[0]|0x20 >= 'a' && s[0]|0x20 <= 'z') && s[1] == ':' && (s[2] == '\\' || s[2] == '/')
}

func escapeSegment(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || strings.IndexByte(`%:\<>"|?*`, c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// TakeSnapshot copies the current file at path to
// <home>/backups/<UTC timestamp>/<EncodePath(path)> (owner-only) and returns
// the handle. A file that does not exist is recorded as such and creates
// nothing. A symlink or non-regular file is refused. Each call uses a new
// snapshot directory.
func TakeSnapshot(home, path string) (Snapshot, error) {
	if !filepath.IsAbs(path) {
		return Snapshot{}, fail(ErrNotAbsolute, path)
	}
	path = filepath.Clean(path)
	s := Snapshot{Path: path}
	_, err := statTarget(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fail(fmt.Errorf("filemerge: read for snapshot: %w", bare(err)), path)
	}
	enc, err := EncodePath(path)
	if err != nil {
		return Snapshot{}, fail(err, path)
	}
	dir, err := newSnapshotDir(home)
	if err != nil {
		return Snapshot{}, fail(err, path)
	}
	backup := filepath.Join(dir, filepath.FromSlash(enc))
	if err := writeBackup(dir, backup, data); err != nil {
		_ = os.RemoveAll(dir)
		return Snapshot{}, fail(err, path)
	}
	s.Existed, s.Backup = true, backup
	return s, nil
}

// writeBackup creates the mirrored directories under the snapshot dir and the
// owner-only copy.
func writeBackup(root, backup string, data []byte) error {
	rel, err := filepath.Rel(root, filepath.Dir(backup))
	if err != nil {
		return err
	}
	cur := root
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "." || seg == "" {
			continue
		}
		cur = filepath.Join(cur, seg)
		if err := os.Mkdir(cur, dirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("filemerge: create snapshot dir: %w", bare(err))
		}
		if err := perm.EnsureDir(cur); err != nil {
			return fmt.Errorf("filemerge: secure snapshot dir: %w", err)
		}
	}
	if err := writeSynced(backup, data, fileMode); err != nil {
		return err
	}
	if err := perm.EnsureFile(backup); err != nil {
		return fmt.Errorf("filemerge: secure snapshot: %w", err)
	}
	return nil
}

func newSnapshotDir(home string) (string, error) {
	root := filepath.Join(home, "backups")
	if err := os.MkdirAll(root, dirMode); err != nil {
		return "", fmt.Errorf("filemerge: create backup dir: %w", bare(err))
	}
	if err := perm.EnsureDir(root); err != nil {
		return "", fmt.Errorf("filemerge: secure backup dir: %w", err)
	}
	base := filepath.Join(root, snapshotClock().UTC().Format(backupTimeFormat))
	dir := base
	for i := 1; ; i++ {
		err := os.Mkdir(dir, dirMode)
		if err == nil {
			if err := perm.EnsureDir(dir); err != nil {
				_ = os.RemoveAll(dir)
				return "", fmt.Errorf("filemerge: secure backup dir: %w", err)
			}
			return dir, nil
		}
		if !errors.Is(err, os.ErrExist) || i > 999 {
			return "", fmt.Errorf("filemerge: create backup dir: %w", bare(err))
		}
		dir = fmt.Sprintf("%s-%03d", base, i)
	}
}

// statTarget Lstats path and refuses symlinks, reparse points and anything
// that is not a regular file. A missing file returns an error matching
// os.ErrNotExist.
func statTarget(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fail(fmt.Errorf("filemerge: stat: %w", bare(err)), path)
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fail(ErrSymlink, path)
	}
	if !info.Mode().IsRegular() {
		return nil, fail(ErrNotRegular, path)
	}
	return info, nil
}
