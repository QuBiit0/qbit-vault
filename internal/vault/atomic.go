package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	defaultBackupsKeep = 20
	backupTimeFormat   = "20060102T150405.000000000Z"
	dirMode            = 0o700
	fileMode           = 0o600
)

var (
	// beforeRename is a test seam that runs after the temp file is durable
	// and before it replaces the target.
	beforeRename = func(tmp, target string) error { return nil }
	// renameFile is the rename primitive; tests replace it to inject
	// sharing violations.
	renameFile = os.Rename
	// renameBudget bounds the total backoff spent retrying a transient
	// rename failure.
	renameBudget = 2 * time.Second
	// snapshotClock names snapshot directories; tests pin it.
	snapshotClock = time.Now
)

// bare strips the path-bearing wrapper of an os error so messages carry the
// errno text only; callers add the file name themselves.
func bare(err error) error {
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// writeAtomic snapshots and replaces a single file, then prunes. A vault
// save does not use it: it snapshots both of its files together (see
// store.savePair). keep <= 0 means the default of 20 snapshots. The caller
// holds the vault lock.
func writeAtomic(home, name string, data []byte, keep int) error {
	if err := os.MkdirAll(home, dirMode); err != nil {
		return fmt.Errorf("vault: create home: %w", bare(err))
	}
	dir, err := snapshot(home, name)
	if err != nil {
		return err
	}
	if err := replaceFile(home, name, data); err != nil {
		removeSnapshot(dir)
		return err
	}
	return pruneBackups(filepath.Join(home, "backups"), keep)
}

// replaceFile is steps 2-4 of docs/STORAGE.md § Atomic writes and backups:
// temp file, fsync, rename over the target, fsync the directory. The caller
// holds the vault lock, which is what makes removing leftover temp files
// from a crashed save safe.
func replaceFile(home, name string, data []byte) error {
	if err := os.MkdirAll(home, dirMode); err != nil {
		return fmt.Errorf("vault: create home: %w", bare(err))
	}
	target := filepath.Join(home, name)
	cleanTemps(target)
	var sfx [4]byte
	if _, err := rand.Read(sfx[:]); err != nil {
		return errors.New("vault: random source failed")
	}
	tmp := fmt.Sprintf("%s.tmp.%d.%s", target, os.Getpid(), hex.EncodeToString(sfx[:]))
	if err := writeSynced(tmp, data); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := beforeRename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := renameWithRetry(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vault: replace %s: %w", name, bare(err))
	}
	if runtime.GOOS != "windows" {
		if d, err := os.Open(home); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}

// renameWithRetry renames tmp over target, retrying transient sharing
// violations (another process briefly holding the target open, as antivirus
// scanners and indexers do on Windows) with short backoff up to renameBudget.
func renameWithRetry(tmp, target string) error {
	deadline := time.Now().Add(renameBudget)
	wait := time.Millisecond
	for {
		err := renameFile(tmp, target)
		if err == nil || !isTransientFS(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(wait)
		wait = min(wait*2, 100*time.Millisecond)
	}
}

// cleanTemps removes temp files a crashed save left next to target. Only
// called under the vault lock, so none of them can belong to a live save.
func cleanTemps(target string) {
	// os.ReadDir plus a prefix match, not filepath.Glob: the home path may
	// contain glob metacharacters.
	dir, prefix := filepath.Dir(target), filepath.Base(target)+".tmp."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("vault: create temp file: %w", bare(err))
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("vault: write temp file: %w", bare(err))
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("vault: sync temp file: %w", bare(err))
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("vault: close temp file: %w", bare(err))
	}
	return nil
}

// snapshot copies the current version of each named file that exists into
// one new backups/<UTC timestamp>/ directory, so the copies form a consistent
// set, and returns that directory ("" when none of the files exist yet).
// Two snapshots on the same clock tick get a -NNN suffix instead of sharing
// a directory. On failure the directory it created is removed.
func snapshot(home string, names ...string) (string, error) {
	var dir string
	for _, name := range names {
		old, err := os.ReadFile(filepath.Join(home, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			removeSnapshot(dir)
			return "", fmt.Errorf("vault: read %s for backup: %w", name, bare(err))
		}
		if dir == "" {
			if dir, err = newSnapshotDir(home); err != nil {
				return "", err
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), old, fileMode); err != nil {
			removeSnapshot(dir)
			return "", fmt.Errorf("vault: write backup of %s: %w", name, bare(err))
		}
	}
	return dir, nil
}

func newSnapshotDir(home string) (string, error) {
	root := filepath.Join(home, "backups")
	if err := os.MkdirAll(root, dirMode); err != nil {
		return "", fmt.Errorf("vault: create backup dir: %w", bare(err))
	}
	base := filepath.Join(root, snapshotClock().UTC().Format(backupTimeFormat))
	dir := base
	for i := 1; ; i++ {
		err := os.Mkdir(dir, dirMode)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, os.ErrExist) || i > 999 {
			return "", fmt.Errorf("vault: create backup dir: %w", bare(err))
		}
		dir = fmt.Sprintf("%s-%03d", base, i)
	}
}

// removeSnapshot discards a snapshot directory made by a save that failed, so
// failures do not consume backup slots. A "" dir is a no-op.
func removeSnapshot(dir string) {
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

// pruneBackups keeps the newest keep snapshot directories. Names sort
// chronologically because the timestamp format is fixed-width UTC and the
// same-tick suffix is fixed-width too.
func pruneBackups(dir string, keep int) error {
	if keep <= 0 {
		keep = defaultBackupsKeep
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("vault: list backups: %w", bare(err))
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		if err := os.RemoveAll(filepath.Join(dir, names[0])); err != nil {
			return fmt.Errorf("vault: prune backups: %w", bare(err))
		}
		names = names[1:]
	}
	return nil
}
