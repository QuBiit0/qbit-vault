package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

const (
	defaultBackupsKeep = 20
	backupTimeFormat   = "20060102T150405.000000000Z"
	dirMode            = 0o700
	fileMode           = 0o600
)

// beforeRename is a test seam that runs after the temp file is durable and
// before it replaces the target.
var beforeRename = func(tmp, target string) error { return nil }

// writeAtomic snapshots and replaces a single file, then prunes. A vault
// save does not use it: it snapshots both of its files together (see
// store.save). keep <= 0 means the default of 20 snapshots.
func writeAtomic(home, name string, data []byte, keep int) error {
	if err := os.MkdirAll(home, dirMode); err != nil {
		return fmt.Errorf("vault: create home: %w", err)
	}
	if err := snapshot(home, name); err != nil {
		return err
	}
	if err := replaceFile(home, name, data); err != nil {
		return err
	}
	return pruneBackups(filepath.Join(home, "backups"), keep)
}

// replaceFile is steps 2-4 of docs/STORAGE.md § Atomic writes and backups:
// temp file, fsync, rename over the target, fsync the directory.
func replaceFile(home, name string, data []byte) error {
	if err := os.MkdirAll(home, dirMode); err != nil {
		return fmt.Errorf("vault: create home: %w", err)
	}
	target := filepath.Join(home, name)
	tmp := fmt.Sprintf("%s.tmp.%d", target, os.Getpid())
	if err := writeSynced(tmp, data); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := beforeRename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vault: replace %s: %w", name, err)
	}
	if runtime.GOOS != "windows" {
		if d, err := os.Open(home); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("vault: create temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("vault: write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("vault: sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("vault: close temp file: %w", err)
	}
	return nil
}

// snapshot copies the current version of each named file that exists into
// one new backups/<UTC timestamp>/ directory, so the copies form a consistent
// set. Nothing is created when none of the files exist yet.
func snapshot(home string, names ...string) error {
	var dir string
	for _, name := range names {
		old, err := os.ReadFile(filepath.Join(home, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("vault: read %s for backup: %w", name, err)
		}
		if dir == "" {
			dir = filepath.Join(home, "backups", time.Now().UTC().Format(backupTimeFormat))
			if err := os.MkdirAll(dir, dirMode); err != nil {
				return fmt.Errorf("vault: create backup dir: %w", err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), old, fileMode); err != nil {
			return fmt.Errorf("vault: write backup of %s: %w", name, err)
		}
	}
	return nil
}

// pruneBackups keeps the newest keep snapshot directories. Names sort
// chronologically because the timestamp format is fixed-width UTC.
func pruneBackups(dir string, keep int) error {
	if keep <= 0 {
		keep = defaultBackupsKeep
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("vault: list backups: %w", err)
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
			return fmt.Errorf("vault: prune backups: %w", err)
		}
		names = names[1:]
	}
	return nil
}
