package filemerge

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

var (
	// beforeRename is a test seam that runs after the temp file is durable
	// and before it replaces the target.
	beforeRename = func(tmp, target string) error { return nil }
	// renameFile is the rename primitive; tests replace it to inject failures.
	renameFile = os.Rename
	// renameBudget bounds the backoff spent retrying a transient rename failure.
	renameBudget = 2 * time.Second
)

// windowsTransient: ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION and
// ERROR_LOCK_VIOLATION, which mean another process briefly holds the file.
var windowsTransient = []syscall.Errno{5, 32, 33}

func isTransientFS(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	for _, t := range windowsTransient {
		if errno == t {
			return true
		}
	}
	return false
}

// writeAtomic replaces path with data: temp file in the same directory,
// fsync, rename, fsync of the directory. The original is never open for
// writing, so a failure at any step leaves it intact and removes the temp
// file. An existing file keeps its permission bits; a new one is 0600 and
// its missing parent directories 0700. A symlink or non-regular target is
// refused (see statTarget): a link is never silently replaced by a regular
// file and never followed to a place outside the intended path.
func writeAtomic(path string, data []byte) error {
	mode := os.FileMode(fileMode)
	info, err := statTarget(path)
	switch {
	case err == nil:
		mode = info.Mode().Perm()
	case errors.Is(err, os.ErrNotExist):
	default:
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fail(fmt.Errorf("filemerge: create directory: %w", bare(err)), path)
	}
	var sfx [4]byte
	if _, err := rand.Read(sfx[:]); err != nil {
		return fail(errors.New("filemerge: random source failed"), path)
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.qbit-tmp.%d.%s", filepath.Base(path), os.Getpid(), hex.EncodeToString(sfx[:])))
	if err := writeSynced(tmp, data, fileMode); err != nil {
		_ = os.Remove(tmp)
		return fail(err, path)
	}
	if mode != fileMode && runtime.GOOS != "windows" {
		if err := os.Chmod(tmp, mode); err != nil {
			_ = os.Remove(tmp)
			return fail(fmt.Errorf("filemerge: set mode: %w", bare(err)), path)
		}
	}
	if err := beforeRename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fail(err, path)
	}
	if err := renameWithRetry(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fail(fmt.Errorf("filemerge: replace file: %w", bare(err)), path)
	}
	if runtime.GOOS != "windows" {
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}

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

func writeSynced(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("filemerge: create temp file: %w", bare(err))
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("filemerge: write temp file: %w", bare(err))
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("filemerge: sync temp file: %w", bare(err))
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("filemerge: close temp file: %w", bare(err))
	}
	return nil
}
