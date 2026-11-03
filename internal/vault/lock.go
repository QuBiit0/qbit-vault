package vault

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

const lockFile = "vault.lock"

// ErrLocked means another process (or handle) held the vault lock for the
// whole bounded wait. Its message carries no path or name.
var ErrLocked = errors.New("vault is busy")

var (
	// lockTimeout bounds how long an operation waits for the lock.
	lockTimeout = 5 * time.Second
	// lockStaleAfter is the age after which a lock file is presumed to be
	// left by a crashed process and is broken once.
	lockStaleAfter = 30 * time.Second
	lockPoll       = 10 * time.Millisecond
)

// Windows errors that mean "someone else has the file right now" and are
// worth retrying: ERROR_ACCESS_DENIED (also what a delete-pending file
// reports), ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION.
var windowsTransient = []syscall.Errno{5, 32, 33}

// isTransientFS reports whether err is a transient sharing error from the
// file system. It is only ever true on Windows.
var isTransientFS = func(err error) bool {
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

// acquireLock takes the exclusive cross-process lock for home by creating
// home/vault.lock with O_EXCL. The file holds the pid and an RFC3339 time.
// A lock file older than lockStaleAfter is assumed abandoned and is removed
// once per acquisition; a live holder that runs longer than that loses its
// lock, which is accepted because every critical section is a few file
// writes. The returned func releases the lock and is safe to defer.
func acquireLock(home string) (func(), error) {
	path := filepath.Join(home, lockFile)
	var tok [4]byte
	_, _ = rand.Read(tok[:])
	content := fmt.Sprintf("%d\n%s\n%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339), hex.EncodeToString(tok[:]))
	deadline := time.Now().Add(lockTimeout)
	broke := false
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
		if err == nil {
			_, werr := f.WriteString(content)
			cerr := f.Close()
			if werr != nil || cerr != nil {
				_ = os.Remove(path)
				return nil, errors.New("vault: write lock file")
			}
			if err := secureFile(path, "lock file"); err != nil {
				_ = os.Remove(path)
				return nil, err
			}
			return func() { releaseLock(path, content) }, nil
		}
		switch {
		case errors.Is(err, os.ErrExist):
			if info, serr := os.Stat(path); serr == nil && !broke && time.Since(info.ModTime()) > lockStaleAfter {
				broke = true
				_ = os.Remove(path)
				continue
			}
		case errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("vault: lock: %w", os.ErrNotExist)
		case isTransientFS(err):
		default:
			return nil, errors.New("vault: cannot create lock file")
		}
		if time.Now().After(deadline) {
			return nil, ErrLocked
		}
		time.Sleep(lockPoll)
	}
}

// releaseLock removes the lock file only if it is still ours, so a lock
// broken as stale and re-taken by someone else is not deleted from under them.
func releaseLock(path, content string) {
	for range 20 {
		if b, err := os.ReadFile(path); err == nil && string(b) != content {
			return
		}
		err := os.Remove(path)
		if err == nil || errors.Is(err, os.ErrNotExist) || !isTransientFS(err) {
			return
		}
		time.Sleep(lockPoll)
	}
}
