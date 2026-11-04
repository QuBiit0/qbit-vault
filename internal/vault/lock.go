package vault

import (
	"errors"
	"runtime"
	"syscall"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/lockfile"
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

// acquireLock takes the exclusive cross-process lock for home (see
// lockfile.Acquire). A lock held for the whole wait is ErrLocked.
func acquireLock(home string) (func(), error) {
	release, err := lockfile.Acquire(home, lockFile, lockfile.Options{
		Timeout: lockTimeout, StaleAfter: lockStaleAfter, Poll: lockPoll,
	})
	if errors.Is(err, lockfile.ErrBusy) {
		return nil, ErrLocked
	}
	return release, err
}

// Windows errors that mean "someone else has the file right now" and are
// worth retrying: ERROR_ACCESS_DENIED (also what a delete-pending file
// reports), ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION.
var windowsTransient = []syscall.Errno{5, 32, 33}

// isTransientFS reports whether err is a transient sharing error from the
// file system. It is only ever true on Windows. The atomic rename retry uses
// it; tests replace it.
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
