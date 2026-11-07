// Package lockfile is the cross-process exclusive lock behind the vault and
// the audit log: a file created with O_EXCL, a bounded wait, a stale-lock
// break and a release that only removes a lock that is still ours. Errors
// never contain the directory or the lock name.
package lockfile

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

	"github.com/QuBiit0/qbit-vault/internal/perm"
)

// ErrBusy means another process (or handle) held the lock for the whole
// bounded wait.
var ErrBusy = errors.New("lock is busy")

// Defaults used for zero fields of Options.
const (
	DefaultTimeout    = 5 * time.Second
	DefaultStaleAfter = 30 * time.Second
	DefaultPoll       = 10 * time.Millisecond
)

// Options tunes Acquire. Zero fields take the defaults.
type Options struct {
	// Timeout bounds how long Acquire waits for the lock.
	Timeout time.Duration
	// StaleAfter is the age after which a lock file is presumed to be left
	// by a crashed process and is broken once.
	StaleAfter time.Duration
	// Poll is the pause between attempts.
	Poll time.Duration
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.StaleAfter <= 0 {
		o.StaleAfter = DefaultStaleAfter
	}
	if o.Poll <= 0 {
		o.Poll = DefaultPoll
	}
	return o
}

// Windows errors that mean "someone else has the file right now" and are
// worth retrying: ERROR_ACCESS_DENIED (also what a delete-pending file
// reports), ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION.
var windowsTransient = []syscall.Errno{5, 32, 33}

// isTransientFS reports whether err is a transient sharing error from the
// file system. It is only ever true on Windows.
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

// Acquire takes the exclusive lock dir/name by creating it with O_EXCL. The
// file holds the pid and an RFC3339 time. A lock file older than
// opts.StaleAfter is assumed abandoned and is removed once per acquisition; a
// live holder that runs longer than that loses its lock, which is accepted
// because every critical section is a few file writes. The returned func
// releases the lock and is safe to defer. A missing dir is an error wrapping
// os.ErrNotExist; a lock held for the whole wait is ErrBusy.
func Acquire(dir, name string, opts Options) (release func(), err error) {
	opts = opts.withDefaults()
	path := filepath.Join(dir, name)
	var tok [4]byte
	_, _ = rand.Read(tok[:])
	content := fmt.Sprintf("%d\n%s\n%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339), hex.EncodeToString(tok[:]))
	deadline := time.Now().Add(opts.Timeout)
	broke := false
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, werr := f.WriteString(content)
			cerr := f.Close()
			if werr != nil || cerr != nil {
				_ = os.Remove(path)
				return nil, errors.New("lockfile: write lock file")
			}
			if err := perm.EnsureFile(path); err != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("lockfile: secure lock file: %w", err)
			}
			return func() { releaseLock(path, content, opts.Poll) }, nil
		}
		switch {
		case errors.Is(err, os.ErrExist):
			// Stale also when stamped further ahead than the stale age:
			// clock skew or a copied home, which would stay busy forever.
			if info, serr := os.Stat(path); serr == nil && !broke && stale(time.Since(info.ModTime()), opts.StaleAfter) {
				beforeBreak()
				if breakStale(path, opts.StaleAfter) {
					broke = true
					continue
				}
			}
		case errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("lockfile: %w", os.ErrNotExist)
		case isTransientFS(err):
		default:
			return nil, errors.New("lockfile: cannot create lock file")
		}
		if time.Now().After(deadline) {
			return nil, ErrBusy
		}
		time.Sleep(opts.Poll)
	}
}

// beforeBreak is a test seam that runs after a lock was judged stale and
// before it is broken, where another process can replace it.
var beforeBreak = func() {}

// breakStale removes the stale lock at path while holding path+".break",
// so two breakers cannot interleave, and re-checks the age under it: a lock
// another process broke and re-took since the caller looked is fresh and is
// left alone. While the break lock is held nobody can create path unless the
// stale file is gone, so the re-check and the removal cannot straddle a new
// lock. It reports whether the caller did the break (even if the file had
// already gone); false means someone else is breaking, so just wait. A break
// lock older than staleAfter is a breaker that crashed and is discarded.
func breakStale(path string, staleAfter time.Duration) bool {
	guard := path + ".break"
	f, err := os.OpenFile(guard, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if info, serr := os.Stat(guard); serr == nil && stale(time.Since(info.ModTime()), staleAfter) {
			_ = os.Remove(guard)
		}
		return false
	}
	_ = f.Close()
	defer func() { _ = os.Remove(guard) }()
	if info, err := os.Stat(path); err == nil && stale(time.Since(info.ModTime()), staleAfter) {
		_ = os.Remove(path)
	}
	return true
}

// stale reports whether a lock of this age (negative: stamped in the future)
// is abandoned.
func stale(age, after time.Duration) bool {
	return age > after || age < -after
}

// releaseLock removes the lock file only if it is still ours, so a lock
// broken as stale and re-taken by someone else is not deleted from under them.
func releaseLock(path, content string, poll time.Duration) {
	for range 20 {
		if b, err := os.ReadFile(path); err == nil && string(b) != content {
			return
		}
		err := os.Remove(path)
		if err == nil || errors.Is(err, os.ErrNotExist) || !isTransientFS(err) {
			return
		}
		time.Sleep(poll)
	}
}
