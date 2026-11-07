package keychain

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"
)

var (
	// renameFile is the rename primitive; tests replace it to inject sharing
	// violations.
	renameFile = os.Rename
	// renameBudget bounds the total backoff spent retrying a transient
	// rename failure.
	renameBudget = 2 * time.Second
)

// windowsTransient are the Windows errors that mean "someone else has the
// file right now": ERROR_ACCESS_DENIED (also what a delete-pending file
// reports), ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION.
var windowsTransient = []syscall.Errno{5, 32, 33}

// isTransientFS reports whether err is a transient sharing error from the
// file system. It is only ever true on Windows; tests replace it.
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

// renameWithRetry renames from over to, retrying transient sharing
// violations (antivirus scanners and indexers briefly holding a file open on
// Windows) with short backoff up to renameBudget.
func renameWithRetry(from, to string) error {
	deadline := time.Now().Add(renameBudget)
	wait := time.Millisecond
	for {
		err := renameFile(from, to)
		if err == nil || !isTransientFS(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(wait)
		wait = min(wait*2, 100*time.Millisecond)
	}
}
