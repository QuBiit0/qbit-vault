//go:build !windows

package runner

import (
	"os"
	"syscall"
)

// selfKill ends the helper by SIGKILL, as the OOM killer would.
func selfKill() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }
