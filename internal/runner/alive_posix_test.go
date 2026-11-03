//go:build !windows

package runner

import "syscall"

// alive reports whether the process with this pid is still running.
func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }
