//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package cli

import "syscall"

// isEventPoller reports whether fd is a kqueue. kevent with no changes, no
// room for events and a zero timeout returns at once and only succeeds on a
// kqueue; on a pipe, file or socket it fails (EBADF). It changes nothing.
func isEventPoller(fd int) bool {
	_, err := syscall.Kevent(fd, nil, nil, &syscall.Timespec{})
	return err == nil
}
