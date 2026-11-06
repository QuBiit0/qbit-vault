//go:build linux

package cli

import (
	"errors"

	"golang.org/x/sys/unix"
)

// isEventPoller reports whether fd is an epoll instance, the Go runtime's
// poller on Linux. It asks the kernel rather than trusting that fstat reports
// no file type for one: removing a descriptor that was never added fails with
// ENOENT on an epoll and with EINVAL on anything else. The probe descriptor
// is a fresh pipe, so nothing registered is touched, and epoll_wait (which
// could steal the runtime's edge-triggered events) is never called.
func isEventPoller(fd int) bool {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		return false
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	err := unix.EpollCtl(fd, unix.EPOLL_CTL_DEL, p[0], &unix.EpollEvent{})
	return errors.Is(err, unix.ENOENT)
}
