package cli

import (
	"syscall"
	"testing"
)

// pollerFD opens an epoll instance, the descriptor the Go runtime's poller
// uses on Linux.
func pollerFD(t *testing.T) (int, bool) {
	t.Helper()
	fd, err := syscall.EpollCreate1(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd, true
}
