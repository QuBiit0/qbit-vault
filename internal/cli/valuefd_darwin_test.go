package cli

import (
	"syscall"
	"testing"
)

// pollerFD opens a kqueue, the descriptor the Go runtime's poller uses on
// macOS (fd 3 when the parent passed nothing there).
func pollerFD(t *testing.T) (int, bool) {
	t.Helper()
	fd, err := syscall.Kqueue()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd, true
}
