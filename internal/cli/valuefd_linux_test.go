package cli

import (
	"os"
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

// The epoll probe asks the kernel instead of trusting that fstat reports no
// file type for an epoll descriptor.
func TestIsEventPollerProbesEpoll(t *testing.T) {
	pfd, _ := pollerFD(t)
	if !isEventPoller(pfd) {
		t.Error("an epoll descriptor was not recognized")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isEventPoller(int(w.Fd())) {
		t.Error("a pipe was taken for an epoll descriptor")
	}
}

// terminalFD opens a pseudo-terminal; on Linux the /dev/ptmx side already
// answers as a terminal.
func terminalFD(t *testing.T) (int, bool) {
	t.Helper()
	f, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return 0, false
	}
	t.Cleanup(func() { f.Close() })
	return int(f.Fd()), true
}
