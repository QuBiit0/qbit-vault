package cli

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
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

// terminalFD opens the terminal side of a pseudo-terminal. On macOS the
// /dev/ptmx side does not answer as a terminal; the slave it names does, and
// that is what a host would hand a child.
func terminalFD(t *testing.T) (int, bool) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return 0, false
	}
	t.Cleanup(func() { m.Close() })
	fd := m.Fd()
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.TIOCPTYGRANT), 0); e != 0 {
		return 0, false
	}
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.TIOCPTYUNLK), 0); e != 0 {
		return 0, false
	}
	var name [128]byte
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		return 0, false
	}
	n := bytes.IndexByte(name[:], 0)
	if n <= 0 {
		return 0, false
	}
	s, err := os.OpenFile(string(name[:n]), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return 0, false
	}
	t.Cleanup(func() { s.Close() })
	return int(s.Fd()), true
}
