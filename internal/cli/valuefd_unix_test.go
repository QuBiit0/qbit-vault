//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// The value descriptor must be something a host can hand a child: a pipe, a
// socket, a regular file or a terminal. Anything else (a directory, a closed
// number, the Go runtime's own poller) is refused before any *os.File wraps
// it, so no finalizer can close a descriptor that is not ours.
func TestValueFDKindAcceptsWhatAHostCanPass(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if !valueFDKindOK(int(w.Fd())) {
		t.Error("a pipe was refused")
	}
	f, err := os.CreateTemp(t.TempDir(), "value")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !valueFDKindOK(int(f.Fd())) {
		t.Error("a regular file was refused")
	}
}

func TestValueFDKindRefusesWhatAHostCannotPass(t *testing.T) {
	dir, err := os.Open(filepath.Clean(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if valueFDKindOK(int(dir.Fd())) {
		t.Error("a directory was accepted")
	}
	fd, err := syscall.Dup(int(dir.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(fd); err != nil {
		t.Fatal(err)
	}
	if valueFDKindOK(fd) {
		t.Error("a closed descriptor was accepted")
	}
	if pfd, ok := pollerFD(t); ok && valueFDKindOK(pfd) {
		t.Error("an event poller (the Go runtime's own kind of descriptor) was accepted")
	}
}

// A descriptor that is not a host's channel (here an event poller, which is
// what fd 3 is on macOS when the parent passed nothing) is refused as "no fd
// 3", and is still open afterwards: nothing wrapped it in an *os.File whose
// finalizer would close it.
func TestOpenValueFDRefusesAPollerAndLeavesItOpen(t *testing.T) {
	pfd, ok := pollerFD(t)
	if !ok {
		t.Skip("no event poller to test with on this platform")
	}
	w, err := openValueFDNum(pfd)
	if w != nil || err != errNoFD3 {
		if w != nil {
			_ = w.Close()
		}
		t.Fatalf("openValueFDNum(poller) = %v, %v; want nil, errNoFD3", w, err)
	}
	runtime.GC()
	runtime.GC()
	var st syscall.Stat_t
	if err := syscall.Fstat(pfd, &st); err != nil {
		t.Fatalf("the poller descriptor was closed: %v", err)
	}
}
