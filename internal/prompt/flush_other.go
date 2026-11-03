//go:build !linux && !windows

package prompt

import (
	"os"

	"golang.org/x/sys/unix"
)

// flushInput discards what the user typed or pasted that nobody read, so the
// next program on the terminal does not run it.
func flushInput(f *os.File) {
	_ = unix.IoctlSetPointerInt(int(f.Fd()), unix.TIOCFLUSH, 1) // FREAD
}
