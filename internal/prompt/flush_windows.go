package prompt

import (
	"os"

	"golang.org/x/sys/windows"
)

// flushInput discards what the user typed or pasted that nobody read, so the
// next program on the console does not run it.
func flushInput(f *os.File) {
	_ = windows.FlushConsoleInputBuffer(windows.Handle(f.Fd()))
}
