package prompt

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// detach keeps the helper from opening a console window of its own. The
// dialog is a GUI window and is unaffected (HideWindow is not set: it would
// hide the dialog's first window too).
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
}

// interactiveSession reports whether this process runs in a user session
// rather than session 0, where services live and no dialog can be seen.
func interactiveSession() bool {
	var id uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &id); err != nil {
		return false
	}
	return id != 0
}
