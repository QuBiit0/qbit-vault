//go:build windows

package runner

import (
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const createSuspended = 0x00000004

var procNtResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

// tree is a job object holding the child and everything it starts.
type tree struct{ job windows.Handle }

// prepare starts the child suspended, so it joins the job before it can start
// any process of its own, and builds the command line by hand for the shells
// that do not decode Go's argument quoting: cmd.exe takes the command
// verbatim, and bash/sh (MSYS, as in Git Bash) decode `\"` differently from
// the Windows rules, which loses quotes in commands such as `"gh" pr`.
func prepare(cmd *exec.Cmd, path string, args []string) {
	attr := &syscall.SysProcAttr{CreationFlags: createSuspended}
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "cmd.exe" && len(args) == 4 && args[0] == "/d":
		attr.CmdLine = `"` + path + `" /d /s /c "` + args[3] + `"`
	case (base == "bash.exe" || base == "sh.exe") && len(args) == 2 && args[0] == "-c":
		attr.CmdLine = `"` + path + `" -c ` + msysQuote(args[1])
	}
	cmd.SysProcAttr = attr
}

// msysQuote wraps s so that an MSYS program receives exactly s: inside double
// quotes it reads \\ as a backslash and \" as a quote, and nothing else is
// special.
func msysQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// attach assigns the suspended child to a kill-on-close job and resumes it.
func attach(cmd *exec.Cmd) (*tree, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME, false, uint32(cmd.Process.Pid))
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	if r, _, _ := procNtResumeProcess.Call(uintptr(h)); r != 0 {
		windows.CloseHandle(job)
		return nil, syscall.EINVAL
	}
	return &tree{job: job}, nil
}

// kill terminates every process of the job.
func (t *tree) kill() { _ = windows.TerminateJobObject(t.job, 1) }

// release closes the job; kill-on-close ends any descendant still running.
func (t *tree) release() { _ = windows.CloseHandle(t.job) }
