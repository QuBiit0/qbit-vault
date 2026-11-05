//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// D1 (dogfood 1): with no Git for Windows a command that names bash or sh is
// refused with one fixed message, before anything is claimed or started; the
// WSL launcher in System32 is never the fallback.
func TestExecBareBashWithoutGitIsRefusedAndKeepsTheOnceGrant(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "once")

	empty := t.TempDir()
	sys32 := filepath.Join(os.Getenv("SystemRoot"), "System32")
	t.Setenv("PATH", sys32)
	for _, k := range []string{"ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LocalAppData"} {
		t.Setenv(k, empty)
	}
	want := "error: " + msgNoPosixShell + "\n"
	for _, cmd := range []string{`bash -c "echo hi"`, `echo hi | sh`, `env X=1 bash`} {
		code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, cmd)...)
		if code != 3 || out != "" || errs != want {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", cmd, code, out, errs)
		}
	}
	if n := countStarted(w.auditEvents("exec")); n != 0 {
		t.Fatalf("%d started records for refused commands", n)
	}

	// An absolute path is the user's explicit choice and is not second-guessed
	// here, and a command without bash or sh is not affected.
	run := child(t, "mark", marker(t), 0)
	w.onceStillWorks(sessA, "GITHUB_TOKEN", run)
}
