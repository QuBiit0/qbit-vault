//go:build windows

package runner

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestRunWithCmdShell(t *testing.T) {
	s := spec(t, nil)
	s.Shell = ShellCmd
	s.Command = `echo "hello world" & exit /b 3`
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || !strings.Contains(res.Stdout, "hello world") {
		t.Fatalf("exit %d out %q", res.ExitCode, res.Stdout)
	}
}

func TestRunWithPwshShell(t *testing.T) {
	if _, err := exec.LookPath("pwsh"); err != nil {
		if _, err := exec.LookPath("powershell"); err != nil {
			t.Skip("PowerShell not available")
		}
	}
	s := spec(t, nil)
	s.Shell = ShellPwsh
	s.Command = `Write-Output 'hello world'; exit 4`
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 4 || !strings.Contains(res.Stdout, "hello world") {
		t.Fatalf("exit %d out %q", res.ExitCode, res.Stdout)
	}
}
