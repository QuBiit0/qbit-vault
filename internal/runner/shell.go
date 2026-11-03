package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// buildArgv returns the shell program and its arguments for command (L5).
// The command is the last argument: values never appear in it.
func buildArgv(shell Shell, command string) (path string, args []string, err error) {
	if shell == "" {
		shell = ShellAuto
	}
	switch shell {
	case ShellAuto:
		if runtime.GOOS != "windows" {
			return "/bin/sh", []string{"-c", command}, nil
		}
		if p, err := lookBash(); err == nil {
			return p, []string{"-c", command}, nil
		}
		return cmdExe(command)
	case ShellSh:
		if runtime.GOOS != "windows" {
			return "/bin/sh", []string{"-c", command}, nil
		}
		p, err := exec.LookPath("sh")
		if err != nil {
			return "", nil, ErrShellUnavailable
		}
		return p, []string{"-c", command}, nil
	case ShellBash:
		p, err := lookBash()
		if err != nil {
			return "", nil, ErrShellUnavailable
		}
		return p, []string{"-c", command}, nil
	case ShellCmd:
		if runtime.GOOS != "windows" {
			return "", nil, ErrShellUnavailable
		}
		return cmdExe(command)
	case ShellPwsh:
		p, err := exec.LookPath("pwsh")
		if err != nil && runtime.GOOS == "windows" {
			p, err = exec.LookPath("powershell")
		}
		if err != nil {
			return "", nil, ErrShellUnavailable
		}
		return p, []string{"-NoProfile", "-NonInteractive", "-Command", command}, nil
	}
	return "", nil, ErrUnknownShell
}

func cmdExe(command string) (string, []string, error) {
	p := os.Getenv("ComSpec")
	if p == "" {
		var err error
		if p, err = exec.LookPath("cmd.exe"); err != nil {
			return "", nil, ErrShellUnavailable
		}
	}
	return p, []string{"/d", "/s", "/c", command}, nil
}

// lookBash finds bash on PATH. On Windows it skips the WSL launcher in the
// system directory: it would run the command inside a Linux guest that does
// not receive the injected environment.
func lookBash() (string, error) {
	if runtime.GOOS != "windows" {
		return exec.LookPath("bash")
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, "bash.exe")
		if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			continue
		}
		low := strings.ToLower(filepath.ToSlash(p))
		if strings.Contains(low, "/windows/system32/") || strings.Contains(low, "/windows/sysnative/") {
			continue
		}
		return p, nil
	}
	return "", exec.ErrNotFound
}

// CheckShell reports whether shell can be used on this system, without
// running anything.
func CheckShell(shell Shell) error {
	_, _, err := buildArgv(shell, "true")
	return err
}

// Resolve returns the shell that will actually interpret a command: auto
// (or empty) becomes sh, bash or cmd per L5; any other value is returned as
// given. Callers use it to pick the grammar that applies to the command.
func Resolve(shell Shell) Shell {
	if shell != ShellAuto && shell != "" {
		return shell
	}
	if runtime.GOOS != "windows" {
		return ShellSh
	}
	if _, err := lookBash(); err == nil {
		return ShellBash
	}
	return ShellCmd
}
