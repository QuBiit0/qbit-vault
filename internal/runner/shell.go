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
		p, err := lookPosix("sh")
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

// lookBash finds bash: see lookPosix.
func lookBash() (string, error) { return lookPosix("bash") }

// lookPosix finds a POSIX shell, "bash" or "sh". On POSIX that is PATH. On
// Windows it is the first PATH entry that is not the WSL launcher (the system
// directories and the WindowsApps alias run the command inside a Linux guest
// that does not receive the injected environment), else Git for Windows'
// copy, found from git.exe on PATH or the usual install directories: Git's
// own install puts only its cmd directory on PATH, not the one with
// bash.exe. There is no WSL fallback.
func lookPosix(name string) (string, error) {
	if runtime.GOOS != "windows" {
		return exec.LookPath(name)
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if p := regularFile(dir, name+".exe"); p != "" && !isWSLShim(p) {
			return p, nil
		}
	}
	for _, root := range gitRoots() {
		if p := regularFile(filepath.Join(root, "bin"), name+".exe"); p != "" {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}

func regularFile(dir, file string) string {
	if dir == "" {
		return ""
	}
	p := filepath.Join(dir, file)
	if fi, err := os.Stat(p); err != nil || fi.IsDir() {
		return ""
	}
	return p
}

// isWSLShim reports whether p lives where Windows keeps its WSL launcher.
func isWSLShim(p string) bool {
	low := strings.ToLower(filepath.ToSlash(p))
	return strings.Contains(low, "/windows/system32/") || strings.Contains(low, "/windows/sysnative/") || strings.Contains(low, "/windowsapps/")
}

// gitRoots lists the Git for Windows installs that have bin/bash.exe: the
// ones git.exe on PATH belongs to first, then the default locations.
func gitRoots() []string {
	var roots []string
	add := func(dir string) {
		if dir == "" || regularFile(filepath.Join(dir, "bin"), "bash.exe") == "" {
			return
		}
		for _, r := range roots {
			if strings.EqualFold(r, dir) {
				return
			}
		}
		roots = append(roots, dir)
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if regularFile(dir, "git.exe") == "" {
			continue
		}
		// The install root is up to three levels above git.exe: cmd,
		// bin, mingw64/bin and usr/bin all live under it.
		for d, n := dir, 0; n < 3; d, n = filepath.Dir(d), n+1 {
			add(d)
		}
	}
	for _, env := range []string{"ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"} {
		if base := os.Getenv(env); base != "" {
			add(filepath.Join(base, "Git"))
		}
	}
	if base := os.Getenv("LocalAppData"); base != "" {
		add(filepath.Join(base, "Programs", "Git"))
	}
	return roots
}

// withShellOnPath puts the directory of Git's bash and sh first on the
// child's PATH (Windows), so a bare `bash` or `sh` in the command, under any
// shell, runs Git's and never the WSL launcher. Without Git it changes
// nothing: callers refuse such commands first (PosixShellAvailable).
func withShellOnPath(env []string) []string {
	if runtime.GOOS != "windows" {
		return env
	}
	roots := gitRoots()
	if len(roots) == 0 {
		return env
	}
	bin := filepath.Join(roots[0], "bin")
	for i, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" && strings.EqualFold(k, "PATH") {
			env[i] = k + "=" + bin + string(os.PathListSeparator) + v
			return env
		}
	}
	return append(env, "PATH="+bin)
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

// PosixShellAvailable reports whether a bare `bash` or `sh` can be resolved
// to a real POSIX shell (always on POSIX).
func PosixShellAvailable() bool {
	_, err := lookBash()
	return err == nil
}
