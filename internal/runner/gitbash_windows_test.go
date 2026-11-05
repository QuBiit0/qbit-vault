//go:build windows

package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

func isWSLPath(p string) bool {
	low := strings.ToLower(filepath.ToSlash(p))
	return strings.Contains(low, "/windows/system32/") || strings.Contains(low, "/windows/sysnative/") || strings.Contains(low, "/windowsapps/")
}

// gitRoot is the Git for Windows install of this machine, from git.exe.
func gitRoot(t *testing.T) string {
	t.Helper()
	g, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git for Windows not available")
	}
	for dir := filepath.Dir(g); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "bin", "bash.exe")); err == nil {
			return dir
		}
	}
	t.Skip("Git for Windows has no bin\bash.exe here")
	return ""
}

func system32() string { return filepath.Join(os.Getenv("SystemRoot"), "System32") }

// onlyGitCmdOnPath is the usual Git for Windows install: git.exe is on PATH
// (…\Git\cmd) but bash.exe is not.
func onlyGitCmdOnPath(t *testing.T) string {
	root := gitRoot(t)
	t.Setenv("PATH", filepath.Join(root, "cmd")+";"+system32())
	return root
}

// noGit hides every Git for Windows location the lookup knows.
func noGit(t *testing.T) {
	t.Helper()
	empty := t.TempDir()
	t.Setenv("PATH", system32())
	for _, k := range []string{"ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LocalAppData"} {
		t.Setenv(k, empty)
	}
}

func TestShellsNeverResolveToWSL(t *testing.T) {
	for _, sh := range []Shell{ShellAuto, ShellSh, ShellBash} {
		path, _, err := buildArgv(sh, "true")
		if err == nil && isWSLPath(path) {
			t.Errorf("%s resolved to %s", sh, path)
		}
	}
	// A WindowsApps alias on PATH is the WSL launcher too.
	fake := filepath.Join(t.TempDir(), "WindowsApps")
	if err := os.MkdirAll(fake, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"bash.exe", "sh.exe"} {
		if err := os.WriteFile(filepath.Join(fake, n), []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	noGit(t)
	t.Setenv("PATH", fake+";"+system32())
	for _, sh := range []Shell{ShellSh, ShellBash} {
		if path, _, err := buildArgv(sh, "true"); err == nil {
			t.Errorf("%s resolved to %s with only a WindowsApps alias", sh, path)
		}
	}
}

func TestGitBashIsFoundFromGitOnPath(t *testing.T) {
	root := onlyGitCmdOnPath(t)
	for _, tt := range []struct {
		sh   Shell
		file string
	}{{ShellBash, "bash.exe"}, {ShellSh, "sh.exe"}, {ShellAuto, "bash.exe"}} {
		path, args, err := buildArgv(tt.sh, "echo hi")
		if err != nil {
			t.Fatalf("%s: %v", tt.sh, err)
		}
		if !strings.EqualFold(path, filepath.Join(root, "bin", tt.file)) || args[0] != "-c" {
			t.Errorf("%s: %q %q, want %s", tt.sh, path, args, filepath.Join(root, "bin", tt.file))
		}
	}
	if !PosixShellAvailable() {
		t.Error("PosixShellAvailable is false with Git installed")
	}
	if Resolve(ShellAuto) != ShellBash {
		t.Errorf("auto resolves to %q", Resolve(ShellAuto))
	}
}

func TestWithoutGitThereIsNoPosixShell(t *testing.T) {
	noGit(t)
	if PosixShellAvailable() {
		t.Error("PosixShellAvailable is true without Git")
	}
	for _, sh := range []Shell{ShellSh, ShellBash} {
		if _, _, err := buildArgv(sh, "true"); !errors.Is(err, ErrShellUnavailable) {
			t.Errorf("%s: %v", sh, err)
		}
	}
	if got := Resolve(ShellAuto); got != ShellCmd {
		t.Errorf("auto resolves to %q, want cmd", got)
	}
}

// A bare `bash` typed inside a cmd or pwsh command reaches Git's bash, not the
// WSL launcher that sits earlier in the system directory.
func TestBareBashUnderCmdResolvesToGit(t *testing.T) {
	root := onlyGitCmdOnPath(t)
	s := spec(t, nil)
	s.Shell = ShellCmd
	s.Command = "where bash"
	s.Stdin = strings.NewReader("")
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.TrimSpace(strings.SplitN(nl(res.Stdout), "\n", 2)[0])
	if !strings.EqualFold(first, filepath.Join(root, "bin", "bash.exe")) {
		t.Fatalf("bash resolves to %q (exit %d), want Git's", first, res.ExitCode)
	}
}

func nl(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// S6: `sh -c 'printf "%s" ...'` through the runner on Windows keeps its
// format and its quotes. The loss seen in dogfood came from joining argv
// words without quoting them (internal/cli), not from the runner.
func TestRealShPrintfFormatThroughRunner(t *testing.T) {
	onlyGitCmdOnPath(t)
	value := "TESTSECRET_s6_123456789"
	for _, tt := range []struct{ command, want string }{
		{`sh -c 'printf "%s" "$QBV_S6" | wc -c'`, strconv.Itoa(len(value))},
		{`bash -c 'printf "%s|%s" a b'`, "a|b"},
		{`printf "%s" "$QBV_S6" | wc -c`, strconv.Itoa(len(value))},
	} {
		for _, sh := range []Shell{ShellAuto, ShellSh, ShellBash} {
			s := spec(t, map[string]secret.Secret{"QBV_S6": secret.New("S6", []byte(value))})
			s.Shell = sh
			s.Command = tt.command
			s.Stdin = strings.NewReader("")
			res, err := Run(context.Background(), s)
			if err != nil || strings.TrimSpace(res.Stdout) != tt.want {
				t.Errorf("%s %q: out %q err %v (stderr %q), want %q", sh, tt.command, res.Stdout, err, res.Stderr, tt.want)
			}
		}
	}
}
