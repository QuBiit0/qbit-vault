package codex_test

import (
	"errors"
	"os"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/hosts"
	"github.com/qbitdevz/qbit-vault/internal/hosts/codex"
)

// The hook command is a shell command line (the Codex docs have no argv
// form), so the executable is quoted for the shell: single quotes for
// `command` (sh) and a PowerShell call for `commandWindows`, the Windows-only
// override (odd/tasks/output-guard.md S10.1).
func TestHookCommandQuoting(t *testing.T) {
	for _, c := range []struct{ name, exe, posix, windows string }{
		{"plain", "/opt/qbit/bin/qbit-vault", "/opt/qbit/bin/qbit-vault", "& '/opt/qbit/bin/qbit-vault'"},
		{"space", "/opt/Q Bit/qbit-vault", "'/opt/Q Bit/qbit-vault'", "& '/opt/Q Bit/qbit-vault'"},
		{"double quote", `/opt/a"b/qbit-vault`, `'/opt/a"b/qbit-vault'`, `& '/opt/a"b/qbit-vault'`},
		{"dollar and backtick", "/opt/$HOME/`x`/qbit-vault", "'/opt/$HOME/`x`/qbit-vault'", "& '/opt/$HOME/`x`/qbit-vault'"},
		{"percent and bang", "/opt/%PATH%/a!b/qbit-vault", "'/opt/%PATH%/a!b/qbit-vault'", "& '/opt/%PATH%/a!b/qbit-vault'"},
		{"shell syntax", "/opt/a&b (x);y|z<>/qbit-vault", "'/opt/a&b (x);y|z<>/qbit-vault'", "& '/opt/a&b (x);y|z<>/qbit-vault'"},
		{"single quote", "/opt/it's/qbit-vault", `'/opt/it'\''s/qbit-vault'`, "& '/opt/it''s/qbit-vault'"},
		{"curly quotes", "/opt/\u2018x\u2019/qbit-vault", "'/opt/\u2018x\u2019/qbit-vault'", "& '/opt/\u2018\u2018x\u2019\u2019/qbit-vault'"},
		{"non-ASCII", "/opt/ñandú/qbit-vault", "'/opt/ñandú/qbit-vault'", "& '/opt/ñandú/qbit-vault'"},
		{"newline", "/opt/a\nb/qbit-vault", "'/opt/a\nb/qbit-vault'", "& '/opt/a\nb/qbit-vault'"},
		{"drive path", `C:\Program Files\Q Bit\qbit-vault.exe`, `'C:\Program Files\Q Bit\qbit-vault.exe'`, `& 'C:\Program Files\Q Bit\qbit-vault.exe'`},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.host = codex.NewWithExe(c.exe)
			r.apply()
			es := ours(readHooks(t, r.read(r.hooksFile())))
			if len(es) != 2 {
				t.Fatalf("hooks: %+v", es)
			}
			for _, e := range es {
				sub := map[string]string{"PostToolUse": "post-bash", "PreToolUse": "pre-write"}[e.event]
				if want := c.posix + " hook " + sub + " --host codex"; e.command != want {
					t.Errorf("command = %q, want %q", e.command, want)
				}
				if want := c.windows + " hook " + sub + " --host codex"; e.windows != want {
					t.Errorf("commandWindows = %q, want %q", e.windows, want)
				}
			}
			if err := checks(r)["hooks"]; err != nil {
				t.Errorf("a fresh registration drifts: %v", err)
			}
		})
	}
}

// A path hooks.json cannot hold at all (not valid UTF-8, or a NUL) is refused
// with a typed error that names the problem, nothing is written, and the
// check says the same (S10.1).
func TestHookCommandRefusesAPathItCannotCarry(t *testing.T) {
	for _, bad := range []string{"/opt/a\xffb/qbit-vault", "/opt/a\x00b/qbit-vault"} {
		r := newRig(t)
		r.host = codex.NewWithExe(bad)
		res := hosts.Apply(r.env, []hosts.Adapter{r.host})
		if !errors.Is(res[0].Err(), codex.ErrHookPath) || res[0].FailedStep() != "hooks" {
			t.Fatalf("%q: %+v", bad, res[0])
		}
		if _, err := os.Stat(r.hooksFile()); err == nil {
			t.Fatalf("%q: hooks.json created", bad)
		}
	}
}
