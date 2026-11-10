package prompt

import (
	"context"
	"strings"
	"testing"
	"time"
)

// wslEnv is a Linux process with the WSL markers asked for. helpers are the
// programs present at their fixed locations (see envOf).
func wslEnv(vars map[string]string, interop bool, helpers ...string) Env {
	e := envOf("linux", vars, helpers...)
	base := e.Exists
	e.Exists = func(p string) bool { return (interop && p == wslInteropPath) || base(p) }
	return e
}

func TestWSLPicksPowerShellBeforeLinuxHelpers(t *testing.T) {
	for _, tt := range []struct {
		name    string
		vars    map[string]string
		interop bool
	}{
		{"distro name, WSLg display", map[string]string{"WSL_DISTRO_NAME": "Ubuntu", "DISPLAY": ":0"}, false},
		{"distro name, no display", map[string]string{"WSL_DISTRO_NAME": "Ubuntu"}, false},
		{"interop only, no display", nil, true},
		{"interop only, wayland", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// zenity and kdialog are installed too: the Windows dialog still wins.
			tl, path := nativeFor(wslEnv(tt.vars, tt.interop, "powershell.exe", "zenity", "kdialog"))
			if tl == nil || tl.name() != "powershell" || path != wslPS {
				t.Fatalf("got %v %q", tl, path)
			}
		})
	}
}

func TestWSLWithoutTheHelperFallsBackAsBefore(t *testing.T) {
	wsl := map[string]string{"WSL_DISTRO_NAME": "Ubuntu"}
	display := map[string]string{"WSL_DISTRO_NAME": "Ubuntu", "DISPLAY": ":0"}
	for _, tt := range []struct {
		name string
		vars map[string]string
		on   []string
		want string
	}{
		{"zenity", display, []string{"zenity"}, "zenity"},
		{"kdialog", display, []string{"kdialog"}, "kdialog"},
		{"no display", wsl, []string{"zenity", "kdialog"}, ""},
		{"nothing", display, nil, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tl, _ := nativeFor(wslEnv(tt.vars, true, tt.on...))
			got := ""
			if tl != nil {
				got = tl.name()
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestLinuxOutsideWSLIsUnchanged(t *testing.T) {
	// The Windows helper path exists (a file at that path on a non-WSL box
	// proves nothing) but nothing says this is WSL: it is not used.
	for _, tt := range []struct {
		name string
		vars map[string]string
		on   []string
		want string
	}{
		{"display, helper path present", map[string]string{"DISPLAY": ":0"}, []string{"powershell.exe"}, ""},
		{"headless, helper path present", nil, []string{"powershell.exe", "zenity"}, ""},
		{"display, zenity", map[string]string{"DISPLAY": ":0"}, []string{"powershell.exe", "zenity"}, "zenity"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tl, _ := nativeFor(wslEnv(tt.vars, false, tt.on...))
			got := ""
			if tl != nil {
				got = tl.name()
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestWSLDoesNotNeedAnInteractiveSessionCheck(t *testing.T) {
	// Interactive is the Windows session-0 check; it must not gate WSL.
	e := wslEnv(map[string]string{"WSL_DISTRO_NAME": "Ubuntu"}, false, "powershell.exe")
	e.Interactive = func() bool { return false }
	if tl, _ := nativeFor(e); tl == nil || tl.name() != "powershell" {
		t.Fatalf("got %v", tl)
	}
	e.Getenv = func(k string) string {
		return map[string]string{"WSL_DISTRO_NAME": "Ubuntu", EnvBackend: "powershell"}[k]
	}
	if b, err := SelectWith(e); err != nil || b.Name() != "powershell" {
		t.Fatalf("forced: %v %v", b, err)
	}
}

func TestWSLQbitVaultPromptStillForces(t *testing.T) {
	vars := func(backend string) map[string]string {
		return map[string]string{"WSL_DISTRO_NAME": "Ubuntu", "DISPLAY": ":0", EnvBackend: backend}
	}
	if b, err := SelectWith(wslEnv(vars("tty"), true, "powershell.exe", "zenity")); err != nil || b.Name() != "tty" {
		t.Fatalf("tty: %v %v", b, err)
	}
	if b, err := SelectWith(wslEnv(vars("zenity"), true, "powershell.exe", "zenity")); err != nil || b.Name() != "zenity" {
		t.Fatalf("zenity: %v %v", b, err)
	}
	if b, err := SelectWith(wslEnv(vars("zenity"), true, "powershell.exe")); b != nil || err == nil {
		t.Fatalf("zenity missing must not fall back: %v %v", b, err)
	}
}

// What powershell.exe writes for a secret is the raw UTF-8 of the text box
// (psSecretOutput writes bytes to the stdout stream, no console code page, no
// BOM, no line terminator), whether the caller is Windows or WSL; a choice is
// the digits through Console.Out. The WSL backend reads both the same way.
func TestWSLPowerShellDialogsOverStdin(t *testing.T) {
	var got []command
	reply := []byte("pässwörd\u00e9\u20ac")
	e := wslEnv(map[string]string{"WSL_DISTRO_NAME": "Ubuntu"}, false, "powershell.exe")
	e.run = func(_ context.Context, c command) (result, error) {
		got = append(got, c)
		return result{Stdout: append([]byte(nil), reply...)}, nil
	}
	b, err := SelectWith(e)
	if err != nil || b.Name() != "powershell" {
		t.Fatalf("backend %v %v", b, err)
	}
	s, err := b.Secret(SecretRequest{Name: "TESTSECRET_NAME"})
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Reveal()) != string(reply) {
		t.Fatalf("value %q", s.Reveal())
	}
	// CRLF, as a console-written answer would end.
	reply = []byte("TESTSECRET_value\r\n")
	if s, err = b.Secret(SecretRequest{Name: "N"}); err != nil || string(s.Reveal()) != "TESTSECRET_value" {
		t.Fatalf("crlf: %q %v", s.Reveal(), err)
	}
	for _, c := range got {
		if c.Path != wslPS || len(c.Stdin) == 0 || len(c.Env) != 0 {
			t.Fatalf("command %+v", c)
		}
		// The script travels on stdin; nothing names a file or carries the reply.
		if strings.Contains(strings.Join(c.Args, " "), "TESTSECRET") || strings.Contains(string(c.Stdin), "TESTSECRET_value") {
			t.Fatalf("value in the command: %+v", c)
		}
		if strings.Join(c.Args, " ") != "-NoProfile -NonInteractive -STA -Command -" {
			t.Fatalf("args %q", c.Args)
		}
		for _, banned := range []string{"-File", "-EncodedCommand", "Out-File", "Set-Content", "GetTempPath", "$env:TEMP"} {
			if strings.Contains(string(c.Stdin), banned) || strings.Contains(strings.Join(c.Args, " "), banned) {
				t.Fatalf("script needs a file: %s", banned)
			}
		}
	}
}

func TestWSLPowerShellAnswersAChoiceAndACancel(t *testing.T) {
	e := wslEnv(map[string]string{"WSL_DISTRO_NAME": "Ubuntu"}, false, "powershell.exe")
	out, exit := []byte("2"), 0
	e.run = func(context.Context, command) (result, error) {
		return result{Stdout: append([]byte(nil), out...), Exit: exit}, nil
	}
	b, err := SelectWith(e)
	if err != nil || b.Name() != "powershell" {
		t.Fatalf("backend %v %v", b, err)
	}
	n := b.(*native)
	n.timeout = time.Minute
	d := dialog{kind: dialogChoose, title: dialogTitle, options: []string{"a", "b", "c"}}
	r, st, err := n.ask(d)
	if err != nil || st != statusOK {
		t.Fatalf("%v %v", st, err)
	}
	if i, ok := parseChoice(r.Stdout, 3); !ok || i != 1 {
		t.Fatalf("choice %d %v", i, ok)
	}
	out, exit = nil, psExitCancel
	if _, st, err = n.ask(d); st != statusCancel || err == nil {
		t.Fatalf("cancel: %v %v", st, err)
	}
}

func TestDescribeNamesTheBackend(t *testing.T) {
	for _, tt := range []struct {
		name string
		e    Env
		want string
	}{
		{"wsl", wslEnv(map[string]string{"WSL_DISTRO_NAME": "Ubuntu"}, false, "powershell.exe"), "powershell (WSL)"},
		{"wsl forced", wslEnv(map[string]string{"WSL_DISTRO_NAME": "Ubuntu", EnvBackend: "powershell"}, false, "powershell.exe"), "powershell (WSL)"},
		{"windows", envOf("windows", nil, "powershell.exe"), "powershell"},
		{"macos", envOf("darwin", nil, "osascript"), "osascript"},
		{"linux desktop", envOf("linux", map[string]string{"DISPLAY": ":0"}, "zenity"), "zenity"},
		{"terminal", envOf("linux", nil), "tty"},
		{"wsl without the helper", wslEnv(map[string]string{"WSL_DISTRO_NAME": "Ubuntu"}, true), "tty"},
		{"tty forced", wslEnv(map[string]string{"WSL_DISTRO_NAME": "Ubuntu", EnvBackend: "tty"}, false, "powershell.exe"), "tty"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := describeWith(tt.e)
			if err != nil || got != tt.want {
				t.Fatalf("got %q %v, want %q", got, err, tt.want)
			}
		})
	}
	// A backend named but unavailable is an error, as for any command.
	if _, err := describeWith(envOf("linux", map[string]string{EnvBackend: "zenity"})); err == nil {
		t.Fatal("forced zenity without zenity")
	}
}
