package prompt

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const fxShown = "QVR1-TESTSECRET-SHOWN-KEY"

// Shown text must never reach a helper's argv: on Linux any local user can
// read another process's command line.
func TestShowNeverPutsTheTextInArgv(t *testing.T) {
	for _, tl := range []tool{zenityTool{}, osascriptTool{}, powershellTool{}} {
		f := &fakeRun{res: []result{ok("")}}
		if err := nativeOf(tl, f).(Shower).Show("Recovery key", "Write this down:\n"+fxShown); err != nil {
			t.Fatalf("%s: %v", tl.name(), err)
		}
		if len(f.cmds) != 1 {
			t.Fatalf("%s: %d commands", tl.name(), len(f.cmds))
		}
		for _, a := range f.cmds[0].Args {
			if strings.Contains(a, "TESTSECRET") {
				t.Errorf("%s: text in argv %q", tl.name(), a)
			}
		}
		if len(f.cmds[0].Env) != 0 {
			t.Errorf("%s: env set", tl.name())
		}
	}
	// zenity reads the text from stdin with --text-info, as is.
	f := &fakeRun{res: []result{ok("")}}
	_ = nativeOf(zenityTool{}, f).(Shower).Show("T", fxShown)
	if c := f.cmds[0]; c.Args[0] != "--text-info" || string(c.Stdin) != fxShown {
		t.Errorf("zenity: args=%q stdin=%q", c.Args, c.Stdin)
	}
}

func TestShowOutcomes(t *testing.T) {
	sh := nativeOf(zenityTool{}, &fakeRun{res: []result{{Exit: 1}}}).(Shower)
	if err := sh.Show("T", "x"); !errors.Is(err, ErrCancelled) {
		t.Errorf("closed dialog: %v", err)
	}
	sh = nativeOf(powershellTool{}, &fakeRun{res: []result{{Exit: 2}}}).(Shower)
	if err := sh.Show("T", "x"); !errors.Is(err, ErrCancelled) {
		t.Errorf("powershell cancel: %v", err)
	}
	// kdialog takes text only as arguments: it cannot show a secret.
	f := &fakeRun{res: []result{ok("")}}
	if err := nativeOf(kdialogTool{}, f).(Shower).Show("T", fxShown); !errors.Is(err, ErrUnavailable) || len(f.cmds) != 0 {
		t.Errorf("kdialog: %v, %d commands", err, len(f.cmds))
	}
	// Control characters cannot paint over the dialog.
	f = &fakeRun{res: []result{ok("")}}
	_ = nativeOf(zenityTool{}, f).(Shower).Show("T", "a\x1b[2Jb")
	if strings.Contains(string(f.cmds[0].Stdin), "\x1b") {
		t.Error("escape sequence shown raw")
	}
}

func TestTTYShow(t *testing.T) {
	b, term := backendOf("")
	if err := b.(Shower).Show("Recovery key", "Write this down:\n"+fxShown+"\x1b[2J"); err != nil {
		t.Fatal(err)
	}
	out := term.out.String()
	if !strings.Contains(out, fxShown) || !strings.Contains(out, "Press Enter") || strings.Contains(out, "\x1b") {
		t.Fatalf("out=%q", out)
	}
	if len(term.hidden) != 1 || term.hidden[0] || !term.closed {
		t.Fatalf("reads=%v closed=%v", term.hidden, term.closed)
	}
	b, _ = backendOf(ctrlC)
	if err := b.(Shower).Show("T", "x"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("ctrl-c: %v", err)
	}
}

func TestPowerShellShowParses(t *testing.T) {
	if runtime.GOOS != "windows" || testing.Short() {
		t.Skip("needs Windows PowerShell")
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe not found")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "show.ps1"), powershellTool{}.build(ps, showDialog("T", "a 'b' $c\nline 2")).Stdin, 0o600); err != nil {
		t.Fatal(err)
	}
	drv := `$e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput([IO.File]::ReadAllText((Join-Path $env:QBV_DIR 'show.ps1')), [ref]$null, [ref]$e); Write-Output $e.Count`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", drv)
	cmd.Env = append(os.Environ(), "QBV_DIR="+dir)
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "0" {
		t.Fatalf("parse errors: %q %v", out, err)
	}
}

// A recovery key must be selectable so the user can copy it instead of
// typing it: on Windows the text sits in a read-only text box, not a label.
func TestPowerShellShowTextIsSelectable(t *testing.T) {
	s := string(powershellTool{}.build("powershell.exe", showDialog("Recovery key", "QVR1-TESTSECRET_x")).Stdin)
	for _, want := range []string{"$sel.ReadOnly = $true", "$sel.Multiline = $true", "$sel.Text = $code.Replace("} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// Other dialogs keep the label.
	if c := string(powershellTool{}.build("powershell.exe", dialog{kind: dialogConfirm, title: "t", text: "x"}).Stdin); strings.Contains(c, "$sel") {
		t.Error("a confirm dialog got the selectable box")
	}
}

// The last paragraph of a shown text is the code (recovery key, pairing
// code); the paragraphs before it are the explanation.
func TestSplitShown(t *testing.T) {
	tests := []struct{ name, in, intro, code string }{
		{"one paragraph", "QVR1-AAAA", "", "QVR1-AAAA"},
		{"intro and code", "Write it down.\n\nQVR1-AAAA", "Write it down.", "QVR1-AAAA"},
		{"several paragraphs", "One.\n\nTwo\nlines.\n\nQVR1-AAAA", "One.\n\nTwo\nlines.", "QVR1-AAAA"},
		{"code of two lines", "Intro.\n\nQVR1-AAAA\nBBBB", "Intro.", "QVR1-AAAA\nBBBB"},
		{"trailing blank lines", "Intro.\n\nQVR1-AAAA\n\n", "Intro.", "QVR1-AAAA"},
		{"several blank lines", "Intro.\n\n\n\nQVR1-AAAA", "Intro.", "QVR1-AAAA"},
		{"single line break is no paragraph", "Intro.\nQVR1-AAAA", "", "Intro.\nQVR1-AAAA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intro, code := splitShown(tt.in)
			if intro != tt.intro || code != tt.code {
				t.Fatalf("got %q, %q; want %q, %q", intro, code, tt.intro, tt.code)
			}
		})
	}
}

// V1: the explanation wraps in the label and the code sits alone in the box,
// whose height is measured, not counted in logical lines.
func TestPowerShellShowLayout(t *testing.T) {
	text := "Write this recovery key down.\n\n" + fxShown
	s := string(powershellTool{}.build("powershell.exe", showDialog("Recovery key", text)).Stdin)
	prelude := s[:strings.Index(s, psBodyMarker)]
	if !strings.Contains(prelude, "$text = Dec "+psString("Write this recovery key down.")) {
		t.Errorf("the label does not hold the explanation only:\n%s", prelude)
	}
	if !strings.Contains(prelude, "$code = Dec "+psString(fxShown)) {
		t.Errorf("the box does not hold the code:\n%s", prelude)
	}
	if strings.Contains(s, "Lines.Count") {
		t.Error("the box height still counts logical lines")
	}
	if !strings.Contains(s, "TextRenderer]::MeasureText($sel.Text") {
		t.Error("the box height is not measured")
	}
	if !strings.Contains(s, "$sel.Text = $code.Replace(") {
		t.Error("the box does not show $code")
	}
	// A single paragraph goes all in the box: the label is dropped.
	one := string(powershellTool{}.build("powershell.exe", showDialog("Pairing code", fxShown)).Stdin)
	if !strings.Contains(one, "$text = Dec "+psString("")) || !strings.Contains(one, "$code = Dec "+psString(fxShown)) {
		t.Error("one paragraph is not all in the box")
	}
	if !strings.Contains(one, "if ($text.Length -eq 0) { $p.Controls.Remove($l) }") {
		t.Error("an empty explanation still leaves a label")
	}
	// Other dialogs carry no $code.
	if c := string(powershellTool{}.build("powershell.exe", dialog{kind: dialogConfirm, title: "t", text: "x"}).Stdin); strings.Contains(c, "$code") {
		t.Error("a confirm dialog got $code")
	}
}
