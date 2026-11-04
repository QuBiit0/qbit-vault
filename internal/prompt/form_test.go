package prompt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var formReqs = []SecretRequest{
	{Name: "DB_HOST", Reason: "run the shop-api migrations", Host: "pi", Session: "pi:abcd1234", Project: "shop-api", Label: "Host", Visible: true},
	{Name: "DB_PASSWORD", Reason: "run the shop-api migrations", Host: "pi", Session: "pi:abcd1234", Project: "shop-api", Label: "Password"},
}

func TestFormDialog(t *testing.T) {
	d := formDialog(formReqs)
	if d.kind != dialogForm || len(d.fields) != 2 || d.fields[0].label != "Host" || !d.fields[0].visible || d.fields[1].visible {
		t.Fatalf("dialog=%+v", d)
	}
	if !strings.Contains(d.text, "DB_HOST, DB_PASSWORD") || !strings.Contains(d.text, "run the shop-api migrations") {
		t.Fatalf("text=%q", d.text)
	}
	unnamed := formDialog([]SecretRequest{{Name: "A\x1b[31m"}, {Name: "B"}})
	if unnamed.fields[0].label != `A\x1b[31m` {
		t.Fatalf("label not escaped: %q", unnamed.fields[0].label)
	}
}

func TestZenityForm(t *testing.T) {
	d := formDialog(formReqs)
	got := zenityTool{}.buildForm("/usr/bin/zenity", d).Args
	want := []string{"--forms", "--no-markup", "--title=" + d.title, "--text=" + d.text, "--separator=" + formSep, "--add-entry=Host", "--add-password=Password"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	vals, ok := zenityTool{}.parseForm([]byte("db.internal"+formSep+"TESTSECRET_pw\n"), 2)
	if !ok || string(vals[0]) != "db.internal" || string(vals[1]) != "TESTSECRET_pw" {
		t.Fatalf("parse: %q %v", vals, ok)
	}
	for _, bad := range []string{"only-one\n", "a" + formSep + "b" + formSep + "c\n"} {
		if _, ok := (zenityTool{}).parseForm([]byte(bad), 2); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPowerShellForm(t *testing.T) {
	d := formDialog(formReqs)
	s := string(powershellTool{}.buildForm("powershell.exe", d).Stdin)
	for _, must := range []string{"$labels = @(", "$hides = @($false, $true)", "UseSystemPasswordChar = $hides[$i]", "OpenStandardOutput", "TopMost = $true", "exit 2"} {
		if !strings.Contains(s, must) {
			t.Errorf("script lacks %q", must)
		}
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.Count(line, "{") != strings.Count(line, "}") || strings.Count(line, "(") != strings.Count(line, ")") {
			t.Errorf("statement spans lines: %q", line)
		}
	}
	for _, b := range []byte(s) {
		if b >= 0x80 {
			t.Fatal("non-ASCII byte in the script")
		}
	}
	out := base64.StdEncoding.EncodeToString([]byte("db.internal")) + "\n" + base64.StdEncoding.EncodeToString([]byte("TESTSECRET_pw")) + "\n"
	vals, ok := powershellTool{}.parseForm([]byte(out), 2)
	if !ok || string(vals[1]) != "TESTSECRET_pw" {
		t.Fatalf("parse: %v", ok)
	}
	if _, ok := (powershellTool{}).parseForm([]byte("not base64!\n"), 1); ok {
		t.Fatal("accepted garbage")
	}
}

func TestNativeFormReadsAndWipes(t *testing.T) {
	out := []byte("db.internal" + formSep + "TESTSECRET_pw\n")
	f := &fakeRun{res: []result{{Stdout: out}}}
	vals, err := nativeOf(zenityTool{}, f).(Former).Form(formReqs)
	if err != nil || len(vals) != 2 || string(vals[0].Reveal()) != "db.internal" || vals[1].Name() != "DB_PASSWORD" {
		t.Fatalf("vals=%v err=%v", vals, err)
	}
	if string(out) != string(make([]byte, len(out))) {
		t.Fatal("helper output not wiped")
	}
	if strings.Contains(strings.Join(f.cmds[0].Args, " "), "TESTSECRET_") {
		t.Fatal("value in argv")
	}
	f = &fakeRun{res: []result{{Exit: 1}}}
	if _, err := nativeOf(zenityTool{}, f).(Former).Form(formReqs); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancel: %v", err)
	}
	f = &fakeRun{res: []result{ok("one-field-only\n")}}
	if _, err := nativeOf(zenityTool{}, f).(Former).Form(formReqs); err == nil {
		t.Fatal("a short answer was accepted")
	}
	for _, tl := range []tool{kdialogTool{}, osascriptTool{}} {
		if _, err := nativeOf(tl, &fakeRun{}).(Former).Form(formReqs); !errors.Is(err, ErrNoForm) {
			t.Errorf("%s: %v", tl.name(), err)
		}
	}
}

func TestPowerShellFormParses(t *testing.T) {
	if runtime.GOOS != "windows" || testing.Short() {
		t.Skip("needs Windows PowerShell")
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe not found")
	}
	dir := t.TempDir()
	for i, tt := range hostile {
		reqs := []SecretRequest{{Name: "A", Reason: tt.in, Label: tt.in, Visible: true}, {Name: "B", Label: tt.in}}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.ps1", i)), powershellTool{}.buildForm(ps, formDialog(reqs)).Stdin, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	drv := `foreach ($fi in Get-ChildItem -LiteralPath $env:GV_DIR -Filter *.ps1) { $e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput([IO.File]::ReadAllText($fi.FullName), [ref]$null, [ref]$e); Write-Output ($fi.Name + ' ' + $e.Count) }`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", drv)
	cmd.Env = append(os.Environ(), "GV_DIR="+dir)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != len(hostile) {
		t.Fatalf("checked %d of %d", len(lines), len(hostile))
	}
	for _, l := range lines {
		if !strings.HasSuffix(strings.TrimSpace(l), " 0") {
			t.Errorf("parse errors: %s", l)
		}
	}
}

// W2: zenity renders Pango markup unless told not to.
func TestZenityFormHasNoMarkup(t *testing.T) {
	if args := (zenityTool{}).buildForm("/usr/bin/zenity", formDialog(formReqs)).Args; args[1] != "--no-markup" {
		t.Fatalf("args=%q", args)
	}
}

// W5: a blank last field is a blank value, not a failed dialog.
func TestPowerShellFormBlankLastField(t *testing.T) {
	out := base64.StdEncoding.EncodeToString([]byte("db.internal")) + "\n" + "\n"
	vals, ok := powershellTool{}.parseForm([]byte(out), 2)
	if !ok || len(vals) != 2 || string(vals[0]) != "db.internal" || len(vals[1]) != 0 {
		t.Fatalf("vals=%q ok=%v", vals, ok)
	}
}

// W3, W4 in the header.
func TestHeaderShowsDescriptionAndStored(t *testing.T) {
	h := Header(SecretRequest{Name: "A", Reason: "x y z", Description: "staging \x1b[31mdb", Stored: []string{"B", "C"}})
	if !strings.Contains(h, `  about:   staging \x1b[31mdb`+"\n") || !strings.Contains(h, "  stored:  B, C (already stored, not asked)\n") {
		t.Fatalf("header=%q", h)
	}
}
