package prompt

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// hostile is text a requester could put in a reason or a name to break out of
// the literal it is shown in.
var hostile = []struct{ name, in string }{
	{"plain", "run the release"},
	{"double quote", `say "hi"`},
	{"single quote", `it's`},
	{"smart quotes", "a\u2018b\u2019c\u201cd\u201de"},
	{"backslash", `C:\temp\x`},
	{"trailing backslash", `end\`},
	{"quote then backslash", `\"; do shell script "id" --`},
	{"dollar and subshell", "$(Get-Process) ${env:PATH} $x"},
	{"backticks", "`n`r `$x"},
	{"percent", "%PATH% %d %s"},
	{"newline", "a\nb"},
	{"carriage return", "a\rb"},
	{"crlf", "a\r\nb"},
	{"nul", "a\x00b"},
	{"unicode", "héllo ☃ 日本語 🔑"},
	{"ansi", "\x1b[31mred\x1b[0m\x1b]0;title\x07"},
	{"bidi override", "a\u202eb"},
	{"invalid utf-8", "a\xffb"},
	{"markup", "<b>bold</b> &amp; <a href=x>"},
	{"leading dash", "--help"},
	{"semicolons and pipes", "a; b | c && d"},
	{"empty", ""},
}

// ---- PowerShell ----

var b64Literal = regexp.MustCompile(`^'[A-Za-z0-9+/=]*'$`)

func TestPSStringCannotBreakOut(t *testing.T) {
	for _, tt := range hostile {
		t.Run(tt.name, func(t *testing.T) {
			lit := psString(tt.in)
			if !b64Literal.MatchString(lit) {
				t.Fatalf("literal %q is not a base64 literal", lit)
			}
			raw, err := base64.StdEncoding.DecodeString(strings.Trim(lit, "'"))
			if err != nil || string(raw) != tt.in {
				t.Fatalf("round trip: %q, %v", raw, err)
			}
		})
	}
}

func psTool(t *testing.T) (powershellTool, command) {
	t.Helper()
	d := secretDialog(req)
	return powershellTool{}, powershellTool{}.build("powershell.exe", d)
}

func TestPowerShellCommandShape(t *testing.T) {
	_, c := psTool(t)
	if c.Path != "powershell.exe" {
		t.Fatalf("path %q", c.Path)
	}
	want := []string{"-NoProfile", "-NonInteractive", "-STA", "-Command", "-"}
	if !reflect.DeepEqual(c.Args, want) {
		t.Fatalf("argv %q", c.Args)
	}
	s := string(c.Stdin)
	for _, must := range []string{"$hide = $true\n", "UseSystemPasswordChar = $hide", "TopMost = $true", "exit 2", "OpenStandardOutput", "UseMnemonic = $false"} {
		if !strings.Contains(s, must) {
			t.Errorf("script lacks %q", must)
		}
	}
	// The request travels as base64 data, never as script text.
	for _, leak := range []string{"GITHUB_TOKEN", "run the release", "claude-code"} {
		if strings.Contains(s, leak) {
			t.Errorf("script holds %q outside a data literal", leak)
		}
	}
	if !strings.Contains(s, psString(secretDialog(req).title)) || !strings.Contains(s, psString(secretDialog(req).text)) {
		t.Error("script lacks the title or the text literal")
	}
}

func TestPowerShellScriptsAreASCII(t *testing.T) {
	// The script goes through stdin, whose code page is not UTF-8: only ASCII
	// may be in it, whatever the request holds.
	for _, tt := range hostile {
		for _, d := range []dialog{
			secretDialog(SecretRequest{Name: "N", Reason: tt.in, Host: tt.in, Session: tt.in, Project: tt.in}),
			chooseDialog(tt.in, []string{tt.in, "b"}, 0),
			confirmDialog(tt.in),
		} {
			for _, b := range (powershellTool{}).build("powershell.exe", d).Stdin {
				if b >= 0x80 || (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
					t.Fatalf("%s: byte %#x in the script", tt.name, b)
				}
			}
		}
	}
}

// powershell.exe reads "-Command -" line by line and drops what follows a
// statement that spans lines, so every line must be a whole statement.
func TestPowerShellStatementsAreOneLine(t *testing.T) {
	for _, d := range []dialog{secretDialog(req), chooseDialog("q", []string{"a", "b"}, 0), confirmDialog("q")} {
		for _, line := range strings.Split(string(powershellTool{}.build("p", d).Stdin), "\n") {
			if strings.Count(line, "{") != strings.Count(line, "}") || strings.Count(line, "(") != strings.Count(line, ")") {
				t.Errorf("statement spans lines: %q", line)
			}
		}
	}
}

func TestPowerShellClassify(t *testing.T) {
	tests := []struct {
		exit int
		want status
	}{{0, statusOK}, {2, statusCancel}, {1, statusFail}, {-1, statusFail}, {3, statusFail}}
	for _, tt := range tests {
		if got := (powershellTool{}).classify(secretDialog(req), result{Exit: tt.exit}); got != tt.want {
			t.Errorf("exit %d: %v, want %v", tt.exit, got, tt.want)
		}
	}
}

// TestPowerShellParses runs the real PowerShell parser over every script and
// decodes each data prelude with PowerShell itself, in a single process.
func TestPowerShellParses(t *testing.T) {
	if runtime.GOOS != "windows" || testing.Short() {
		t.Skip("needs Windows PowerShell")
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe not found")
	}
	dir := t.TempDir()
	want := map[string]string{} // file -> title|text
	for i, tt := range hostile {
		dialogs := map[string]dialog{
			"secret":  secretDialog(SecretRequest{Name: "N", Reason: tt.in, Host: "h", Session: "s", Project: tt.in}),
			"choose":  chooseDialog(tt.in, []string{tt.in, "two"}, 1),
			"confirm": confirmDialog(tt.in),
		}
		for kind, d := range dialogs {
			file := fmt.Sprintf("%02d-%s.ps1", i, kind)
			if err := os.WriteFile(filepath.Join(dir, file), powershellTool{}.build(ps, d).Stdin, 0o600); err != nil {
				t.Fatal(err)
			}
			want[file] = d.title + "|" + d.text
		}
	}
	drv := `foreach ($fi in Get-ChildItem -LiteralPath $env:QBV_DIR -Filter *.ps1) {
  $s = [IO.File]::ReadAllText($fi.FullName)
  $e = $null
  [void][System.Management.Automation.Language.Parser]::ParseInput($s, [ref]$null, [ref]$e)
  $pre = $s.Substring(0, $s.IndexOf($env:QBV_MARK))
  & { Invoke-Expression $pre; $o = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($title + '|' + $text)); Write-Output ($fi.Name + ' ' + $e.Count + ' ' + $o) }
}`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", drv)
	cmd.Env = append(os.Environ(), "QBV_DIR="+dir, "QBV_MARK="+psBodyMarker)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	seen := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			t.Fatalf("driver line %q", line)
		}
		raw, _ := base64.StdEncoding.DecodeString(f[2])
		if f[1] != "0" || string(raw) != want[f[0]] {
			t.Errorf("%s: %s parse errors, prelude decoded %q", f[0], f[1], raw)
		}
		seen++
	}
	if seen != len(want) {
		t.Fatalf("checked %d scripts of %d", seen, len(want))
	}
}

// ---- AppleScript ----

// unAS decodes an AppleScript string literal the way AppleScript would, and
// fails on anything that would end it early or is a raw control character.
func unAS(t *testing.T, lit string) string {
	t.Helper()
	if len(lit) < 2 || lit[0] != '"' || lit[len(lit)-1] != '"' {
		t.Fatalf("not a quoted literal: %q", lit)
	}
	in := lit[1 : len(lit)-1]
	var b strings.Builder
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '"':
			t.Fatalf("unescaped quote in %q", lit)
		case c < 0x20 || c == 0x7f:
			t.Fatalf("raw control byte %#x in %q", c, lit)
		case c == '\\':
			i++
			if i >= len(in) {
				t.Fatalf("dangling backslash in %q", lit)
			}
			switch in[i] {
			case '\\', '"':
				b.WriteByte(in[i])
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				t.Fatalf("unknown escape \\%c in %q", in[i], lit)
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func TestASStringCannotBreakOut(t *testing.T) {
	want := map[string]string{
		"double quote":        `say "hi"`,
		"backslash":           `C:\temp\x`,
		"newline":             "a\nb",
		"crlf":                "a\r\nb",
		"nul":                 `a\x00b`,
		"ansi":                `\x1b[31mred\x1b[0m\x1b]0;title\x07`,
		"bidi override":       `a\u202eb`,
		"invalid utf-8":       `a\xffb`,
		"unicode":             "héllo ☃ 日本語 🔑",
		"dollar and subshell": "$(Get-Process) ${env:PATH} $x",
		"percent":             "%PATH% %d %s",
	}
	for _, tt := range hostile {
		t.Run(tt.name, func(t *testing.T) {
			got := unAS(t, asString(tt.in))
			if w, ok := want[tt.name]; ok && got != w {
				t.Fatalf("decoded %q, want %q", got, w)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("decoded text is not UTF-8: %q", got)
			}
		})
	}
}

func TestOsascriptSecretScript(t *testing.T) {
	d := secretDialog(req)
	c := osascriptTool{}.build("/usr/bin/osascript", d)
	if c.Path != "/usr/bin/osascript" || !reflect.DeepEqual(c.Args, []string{"-"}) {
		t.Fatalf("command %q %q", c.Path, c.Args)
	}
	want := `display dialog ` + asString(d.text) + ` with title ` + asString(d.title) +
		` default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel" with icon caution` + "\n" +
		`return text returned of result` + "\n"
	if string(c.Stdin) != want {
		t.Fatalf("script:\n%s\nwant:\n%s", c.Stdin, want)
	}
}

func TestOsascriptChooseAndConfirmScripts(t *testing.T) {
	d := chooseDialog(`Allow "X"?`, []string{"once", `a "b"`, "deny"}, 1)
	s := string(osascriptTool{}.build("osascript", d).Stdin)
	want := `set r to choose from list {"1) once", "2) a \"b\"", "3) deny"} with prompt "Allow \"X\"?" with title ` + asString(d.title) +
		` default items {"2) a \"b\""} OK button name "OK" cancel button name "Cancel" without multiple selections allowed and without empty selection allowed` + "\n" +
		`if r is false then error number -128` + "\n" +
		`return item 1 of r` + "\n"
	if s != want {
		t.Fatalf("script:\n%s\nwant:\n%s", s, want)
	}
	cd := confirmDialog("Remove X?")
	s = string(osascriptTool{}.build("osascript", cd).Stdin)
	want = `display dialog "Remove X?" with title ` + asString(cd.title) +
		` buttons {"Decline", "Confirm"} default button "Decline" cancel button "Decline" with icon caution` + "\n" +
		`return button returned of result` + "\n"
	if s != want {
		t.Fatalf("script:\n%s\nwant:\n%s", s, want)
	}
}

func TestOsascriptClassify(t *testing.T) {
	d := secretDialog(req)
	tests := []struct {
		name string
		r    result
		want status
	}{
		{"ok", result{Exit: 0}, statusOK},
		{"cancel", result{Exit: 1, Stderr: []byte("execution error: User canceled. (-128)")}, statusCancel},
		{"other error", result{Exit: 1, Stderr: []byte("execution error: not allowed (-1743)")}, statusFail},
		{"no output", result{Exit: 1}, statusFail},
	}
	for _, tt := range tests {
		if got := (osascriptTool{}).classify(d, tt.r); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

// ---- zenity and kdialog ----

func TestZenityArgv(t *testing.T) {
	sd := secretDialog(req)
	cd := chooseDialog("Which scope?", []string{"once", "-danger", "deny"}, 1)
	qd := confirmDialog("Remove X?")
	tests := []struct {
		name string
		d    dialog
		want []string
	}{
		{"secret", sd, []string{"--entry", "--hide-text", "--no-markup", "--title=" + sd.title, "--text=" + sd.text}},
		{"choose", cd, []string{
			"--list", "--radiolist", "--no-markup", "--title=" + cd.title, "--text=Which scope?",
			"--column=Pick", "--column=Index", "--column=Option", "--hide-column=2", "--print-column=2",
			"FALSE", "1", "once", "TRUE", "2", " -danger", "FALSE", "3", "deny",
		}},
		{"confirm", qd, []string{"--question", "--no-markup", "--title=" + qd.title, "--text=Remove X?", "--ok-label=Confirm", "--cancel-label=Decline"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := zenityTool{}.build("/usr/bin/zenity", tt.d)
			if c.Path != "/usr/bin/zenity" || len(c.Stdin) != 0 || !reflect.DeepEqual(c.Args, tt.want) {
				t.Fatalf("got %q\nwant %q", c.Args, tt.want)
			}
		})
	}
}

func TestKdialogArgv(t *testing.T) {
	sd := secretDialog(req)
	cd := chooseDialog("Which scope?", []string{"once", "-danger", "deny"}, 1)
	qd := confirmDialog("Remove X?")
	tests := []struct {
		name string
		d    dialog
		want []string
	}{
		{"secret", sd, []string{"--title", sd.title, "--password", strings.ReplaceAll(sd.text, "\n", "<br>")}},
		{"choose", cd, []string{"--title", cd.title, "--radiolist", "Which scope?", "1", "once", "off", "2", " -danger", "on", "3", "deny", "off"}},
		{"confirm", qd, []string{"--title", qd.title, "--yes-label", "Confirm", "--no-label", "Decline", "--yesno", "Remove X?"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := kdialogTool{}.build("kdialog", tt.d)
			if len(c.Stdin) != 0 || !reflect.DeepEqual(c.Args, tt.want) {
				t.Fatalf("got %q\nwant %q", c.Args, tt.want)
			}
		})
	}
}

func TestKdialogEscapesRichText(t *testing.T) {
	for _, reason := range []string{"<br>value: x<b>", "<a href=x>", "<img src=x>", `a "q" & b`} {
		sd := secretDialog(SecretRequest{Name: "N<i>", Reason: reason, Host: "h", Session: "s"})
		c := kdialogTool{}.build("kdialog", sd)
		text := c.Args[len(c.Args)-1]
		for _, bad := range []string{"<b>", "<a ", "<img", "<i>", `"q"`} {
			if strings.Contains(text, bad) {
				t.Errorf("%q: text holds %q: %q", reason, bad, text)
			}
		}
		// The only tags are our own line breaks.
		if rest := strings.ReplaceAll(text, "<br>", ""); strings.ContainsAny(rest, "<>\"") || strings.Contains(text, "\n") {
			t.Errorf("%q: markup or raw newline left: %q", reason, text)
		}
		if strings.Count(text, "<br>") != strings.Count(sd.text, "\n") {
			t.Errorf("%q: layout lines changed: %q", reason, text)
		}
	}
	c := kdialogTool{}.build("kdialog", secretDialog(SecretRequest{Name: "N", Reason: "<br>value: x<b>", Host: "h", Session: "s"}))
	if !strings.Contains(c.Args[len(c.Args)-1], "Why:      &lt;br&gt;value: x&lt;b&gt;") {
		t.Errorf("entities missing: %q", c.Args)
	}
	cd := chooseDialog("<b>Q</b> & co", []string{"<i>a</i>", "b"}, 0)
	c = kdialogTool{}.build("kdialog", cd)
	want := []string{"--title", cd.title, "--radiolist", "&lt;b&gt;Q&lt;/b&gt; &amp; co", "1", "&lt;i&gt;a&lt;/i&gt;", "on", "2", "b", "off"}
	if !reflect.DeepEqual(c.Args, want) {
		t.Errorf("choose: %q\nwant %q", c.Args, want)
	}
}

func TestArgvToolsKeepHostileTextInOneElement(t *testing.T) {
	for _, tt := range hostile {
		d := secretDialog(SecretRequest{Name: "N", Reason: tt.in, Host: "h", Session: "s"})
		for _, tl := range []tool{zenityTool{}, kdialogTool{}} {
			c := tl.build("x", d)
			if len(c.Args) != 5 && len(c.Args) != 4 {
				t.Fatalf("%s/%s: %d args", tl.name(), tt.name, len(c.Args))
			}
			// The reason is escaped: no raw control byte beyond the layout newlines.
			for _, a := range c.Args {
				for i := 0; i < len(a); i++ {
					if (a[i] < 0x20 && a[i] != '\n') || a[i] == 0x7f {
						t.Fatalf("%s/%s: raw control byte %#x in argv", tl.name(), tt.name, a[i])
					}
				}
				if strings.Count(a, "\n") > 6 {
					t.Fatalf("%s/%s: the reason added lines", tl.name(), tt.name)
				}
			}
		}
	}
}

func TestZenityKdialogClassify(t *testing.T) {
	for _, tl := range []tool{zenityTool{}, kdialogTool{}} {
		sd, qd := secretDialog(req), confirmDialog("q")
		if tl.classify(sd, result{Exit: 0}) != statusOK {
			t.Errorf("%s: exit 0", tl.name())
		}
		if tl.classify(sd, result{Exit: 1}) != statusCancel {
			t.Errorf("%s: exit 1 on a value", tl.name())
		}
		if tl.classify(qd, result{Exit: 1}) != statusNo {
			t.Errorf("%s: exit 1 on a question", tl.name())
		}
		for _, code := range []int{255, -1, 127, 5} {
			if tl.classify(sd, result{Exit: code}) != statusFail {
				t.Errorf("%s: exit %d", tl.name(), code)
			}
		}
	}
	if (kdialogTool{}).classify(secretDialog(req), result{Exit: 2}) != statusCancel {
		t.Error("kdialog exit 2")
	}
}

// ---- dialogs ----

func TestDialogsEscapeRequestText(t *testing.T) {
	d := secretDialog(SecretRequest{Name: "N", Reason: "x\n  Secret:   OTHER\x1b[2J", Host: "h", Session: "s"})
	if !strings.HasPrefix(d.text, "  Who:") || strings.Contains(d.text, "\n  Secret:   OTHER") || strings.Count(d.text, "\n") != 6 || strings.Contains(d.text, "\x1b") || !strings.Contains(d.text, `\n`) {
		t.Fatalf("text %q", d.text)
	}
	for _, line := range []string{"Who:", "Secret:", "Why:", "Saved in:", "Value:"} {
		if !strings.Contains(d.text, line) {
			t.Errorf("text lacks %q", line)
		}
	}
	if !strings.Contains(d.text, "Saved in: all projects (global)") || !strings.Contains(d.text, "Value:    new") {
		t.Errorf("text %q", d.text)
	}
	d = secretDialog(SecretRequest{Name: "N", Reason: "r", Host: "h", Session: "s", Project: "shop", Existing: true})
	if !strings.Contains(d.text, "Saved in: project shop") || !strings.Contains(d.text, "replaces the saved value") {
		t.Errorf("text %q", d.text)
	}
	cd := chooseDialog("a\nb", []string{"x\ny"}, 0)
	if strings.Contains(cd.text, "\n") || strings.Contains(cd.options[0], "\n") {
		t.Errorf("choose not escaped: %q %q", cd.text, cd.options)
	}
	if strings.Contains(confirmDialog("a\x1bb").text, "\x1b") {
		t.Error("confirm not escaped")
	}
}

// ---- backend over a fake runner ----

type fakeRun struct {
	cmds []command
	res  []result
	err  error
}

func (f *fakeRun) run(ctx context.Context, c command) (result, error) {
	f.cmds = append(f.cmds, c)
	if f.err != nil {
		return result{}, f.err
	}
	if len(f.res) == 0 {
		return result{}, errors.New("no scripted result")
	}
	r := f.res[0]
	f.res = f.res[1:]
	return r, nil
}

func nativeOf(tl tool, f *fakeRun) Backend {
	return newNative(tl, "/bin/"+tl.name(), f.run, time.Minute)
}

func ok(out string) result { return result{Stdout: []byte(out)} }

func TestNativeSecretReadsStdout(t *testing.T) {
	for _, tl := range []tool{zenityTool{}, kdialogTool{}, osascriptTool{}, powershellTool{}} {
		for _, eol := range []string{"\n", "\r\n", ""} {
			t.Run(tl.name()+fmt.Sprintf("/%q", eol), func(t *testing.T) {
				out := []byte(fxValue + eol)
				f := &fakeRun{res: []result{{Stdout: out}}}
				sec, err := nativeOf(tl, f).Secret(req)
				if err != nil {
					t.Fatal(err)
				}
				if got := sec.Reveal(); string(got) != fxValue || sec.Name() != req.Name {
					t.Fatalf("value %q name %q", got, sec.Name())
				}
				if !bytes.Equal(out, make([]byte, len(out))) {
					t.Fatal("the helper's output buffer was not wiped")
				}
			})
		}
	}
}

func TestNativeNeverPutsTheValueInTheCommand(t *testing.T) {
	for _, tl := range []tool{zenityTool{}, kdialogTool{}, osascriptTool{}, powershellTool{}} {
		f := &fakeRun{res: []result{ok(fxValue + "\n"), ok(fxPass + "\n"), ok(fxPass + "\n")}}
		b := nativeOf(tl, f)
		if _, err := b.Secret(req); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Passphrase(true); err != nil {
			t.Fatal(err)
		}
		for _, c := range f.cmds {
			blob := c.Path + "\x00" + strings.Join(c.Args, "\x00") + "\x00" + string(c.Stdin)
			if strings.Contains(blob, "TESTSECRET_") {
				t.Fatalf("%s: a secret is in the command", tl.name())
			}
			if len(c.Env) != 0 {
				t.Fatalf("%s: the command sets an environment", tl.name())
			}
		}
	}
}

func TestNativeSecretFailures(t *testing.T) {
	tests := []struct {
		name string
		f    *fakeRun
		want error
	}{
		{"cancel", &fakeRun{res: []result{{Exit: 1}}}, ErrCancelled},
		{"helper failed", &fakeRun{res: []result{{Exit: 255}}}, ErrUnavailable},
		{"cannot start", &fakeRun{err: exec.ErrNotFound}, ErrUnavailable},
		{"timeout", &fakeRun{err: context.DeadlineExceeded}, ErrTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sec, err := nativeOf(zenityTool{}, tt.f).Secret(req)
			if !errors.Is(err, tt.want) || sec.Len() != 0 {
				t.Fatalf("err %v len %d", err, sec.Len())
			}
		})
	}
	// A blank answer is returned empty, as the terminal does; the caller says "empty value".
	sec, err := nativeOf(zenityTool{}, &fakeRun{res: []result{ok("  \r\n")}}).Secret(req)
	if err != nil || sec.Len() != 0 {
		t.Fatalf("blank: %v len %d", err, sec.Len())
	}
	// Errors carry no output of the helper.
	_, err = nativeOf(zenityTool{}, &fakeRun{res: []result{{Exit: 255, Stdout: []byte(fxValue), Stderr: []byte(fxValue)}}}).Secret(req)
	if err == nil || strings.Contains(err.Error(), "TESTSECRET_") {
		t.Fatalf("error %v", err)
	}
}

func TestNativeChoose(t *testing.T) {
	opts := []string{"once", "session", "deny"}
	tests := []struct {
		name    string
		tl      tool
		res     result
		want    int
		wantErr error
	}{
		{"zenity index", zenityTool{}, ok("2\n"), 1, nil},
		{"kdialog tag", kdialogTool{}, ok("3\n"), 2, nil},
		{"osascript item", osascriptTool{}, ok("1) once\n"), 0, nil},
		{"powershell index", powershellTool{}, ok("2"), 1, nil},
		{"cancel", zenityTool{}, result{Exit: 1}, 0, ErrCancelled},
		{"empty answer", zenityTool{}, ok("\n"), 0, ErrCancelled},
		{"out of range", zenityTool{}, ok("9\n"), 0, ErrCancelled},
		{"not a number", kdialogTool{}, ok("deny\n"), 0, ErrCancelled},
		{"failed", zenityTool{}, result{Exit: 255}, 0, ErrUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nativeOf(tt.tl, &fakeRun{res: []result{tt.res}}).Choose("Which?", opts, 0)
			if !errors.Is(err, tt.wantErr) || got != tt.want {
				t.Fatalf("got %d, %v", got, err)
			}
		})
	}
	if _, err := nativeOf(zenityTool{}, &fakeRun{}).Choose("q", opts, 3); err == nil {
		t.Fatal("bad default accepted")
	}
}

func TestNativeConfirm(t *testing.T) {
	tests := []struct {
		name    string
		tl      tool
		res     result
		want    bool
		wantErr error
	}{
		{"zenity yes", zenityTool{}, result{Exit: 0}, true, nil},
		{"zenity no", zenityTool{}, result{Exit: 1}, false, nil},
		{"kdialog yes", kdialogTool{}, result{Exit: 0}, true, nil},
		{"kdialog no", kdialogTool{}, result{Exit: 1}, false, nil},
		{"osascript yes", osascriptTool{}, ok("Confirm\n"), true, nil},
		{"osascript decline", osascriptTool{}, result{Exit: 1, Stderr: []byte("User canceled. (-128)")}, false, nil},
		{"powershell yes", powershellTool{}, result{Exit: 0}, true, nil},
		{"powershell no", powershellTool{}, result{Exit: 2}, false, nil},
		{"failed", zenityTool{}, result{Exit: 255}, false, ErrUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nativeOf(tt.tl, &fakeRun{res: []result{tt.res}}).Confirm("Remove X?")
			if !errors.Is(err, tt.wantErr) || got != tt.want {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
}

func TestNativePassphrase(t *testing.T) {
	f := &fakeRun{res: []result{ok(fxPass + "\n")}}
	sec, err := nativeOf(zenityTool{}, f).Passphrase(false)
	if err != nil || string(sec.Reveal()) != fxPass || sec.Name() != "passphrase" || len(f.cmds) != 1 {
		t.Fatalf("single: %v %d", err, len(f.cmds))
	}

	f = &fakeRun{res: []result{ok(fxPass + "\n"), ok(fxPass + "\n")}}
	sec, err = nativeOf(zenityTool{}, f).Passphrase(true)
	if err != nil || string(sec.Reveal()) != fxPass || len(f.cmds) != 2 {
		t.Fatalf("confirmed: %v %d", err, len(f.cmds))
	}
	if reflect.DeepEqual(f.cmds[0].Args, f.cmds[1].Args) {
		t.Error("the second dialog does not say it is the confirmation")
	}

	a, b := []byte(fxPass+"\n"), []byte(fxPass+"x\n")
	f = &fakeRun{res: []result{{Stdout: a}, {Stdout: b}}}
	sec, err = nativeOf(zenityTool{}, f).Passphrase(true)
	if !errors.Is(err, ErrMismatch) || sec.Len() != 0 {
		t.Fatalf("mismatch: %v", err)
	}
	if !bytes.Equal(a, make([]byte, len(a))) || !bytes.Equal(b, make([]byte, len(b))) {
		t.Error("buffers not wiped after a mismatch")
	}

	f = &fakeRun{res: []result{ok(fxPass + "\n"), {Exit: 1}}}
	if _, err = nativeOf(zenityTool{}, f).Passphrase(true); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancel on confirm: %v", err)
	}
}

func TestNativeTimeoutIsPassedToTheRunner(t *testing.T) {
	var dl time.Duration
	run := func(ctx context.Context, c command) (result, error) {
		d, _ := ctx.Deadline()
		dl = time.Until(d)
		return result{Exit: 1}, nil
	}
	_, _ = newNative(zenityTool{}, "zenity", run, 90*time.Second).Secret(req)
	if dl <= 80*time.Second || dl > 90*time.Second {
		t.Fatalf("deadline in %s", dl)
	}
}

// ---- default runner ----

func TestMain(m *testing.M) {
	if os.Getenv("QBV_HELPER") != "" {
		helperMain()
		return
	}
	os.Exit(m.Run())
}

// helperMain is a stand-in for zenity: it echoes stdin to stdout, writes to
// stderr, sleeps or exits as told.
func helperMain() {
	switch os.Getenv("QBV_HELPER") {
	case "echo":
		b, _ := io.ReadAll(os.Stdin)
		os.Stdout.Write(b)
		fmt.Fprint(os.Stderr, "note (-128)")
		os.Exit(3)
	case "flood":
		os.Stdout.Write(bytes.Repeat([]byte("A"), 4*maxInput))
	case "sleep":
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

func helper(mode string, stdin string) command {
	self, _ := os.Executable()
	return command{Path: self, Args: []string{"-test.run=XXX"}, Stdin: []byte(stdin), Env: append(os.Environ(), "QBV_HELPER="+mode)}
}

func TestExecRunner(t *testing.T) {
	r, err := execRunner(context.Background(), helper("echo", "hello\r\n"))
	if err != nil || string(r.Stdout) != "hello\r\n" || r.Exit != 3 || !strings.Contains(string(r.Stderr), "-128") {
		t.Fatalf("got %q %q %d, %v", r.Stdout, r.Stderr, r.Exit, err)
	}
	// An oversized helper output is refused (TestOversizeIsRefused).
}

func TestExecRunnerMissingBinary(t *testing.T) {
	if _, err := execRunner(context.Background(), command{Path: "qbit-vault-no-such-helper"}); err == nil {
		t.Fatal("no error")
	}
	b := newNative(zenityTool{}, "qbit-vault-no-such-helper", execRunner, time.Minute)
	if _, err := b.Secret(req); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestExecRunnerTimeoutKillsTheHelper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := execRunner(ctx, helper("sleep", ""))
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 20*time.Second {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
}

// ---- availability and selection ----

func envOf(goos string, vars map[string]string, onPath ...string) Env {
	return Env{
		GOOS:   goos,
		Getenv: func(k string) string { return vars[k] },
		LookPath: func(n string) (string, error) {
			for _, p := range onPath {
				if p == n && p != "powershell.exe" && p != "osascript" {
					return "/found/" + n, nil
				}
			}
			// A planted look-alike on PATH: the system helpers must never be taken from here.
			if n == "powershell.exe" || n == "osascript" {
				return "/evil/" + n, nil
			}
			return "", exec.ErrNotFound
		},
		// The fixed system locations hold the helper when it is listed.
		Exists: func(p string) bool {
			for _, n := range onPath {
				switch {
				case n == "powershell.exe" && (p == winPS || p == wslPS):
					return true
				case n == "osascript" && p == osascriptPath:
					return true
				case (n == "zenity" || n == "kdialog") && p == "/usr/bin/"+n:
					return true
				}
			}
			return false
		},
	}
}

const (
	winPS = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	wslPS = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
)

func TestNativeAvailability(t *testing.T) {
	no := func() bool { return false }
	tests := []struct {
		name     string
		e        Env
		wantName string
	}{
		{"windows interactive", envOf("windows", nil, "powershell.exe"), "powershell"},
		{"windows service session", func() Env { e := envOf("windows", nil, "powershell.exe"); e.Interactive = no; return e }(), ""},
		{"windows without powershell", envOf("windows", nil), ""},
		{"darwin", envOf("darwin", nil, "osascript"), "osascript"},
		{"darwin without osascript", envOf("darwin", nil), ""},
		{"darwin over ssh", envOf("darwin", map[string]string{"SSH_CONNECTION": "1 2 3 4"}, "osascript"), ""},
		{"darwin over ssh in a GUI app", envOf("darwin", map[string]string{"SSH_CONNECTION": "1 2 3 4", "__CFBundleIdentifier": "com.apple.Terminal"}, "osascript"), "osascript"},
		{"darwin over ssh with TERM_PROGRAM", envOf("darwin", map[string]string{"SSH_TTY": "/dev/ttys001", "TERM_PROGRAM": "iTerm.app"}, "osascript"), "osascript"},
		{"linux x11 zenity", envOf("linux", map[string]string{"DISPLAY": ":0"}, "zenity"), "zenity"},
		{"linux wayland kdialog", envOf("linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, "kdialog"), "kdialog"},
		{"linux both prefers zenity", envOf("linux", map[string]string{"DISPLAY": ":0"}, "kdialog", "zenity"), "zenity"},
		{"linux headless", envOf("linux", nil, "zenity", "kdialog"), ""},
		{"linux display no tool", envOf("linux", map[string]string{"DISPLAY": ":0"}), ""},
		{"freebsd", envOf("freebsd", map[string]string{"DISPLAY": ":0"}, "zenity"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tl, path := nativeFor(tt.e)
			got := ""
			if tl != nil {
				got = tl.name()
				want := map[string]string{"powershell": winPS, "osascript": osascriptPath}[got]
				if want == "" {
					want = "/usr/bin/" + got
				}
				if path != want {
					t.Fatalf("path %q, want %q", path, want)
				}
			}
			if got != tt.wantName {
				t.Fatalf("got %q want %q", got, tt.wantName)
			}
		})
	}
}

func TestSystemHelpersAreNotResolvedThroughPath(t *testing.T) {
	// powershell.exe and osascript sit on PATH here, but not at the system location.
	for _, e := range []Env{
		func() Env { e := envOf("windows", nil); return e }(),
		envOf("darwin", nil),
	} {
		if tl, path := nativeFor(e); tl != nil {
			t.Errorf("%s: took %s from PATH", e.GOOS, path)
		}
		b, err := SelectWith(Env{GOOS: e.GOOS, Getenv: func(k string) string {
			if k == EnvBackend {
				return map[string]string{"windows": "powershell", "darwin": "osascript"}[e.GOOS]
			}
			return ""
		}, LookPath: e.LookPath, Exists: e.Exists})
		if b != nil || !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s forced: %v %v", e.GOOS, b, err)
		}
	}
}

func TestWindowsHelperUsesSystemRoot(t *testing.T) {
	e := envOf("windows", nil, "powershell.exe")
	e.SystemRoot = func() string { return `D:\WINNT` }
	e.Exists = func(p string) bool { return p == `D:\WINNT\System32\WindowsPowerShell\v1.0\powershell.exe` }
	if tl, path := nativeFor(e); tl == nil || path != `D:\WINNT\System32\WindowsPowerShell\v1.0\powershell.exe` {
		t.Fatalf("got %v %q", tl, path)
	}
	// No answer from the system falls back to C:\Windows.
	e.SystemRoot = func() string { return "" }
	e.Exists = func(p string) bool { return p == winPS }
	if tl, path := nativeFor(e); tl == nil || path != winPS {
		t.Fatalf("fallback: %v %q", tl, path)
	}
}

func TestSelectOrder(t *testing.T) {
	desktop := envOf("linux", map[string]string{"DISPLAY": ":0"}, "zenity")
	b, err := SelectWith(desktop)
	if err != nil || b.Name() != "zenity" {
		t.Fatalf("auto on a desktop: %v %v", b, err)
	}
	headless := envOf("linux", nil, "zenity")
	if b, err = SelectWith(headless); err != nil || b.Name() != "tty" {
		t.Fatalf("auto headless: %v %v", b, err)
	}
	// tty forces the terminal even on a desktop.
	forced := envOf("linux", map[string]string{"DISPLAY": ":0", EnvBackend: "tty"}, "zenity")
	if b, err = SelectWith(forced); err != nil || b.Name() != "tty" {
		t.Fatalf("tty override: %v %v", b, err)
	}
}

func TestSelectOverride(t *testing.T) {
	for _, tt := range []struct{ goos, name, program string }{
		{"windows", "powershell", "powershell.exe"},
		{"darwin", "osascript", "osascript"},
		{"linux", "zenity", "zenity"},
		{"linux", "kdialog", "kdialog"},
	} {
		e := envOf(tt.goos, map[string]string{EnvBackend: tt.name}, tt.program)
		b, err := SelectWith(e)
		if err != nil || b.Name() != tt.name {
			t.Errorf("%s: %v %v", tt.name, b, err)
		}
		// Named but not installed: unavailable, never a silent fall back to the tty.
		e = envOf(tt.goos, map[string]string{EnvBackend: tt.name})
		b, err = SelectWith(e)
		if b != nil || !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), tt.name) {
			t.Errorf("%s missing: %v %v", tt.name, b, err)
		}
	}
	// powershell named on a Windows service session
	e := envOf("windows", map[string]string{EnvBackend: "powershell"}, "powershell.exe")
	e.Interactive = func() bool { return false }
	if b, err := SelectWith(e); b != nil || !errors.Is(err, ErrUnavailable) {
		t.Errorf("service session: %v %v", b, err)
	}
	// An explicit name works without a display check on Linux (WSL runs powershell.exe).
	e = envOf("linux", map[string]string{EnvBackend: "powershell"}, "powershell.exe")
	if b, err := SelectWith(e); err != nil || b.Name() != "powershell" || b.(*native).path != wslPS {
		t.Errorf("powershell from linux: %v %v", b, err)
	}
	e = envOf("linux", map[string]string{EnvBackend: "powershell"})
	if b, err := SelectWith(e); b != nil || !errors.Is(err, ErrUnavailable) {
		t.Errorf("powershell from linux without WSL: %v %v", b, err)
	}
	b, err := SelectWith(envOf("linux", map[string]string{EnvBackend: "carrier-pigeon"}))
	if b != nil || !errors.Is(err, ErrUnknownBackend) {
		t.Errorf("unknown: %v %v", b, err)
	}
	b, err = SelectWith(envOf("linux", map[string]string{EnvTimeout: "9s"}))
	if b != nil || !errors.Is(err, ErrBadTimeout) {
		t.Errorf("bad timeout: %v %v", b, err)
	}
}

// TestManualPowerShellDialog opens the real dialog; run it by hand:
//
//	QBIT_VAULT_MANUAL_DIALOG=1 go test ./internal/prompt -run TestManualPowerShellDialog -v
//
// It reports the length of what you type, never the value.
func TestManualPowerShellDialog(t *testing.T) {
	if os.Getenv("QBIT_VAULT_MANUAL_DIALOG") != "1" {
		t.Skip("set QBIT_VAULT_MANUAL_DIALOG=1 to open the dialog")
	}
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell dialog test is for Windows")
	}
	b, err := SelectWith(Env{GOOS: "windows", Getenv: func(k string) string {
		if k == EnvBackend {
			return "powershell"
		}
		return ""
	}, LookPath: exec.LookPath})
	if err != nil {
		t.Fatal(err)
	}
	sec, err := b.Secret(SecretRequest{Name: "MANUAL_TEST", Reason: `try "quotes", 'apostrophes', $dollars and newline: a` + "\nb", Host: "test", Session: "test:1"})
	t.Logf("secret: err=%v len=%d", err, sec.Len())
	sec.Wipe()
	i, err := b.Choose("Pick the second one", []string{"first", "second", "deny"}, 0)
	t.Logf("choose: %d %v", i, err)
	yes, err := b.Confirm("Press Confirm")
	t.Logf("confirm: %v %v", yes, err)
}
