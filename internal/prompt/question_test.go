package prompt

import (
	"strings"
	"testing"
)

// S4.2: a question that is not a secret request (the joiner's confirmation
// code) has its own frame: the heading and the question, none of the request
// lines of a capture.
var codeReq = SecretRequest{Name: "confirmation code", Heading: "Confirmation code", Host: "cli",
	Reason: "Type the confirmation code shown on the device that approved this one"}

func TestHeadingRequestHasItsOwnDialog(t *testing.T) {
	d := secretDialog(codeReq)
	if d.heading != "Confirmation code" || d.text != codeReq.Reason || d.visible || len(d.rows) != 0 || d.tail != "" {
		t.Fatalf("dialog = %+v", d)
	}
	if ok, no := d.buttons(); ok != "Continue" || no != "Cancel" {
		t.Errorf("buttons = %q / %q", ok, no)
	}
	if strings.Contains(d.plain(), "Saved in") || strings.Contains(d.plain(), "Who:") || strings.Contains(d.plain(), "Value") {
		t.Errorf("text still carries the request lines: %q", d.plain())
	}
	// The question is escaped like any other text.
	e := secretDialog(SecretRequest{Heading: "H", Reason: "a\nb\x1b"})
	if e.text != `a\nb\x1b` {
		t.Errorf("text = %q", e.text)
	}
}

func TestHeadingRequestOnTheTerminal(t *testing.T) {
	ft := &fakeTerm{nextValue: "ABCD-EFGH"}
	b := New(func() (Terminal, error) { return ft, nil })
	s, err := b.Secret(codeReq)
	if err != nil || string(s.Reveal()) != "ABCD-EFGH" {
		t.Fatalf("err=%v", err)
	}
	out := ft.out.String()
	if !strings.Contains(out, "Confirmation code") || !strings.Contains(out, codeReq.Reason) {
		t.Errorf("out = %q", out)
	}
	for _, bad := range []string{"secret request", "Who:", "Secret:", "Why:", "Saved in", "Value"} {
		if strings.Contains(out, bad) {
			t.Errorf("out has %q: %q", bad, out)
		}
	}
	if ft.hidden != 1 || ft.echoed != 0 || strings.Contains(out, "ABCD-EFGH") {
		t.Errorf("hidden=%d echoed=%d out=%q", ft.hidden, ft.echoed, out)
	}
}

func TestHeadingRequestOnEveryNativeHelper(t *testing.T) {
	d := secretDialog(codeReq)
	if s := string(powershellTool{}.build("powershell.exe", d).Stdin); !strings.Contains(s, "$heading = Dec "+psString("Confirmation code")) || strings.Contains(s, "Saved in") {
		t.Errorf("powershell:\n%s", s)
	}
	if s := string(osascriptTool{}.build("osascript", d).Stdin); !strings.HasPrefix(s, `display dialog "Confirmation code\n\nType the confirmation code`) || strings.Contains(s, "Saved in") {
		t.Errorf("osascript:\n%s", s)
	}
	for _, a := range (zenityTool{}).build("zenity", d).Args {
		if strings.Contains(a, "Saved in") {
			t.Errorf("zenity arg %q", a)
		}
	}
	for _, a := range (kdialogTool{}).build("kdialog", d).Args {
		if strings.Contains(a, "Saved in") {
			t.Errorf("kdialog arg %q", a)
		}
	}
}
