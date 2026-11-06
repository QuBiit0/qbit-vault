package prompt

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// A text field (R-CAP-09) is visible while typed; a secret one stays masked.
var textReq = SecretRequest{Name: "DB_HOST", Reason: "run the shop-api migrations", Host: "pi", Session: "pi:abcd1234",
	Label: "Host", Visible: true, Field: 1, Fields: 3}

func TestHeaderShowsFieldAndInput(t *testing.T) {
	h := Header(textReq)
	if !strings.Contains(h, "  Field:    1 of 3 (Host)\n") || !strings.Contains(h, "  Value:    new (shown as you type)\n") {
		t.Fatalf("header=%q", h)
	}
	if one := Header(SecretRequest{Name: "A", Reason: "x y z"}); strings.Contains(one, "Field:") {
		t.Fatalf("single field shows a field line: %q", one)
	}
}

func TestSecretDialogVisibleText(t *testing.T) {
	d := secretDialog(textReq)
	if !d.visible || !strings.HasSuffix(d.text, "Type the value. It is shown as you type:") {
		t.Fatalf("dialog=%+v", d)
	}
	if h := secretDialog(req); h.visible || !strings.HasSuffix(h.text, "Type or paste the value. It stays hidden and the agent never sees it:") || h.title != "QBit Vault: secret request" {
		t.Fatalf("hidden dialog=%+v", h)
	}
}

func TestVisibleBuilders(t *testing.T) {
	d := secretDialog(textReq)
	if got := (zenityTool{}).build("/usr/bin/zenity", d).Args; !reflect.DeepEqual(got, []string{"--entry", "--no-markup", "--title=" + d.title, "--text=" + d.text}) {
		t.Errorf("zenity: %q", got)
	}
	if got := (kdialogTool{}).build("kdialog", d).Args; !reflect.DeepEqual(got, []string{"--title", d.title, "--inputbox", strings.ReplaceAll(d.text, "\n", "<br>")}) {
		t.Errorf("kdialog: %q", got)
	}
	if got := string((osascriptTool{}).build("/usr/bin/osascript", d).Stdin); strings.Contains(got, "hidden answer") || !strings.Contains(got, `default answer ""`) {
		t.Errorf("osascript: %s", got)
	}
	ps := psScript(d)
	if !strings.Contains(ps, "$hide = $false\n") || !strings.Contains(ps, "$tb.UseSystemPasswordChar = $hide") {
		t.Errorf("powershell visible prelude missing")
	}
	if !strings.Contains(psScript(secretDialog(req)), "$hide = $true\n") {
		t.Errorf("powershell hidden prelude missing")
	}
}

// fakeTerm records which read the backend used.
type fakeTerm struct {
	out       strings.Builder
	hidden    int
	echoed    int
	nextValue string
}

func (f *fakeTerm) Write(p []byte) (int, error) { return f.out.Write(p) }
func (f *fakeTerm) ReadLine(context.Context) ([]byte, error) {
	f.echoed++
	return []byte(f.nextValue), nil
}
func (f *fakeTerm) ReadHidden(context.Context) ([]byte, error) {
	f.hidden++
	return []byte(f.nextValue), nil
}
func (*fakeTerm) Close() error { return nil }

func TestTTYVisibleFieldEchoes(t *testing.T) {
	ft := &fakeTerm{nextValue: "db.internal"}
	b := New(func() (Terminal, error) { return ft, nil })
	s, err := b.Secret(textReq)
	if err != nil || string(s.Reveal()) != "db.internal" {
		t.Fatalf("err=%v", err)
	}
	if ft.echoed != 1 || ft.hidden != 0 || !strings.Contains(ft.out.String(), "Value (shown as you type): ") {
		t.Fatalf("echoed=%d hidden=%d out=%q", ft.echoed, ft.hidden, ft.out.String())
	}
	ft2 := &fakeTerm{nextValue: "x"}
	if _, err := New(func() (Terminal, error) { return ft2, nil }).Secret(req); err != nil || ft2.hidden != 1 || ft2.echoed != 0 {
		t.Fatalf("secret field: hidden=%d echoed=%d", ft2.hidden, ft2.echoed)
	}
}
