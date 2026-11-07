package prompt

import (
	"reflect"
	"strings"
	"testing"
)

// S7.1, S7.7: every dialog has the one window title, the heading that says
// what it is, and buttons that say the action.
func TestEveryDialogHasOneTitleAHeadingAndActionButtons(t *testing.T) {
	permission := []string{"Once: only the next command", "Don't allow"}
	tests := []struct {
		name            string
		d               dialog
		heading, ok, no string
	}{
		{"secret", secretDialog(req), "Secret request", "Save", "Cancel"},
		{"form", formDialog(formReqs), "Secret request", "Save", "Cancel"},
		{"permission", chooseDialog("q", permission, 0), "Permission request", "Continue", "Cancel"},
		{"choice", chooseDialog("Where should A be saved?", []string{"All projects", "Only this project (shop)"}, 0), "", "Continue", "Cancel"},
		{"confirm", confirmDialog("Remove A (all projects)?"), "Confirm", "Confirm", "Decline"},
		{"recovery key", showDialog("Recovery key", "QVR1-X"), "Recovery key", "Done", "Cancel"},
		{"confirmation code", showDialog("Confirmation code", "123456"), "Confirmation code", "Done", "Cancel"},
		{"vault passphrase", passphraseDialog(VaultPassphrase, false), "Vault passphrase", "Continue", "Cancel"},
		{"export passphrase", passphraseDialog(ExportPassphrase, false), "Export passphrase", "Continue", "Cancel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.d.title != "QBit Vault" || tt.d.heading != tt.heading {
				t.Errorf("title/heading = %q / %q", tt.d.title, tt.d.heading)
			}
			if ok, no := tt.d.buttons(); ok != tt.ok || no != tt.no {
				t.Errorf("buttons = %q / %q, want %q / %q", ok, no, tt.ok, tt.no)
			}
			if strings.Contains(tt.d.title+tt.d.heading+tt.d.text, "qbit-vault:") {
				t.Errorf("a dialog still carries the qbit-vault: prefix: %+v", tt.d)
			}
		})
	}
}

// S7.6: the request lines go to the Windows dialog as a two-column grid, and
// S7.8: in a confirmation Decline is the highlighted button.
func TestPowerShellGridAndButtons(t *testing.T) {
	s := string(powershellTool{}.build("powershell.exe", secretDialog(req)).Stdin)
	prelude := s[:strings.Index(s, psBodyMarker)]
	for _, want := range []string{
		"$heading = Dec " + psString("Secret request"),
		"$rows = @((Dec " + psString("Who:") + "), (Dec " + psString("Claude Code (session sess-aaa)") + "), (Dec " + psString("Secret:") + ")",
		"$okLabel = Dec " + psString("Save"),
		"$cancelLabel = Dec " + psString("Cancel"),
		"$confirm = $false",
	} {
		if !strings.Contains(prelude, want) {
			t.Errorf("prelude lacks %q:\n%s", want, prelude)
		}
	}
	if !strings.Contains(s, "TableLayoutPanel") || strings.Contains(s, "qbit-vault: ") {
		t.Error("the request lines are not a grid")
	}
	c := string(powershellTool{}.build("powershell.exe", confirmDialog("Remove A?")).Stdin)
	for _, want := range []string{"$confirm = $true", "$okLabel = Dec " + psString("Confirm"), "$cancelLabel = Dec " + psString("Decline"), "$f.AcceptButton = $no", "if ($confirm) {"} {
		if !strings.Contains(c, want) {
			t.Errorf("confirm script lacks %q", want)
		}
	}
}

// S7.7, S7.12: the helpers that can set the button labels do, zenity dialogs
// are 480 wide and its lists have no headers.
func TestZenityShowAndFormLabels(t *testing.T) {
	f := &fakeRun{res: []result{ok("")}}
	if err := nativeOf(zenityTool{}, f).(Shower).Show("Recovery key", fxShown); err != nil {
		t.Fatal(err)
	}
	want := []string{"--text-info", "--title=QBit Vault", "--width=480", "--height=280", "--ok-label=Done", "--cancel-label=Cancel"}
	if !reflect.DeepEqual(f.cmds[0].Args, want) || string(f.cmds[0].Stdin) != "Recovery key\n\n"+fxShown {
		t.Errorf("args=%q stdin=%q", f.cmds[0].Args, f.cmds[0].Stdin)
	}
	for _, d := range []dialog{secretDialog(req), chooseDialog("q", []string{"a", "b"}, 0), confirmDialog("q")} {
		if !contains(zenityTool{}.build("z", d).Args, "--width=480") {
			t.Errorf("zenity %v dialog is not 480 wide", d.kind)
		}
	}
	if !contains(zenityTool{}.build("z", chooseDialog("q", []string{"a", "b"}, 0)).Args, "--hide-header") {
		t.Error("the zenity list still shows its Pick and Index headers")
	}
}

func contains(args []string, a string) bool {
	for _, x := range args {
		if x == a {
			return true
		}
	}
	return false
}

// S7.7: osascript shows the action in its buttons.
func TestOsascriptShowAndPassphraseButtons(t *testing.T) {
	s := string(osascriptTool{}.build("osascript", showDialog("Recovery key", "QVR1-X")).Stdin)
	if !strings.Contains(s, `buttons {"Cancel", "Done"} default button "Done" cancel button "Cancel" with icon note`) {
		t.Errorf("show script:\n%s", s)
	}
	s = string(osascriptTool{}.build("osascript", passphraseDialog(ExportPassphrase, false)).Stdin)
	if !strings.Contains(s, `with title "QBit Vault"`) || !strings.HasPrefix(s, `display dialog "Export passphrase\n\nExport passphrase (protects this backup file):"`) {
		t.Errorf("passphrase script:\n%s", s)
	}
}

// S7.10: the unknown backend names the valid ones.
func TestUnknownBackendListsTheValidOnes(t *testing.T) {
	_, err := SelectWith(Env{GOOS: "linux", Getenv: func(k string) string {
		if k == EnvBackend {
			return "bogus"
		}
		return ""
	}})
	if err == nil || !strings.Contains(err.Error(), `QBIT_VAULT_PROMPT="bogus"; use tty, osascript, powershell, zenity or kdialog`) {
		t.Errorf("err = %v", err)
	}
}
