package prompt

import (
	"strings"
	"testing"
)

const unlockReason = "Claude Code wants to use A. Unlock the vault to continue."

// S5.1: the passphrase an agent call asks for says who asks and for what,
// under the heading "Vault passphrase".
func TestPassphraseReasonIsShownAboveTheEntry(t *testing.T) {
	req := VaultPassphrase
	req.Reason = unlockReason
	d := passphraseDialog(req, false)
	if d.heading != "Vault passphrase" || d.text != unlockReason+"\n\nVault passphrase:" {
		t.Fatalf("heading=%q text=%q", d.heading, d.text)
	}
	if again := passphraseDialog(req.Twice(), true); strings.Contains(again.text, "Claude Code") {
		t.Fatalf("the second entry repeats the reason: %q", again.text)
	}
	if plain := passphraseDialog(VaultPassphrase, false); plain.text != "Vault passphrase:" {
		t.Fatalf("a dialog without a reason changed: %q", plain.text)
	}
}

func TestPassphraseReasonIsEscapedInDialogAndTerminal(t *testing.T) {
	req := VaultPassphrase
	req.Reason = "Evil\x1b[2J wants to use A. Unlock the vault to continue."
	if d := passphraseDialog(req, false); strings.ContainsRune(d.text, 0x1b) {
		t.Fatalf("control character in the dialog: %q", d.text)
	}
	b, term := backendOf(fxPass)
	if _, err := b.Passphrase(req); err != nil {
		t.Fatal(err)
	}
	out := term.out.String()
	if strings.ContainsRune(out, 0x1b) || !strings.Contains(out, "wants to use A.") || strings.Contains(out, "TESTSECRET_") {
		t.Fatalf("terminal output = %q", out)
	}
}

func TestTTYPassphraseReasonLineComesFirst(t *testing.T) {
	req := VaultPassphrase
	req.Reason = unlockReason
	b, term := backendOf(fxPass)
	if _, err := b.Passphrase(req); err != nil {
		t.Fatal(err)
	}
	if got := term.out.String(); !strings.HasPrefix(got, unlockReason+"\nVault passphrase: ") {
		t.Fatalf("terminal output = %q", got)
	}
}
