package prompt

import (
	"fmt"
	"strings"
)

// dialogTitle is the window title of every native dialog; the heading inside
// says what it is.
const dialogTitle = "QBit Vault"

// secretDialog is the capture dialog: the request as headerRows lays it out.
func secretDialog(req SecretRequest) dialog {
	if req.Heading != "" {
		return dialog{kind: dialogSecret, title: dialogTitle, heading: escape(req.Heading), text: escape(req.Reason), visible: req.Visible, okLabel: "Continue", cancelLabel: "Cancel"}
	}
	rows := headerRows(req, true)
	input := "Paste or type the value. The agent never sees it:"
	if req.Visible {
		input = "Type the value (shown while you type):"
	}
	return dialog{
		kind:        dialogSecret,
		title:       dialogTitle,
		heading:     "Secret request",
		rows:        rows,
		tail:        input,
		text:        rowsText(rows) + "\n" + input,
		visible:     req.Visible,
		okLabel:     "Save",
		cancelLabel: "Cancel",
	}
}

// passphraseDialog asks one entry of a passphrase: the first, or the second
// when again.
func passphraseDialog(req PassphraseRequest, again bool) dialog {
	text := req.Label + ":"
	if again {
		text = req.again() + ":"
	} else if req.Reason != "" {
		text = escapeLines(req.Reason) + "\n\n" + text
	}
	return dialog{kind: dialogSecret, title: dialogTitle, heading: req.heading(), text: text, okLabel: "Continue", cancelLabel: "Cancel"}
}

// chooseDialog is a question with options. A question about letting an agent
// use a secret is a permission request; any other has no heading, the
// question says it all.
func chooseDialog(q string, options []string, def int) dialog {
	opts := make([]string, len(options))
	for i, o := range options {
		opts[i] = escape(o)
	}
	heading := ""
	if isPermission(options) {
		heading = "Permission request"
	}
	return dialog{kind: dialogChoose, title: dialogTitle, heading: heading, text: escapeLines(q), options: opts, def: def, okLabel: "Continue", cancelLabel: "Cancel"}
}

// isPermission reports whether the options answer a permission question: one
// of them refuses or defers the permission.
func isPermission(options []string) bool {
	for _, o := range options {
		l := strings.ToLower(o)
		if strings.HasPrefix(l, "don't ") || strings.Contains(l, "allow") || strings.Contains(l, "ask me before") {
			return true
		}
	}
	return false
}

func confirmDialog(q string) dialog {
	return dialog{kind: dialogConfirm, title: dialogTitle, heading: "Confirm", text: escapeLines(q), okLabel: "Confirm", cancelLabel: "Decline"}
}

// noDash keeps a row of text from reading as an option to helpers that take
// rows as positional arguments.
func noDash(s string) string {
	if strings.HasPrefix(s, "-") {
		return " " + s
	}
	return s
}

// numbered is "N) text", how osascript lists show and return an option.
func numbered(i int, o string) string { return fmt.Sprintf("%d) %s", i+1, o) }

// plain is the text of a dialog for the helpers that have no heading of their
// own: the heading, a blank line and the text.
func (d dialog) plain() string {
	if d.heading == "" {
		return d.text
	}
	return d.heading + "\n\n" + d.text
}

// removal reports whether a confirmation is about taking something away: the
// one dialog that wears a warning icon.
func (d dialog) removal() bool {
	l := strings.ToLower(d.text)
	return d.kind == dialogConfirm && (strings.Contains(l, "remove") || strings.Contains(l, "delete"))
}

// buttons are the labels of the accept and cancel buttons.
func (d dialog) buttons() (ok, cancel string) {
	ok, cancel = d.okLabel, d.cancelLabel
	if d.kind == dialogConfirm {
		ok, cancel = "Confirm", "Decline"
	}
	if ok == "" {
		ok = "OK"
	}
	if cancel == "" {
		cancel = "Cancel"
	}
	return ok, cancel
}

// retryDialog is the first entry of a passphrase asked again after a mismatch.
func retryDialog(req PassphraseRequest) dialog {
	d := passphraseDialog(req, false)
	d.text = mismatchText + " Try again.\n\n" + d.text
	return d
}
