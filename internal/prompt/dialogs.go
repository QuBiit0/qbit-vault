package prompt

import (
	"fmt"
	"strings"
)

// secretDialog is the capture dialog: the request as Header renders it, under
// a title of its own.
func secretDialog(req SecretRequest) dialog {
	_, body, _ := strings.Cut(Header(req), "\n")
	return dialog{
		kind:  dialogSecret,
		title: "gentle-vault: secret capture",
		text:  strings.TrimRight(body, "\n") + "\n\nValue (input is hidden):",
	}
}

func passphraseDialog(again bool) dialog {
	text := "Passphrase (input is hidden):"
	if again {
		text = "Confirm passphrase (input is hidden):"
	}
	return dialog{kind: dialogSecret, title: "gentle-vault: vault passphrase", text: text}
}

func chooseDialog(q string, options []string, def int) dialog {
	opts := make([]string, len(options))
	for i, o := range options {
		opts[i] = escape(o)
	}
	return dialog{kind: dialogChoose, title: "gentle-vault: choose", text: escape(q), options: opts, def: def}
}

func confirmDialog(q string) dialog {
	return dialog{kind: dialogConfirm, title: "gentle-vault: confirm", text: escape(q)}
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
