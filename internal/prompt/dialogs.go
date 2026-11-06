package prompt

import (
	"fmt"
	"strings"
)

// secretDialog is the capture dialog: the request as Header renders it, under
// a title of its own.
func secretDialog(req SecretRequest) dialog {
	_, body, _ := strings.Cut(Header(req), "\n")
	input := "Type or paste the value. It stays hidden and the agent never sees it:"
	if req.Visible {
		input = "Type the value. It is shown as you type:"
	}
	return dialog{
		kind:    dialogSecret,
		title:   "QBit Vault: secret request",
		text:    strings.TrimRight(body, "\n") + "\n\n" + input,
		visible: req.Visible,
	}
}

func passphraseDialog(again bool) dialog {
	text := "Vault passphrase (hidden):"
	if again {
		text = "Type the passphrase again to confirm (hidden):"
	}
	return dialog{kind: dialogSecret, title: "QBit Vault: vault passphrase", text: text}
}

func chooseDialog(q string, options []string, def int) dialog {
	opts := make([]string, len(options))
	for i, o := range options {
		opts[i] = escape(o)
	}
	return dialog{kind: dialogChoose, title: "QBit Vault", text: escape(q), options: opts, def: def}
}

func confirmDialog(q string) dialog {
	return dialog{kind: dialogConfirm, title: "QBit Vault: confirm", text: escape(q)}
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
