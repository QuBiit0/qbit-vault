package prompt

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ---- zenity ----

// zenityTool uses --entry --hide-text for a value, not --password: that dialog
// has no text, so it cannot show who asks and why (R-CAP-02).
type zenityTool struct{}

func (zenityTool) name() string    { return "zenity" }
func (zenityTool) program() string { return "zenity" }

func (zenityTool) build(path string, d dialog) command {
	var args []string
	switch d.kind {
	case dialogSecret:
		args = []string{"--entry", "--hide-text", "--no-markup", "--title=" + d.title, "--text=" + d.text}
	case dialogChoose:
		args = []string{"--list", "--radiolist", "--no-markup", "--title=" + d.title, "--text=" + d.text,
			"--column=Pick", "--column=Index", "--column=Option", "--hide-column=2", "--print-column=2"}
		for i, o := range d.options {
			picked := "FALSE"
			if i == d.def {
				picked = "TRUE"
			}
			args = append(args, picked, fmt.Sprint(i+1), noDash(o))
		}
	case dialogConfirm:
		args = []string{"--question", "--no-markup", "--title=" + d.title, "--text=" + d.text, "--ok-label=Confirm", "--cancel-label=Decline"}
	}
	return command{Path: path, Args: args}
}

func (zenityTool) classify(d dialog, r result) status { return exitOneIsNo(d, r.Exit) }

// exitOneIsNo reads the exit code zenity and kdialog share: 0 is an answer,
// 1 is Cancel on a value or a list and "No" on a question.
func exitOneIsNo(d dialog, exit int) status {
	switch exit {
	case 0:
		return statusOK
	case 1:
		if d.kind == dialogConfirm {
			return statusNo
		}
		return statusCancel
	}
	return statusFail
}

// ---- kdialog ----

type kdialogTool struct{}

func (kdialogTool) name() string    { return "kdialog" }
func (kdialogTool) program() string { return "kdialog" }

func (kdialogTool) build(path string, d dialog) command {
	args := []string{"--title", d.title}
	switch d.kind {
	case dialogSecret:
		args = append(args, "--password", d.text)
	case dialogChoose:
		args = append(args, "--radiolist", d.text)
		for i, o := range d.options {
			state := "off"
			if i == d.def {
				state = "on"
			}
			args = append(args, fmt.Sprint(i+1), noDash(o), state)
		}
	case dialogConfirm:
		args = append(args, "--yes-label", "Confirm", "--no-label", "Decline", "--yesno", d.text)
	}
	return command{Path: path, Args: args}
}

func (kdialogTool) classify(d dialog, r result) status {
	if r.Exit == 2 {
		return statusCancel
	}
	return exitOneIsNo(d, r.Exit)
}

// ---- osascript ----

type osascriptTool struct{}

func (osascriptTool) name() string    { return "osascript" }
func (osascriptTool) program() string { return "osascript" }

// build gives osascript its script on stdin. Every piece of text is an
// AppleScript string literal made by asString.
func (osascriptTool) build(path string, d dialog) command {
	var s strings.Builder
	switch d.kind {
	case dialogSecret:
		fmt.Fprintf(&s, `display dialog %s with title %s default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel" with icon caution`+"\n", asString(d.text), asString(d.title))
		s.WriteString("return text returned of result\n")
	case dialogChoose:
		items := make([]string, len(d.options))
		for i, o := range d.options {
			items[i] = asString(numbered(i, o))
		}
		fmt.Fprintf(&s, `set r to choose from list {%s} with prompt %s with title %s default items {%s} OK button name "OK" cancel button name "Cancel" without multiple selections allowed and without empty selection allowed`+"\n",
			strings.Join(items, ", "), asString(d.text), asString(d.title), items[d.def])
		s.WriteString("if r is false then error number -128\n")
		s.WriteString("return item 1 of r\n")
	case dialogConfirm:
		fmt.Fprintf(&s, `display dialog %s with title %s buttons {"Decline", "Confirm"} default button "Decline" cancel button "Decline" with icon caution`+"\n", asString(d.text), asString(d.title))
		s.WriteString("return button returned of result\n")
	}
	return command{Path: path, Args: []string{"-"}, Stdin: []byte(s.String())}
}

// classify: Cancel is AppleScript error -128 ("User canceled."); on a
// question the cancel button is Decline.
func (osascriptTool) classify(d dialog, r result) status {
	switch {
	case r.Exit == 0:
		return statusOK
	case strings.Contains(string(r.Stderr), "(-128)"):
		if d.kind == dialogConfirm {
			return statusNo
		}
		return statusCancel
	}
	return statusFail
}

// asString makes s an AppleScript string literal that cannot end early or
// run over a line: quote and backslash are escaped, newline, return and tab
// become their escapes, and any other control or format character, or invalid
// UTF-8, is shown as a visible \xNN or \uNNNN (backslash doubled).
func asString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\\x%02x`, s[i])
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsControl(r) && r < 0x100:
			fmt.Fprintf(&b, `\\x%02x`, r)
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			if r > 0xffff {
				fmt.Fprintf(&b, `\\U%08x`, r)
			} else {
				fmt.Fprintf(&b, `\\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += n
	}
	b.WriteByte('"')
	return b.String()
}
