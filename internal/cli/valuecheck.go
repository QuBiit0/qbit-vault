package cli

import (
	"bytes"
	"unicode/utf8"

	"github.com/qbitdevz/qbit-vault/internal/prompt"
)

// invisible are characters a value almost never means to hold but a copy from
// a web page or a document often carries: zero-width space, joiners, word
// joiner, byte-order mark, no-break space and soft hyphen.
var invisible = map[rune]bool{
	'\u200b': true, '\u200c': true, '\u200d': true, '\u2060': true,
	'\ufeff': true, '\u00a0': true, '\u00ad': true,
}

// valueIssues looks for what a paste adds by mistake: one matching pair of
// surrounding quotes and invisible characters. It returns a problem in plain
// words and the value without them, or "" and nil when the value is clean.
// The fixed value is a fresh slice; v is not changed.
func valueIssues(v []byte) (problem string, fixed []byte) {
	// A pair only counts with something inside: `""` alone is left as typed.
	quoted := len(v) >= 3 && v[0] == v[len(v)-1] && (v[0] == '"' || v[0] == '\'' || v[0] == '`')
	hidden := false
	out := make([]byte, 0, len(v))
	for i := 0; i < len(v); {
		r, n := utf8.DecodeRune(v[i:])
		if invisible[r] {
			hidden = true
		} else {
			out = append(out, v[i:i+n]...)
		}
		i += n
	}
	if quoted {
		out = bytes.Clone(out[1 : len(out)-1])
	}
	switch {
	case quoted && hidden:
		problem = "has quotes around it and invisible characters in it"
	case quoted:
		problem = "has quotes around it"
	case hidden:
		problem = "has invisible characters in it"
	default:
		clear(out)
		return "", nil
	}
	return problem, out
}

// reviewValue asks before saving a value that looks pasted with extras. A
// clean value passes with no question. The answer keeps the fixed value, the
// value as typed, or cancels (prompt.ErrCancelled, so callers treat it like a
// cancelled dialog). The result is a fresh slice the caller wipes; v is not
// changed.
func reviewValue(ask prompt.Backend, name string, v []byte) ([]byte, error) {
	problem, fixed := valueIssues(v)
	if problem == "" {
		return bytes.Clone(v), nil
	}
	q := "The value of " + name + " " + problem + ". Most keys and tokens don't, and extra characters break logins. Which one should be saved?"
	// Without the extras nothing may be left (a value of invisible characters
	// only): then that choice is not offered, rather than saving nothing.
	const withoutThem, asTyped, cancel = "Without them (recommended)", "Keep it as typed", "Cancel"
	opts := []string{withoutThem, asTyped, cancel}
	if len(fixed) == 0 {
		opts = opts[1:]
	}
	i, err := ask.Choose(q, opts, 0)
	if err != nil {
		clear(fixed)
		return nil, err
	}
	switch opts[i] {
	case withoutThem:
		return fixed, nil
	case asTyped:
		clear(fixed)
		return bytes.Clone(v), nil
	default:
		clear(fixed)
		return nil, prompt.ErrCancelled
	}
}
