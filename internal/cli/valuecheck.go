package cli

import (
	"bytes"
	"unicode/utf8"

	"github.com/QuBiit0/qbit-vault/internal/prompt"
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
	quoted := len(v) >= 2 && v[0] == v[len(v)-1] && (v[0] == '"' || v[0] == '\'' || v[0] == '`')
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
		problem = "starts and ends with quotes and has invisible characters"
	case quoted:
		problem = "starts and ends with quotes"
	case hidden:
		problem = "has invisible characters"
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
	q := "The value of " + name + " " + problem + ". Keys and tokens usually don't, and a pasted extra breaks the login. Save it:"
	i, err := ask.Choose(q, []string{"Without them (recommended)", "Exactly as typed", "Cancel"}, 0)
	switch {
	case err != nil:
		clear(fixed)
		return nil, err
	case i == 0 && len(fixed) > 0:
		return fixed, nil
	case i == 1:
		clear(fixed)
		return bytes.Clone(v), nil
	default:
		clear(fixed)
		return nil, prompt.ErrCancelled
	}
}
