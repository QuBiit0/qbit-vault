package redact

import (
	"bytes"
	"encoding/base64"
	"unicode/utf8"
)

// The encoders below are hand-written (instead of using net/url and
// encoding/json) so the secret never passes through an immutable string that
// cannot be wiped. encode_test.go checks each one against the standard
// library.

const hexLower = "0123456789abcdef"
const hexUpper = "0123456789ABCDEF"

func hexDigits(upper bool) string {
	if upper {
		return hexUpper
	}
	return hexLower
}

// b64 encodes v with enc into a fresh slice.
func b64(enc *base64.Encoding, v []byte) []byte {
	out := make([]byte, enc.EncodedLen(len(v)))
	enc.Encode(out, v)
	return out
}

type pctMode int

const (
	pctQuery  pctMode = iota // url.QueryEscape: space becomes '+'
	pctPath                  // url.PathEscape: keeps $&+=:@
	pctStrict                // RFC 3986 unreserved only, space becomes %20
	pctPython                // urllib.parse.quote: unreserved plus '/'
	pctJS                    // encodeURIComponent: unreserved plus !*'()
)

func pctKeep(c byte, mode pctMode) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '~':
		return true
	}
	switch mode {
	case pctPath:
		return c == '$' || c == '&' || c == '+' || c == '=' || c == ':' || c == '@'
	case pctPython:
		return c == '/'
	case pctJS:
		return c == '!' || c == '*' || c == '\'' || c == '(' || c == ')'
	}
	return false
}

// escapeSlashes escapes every '/' as `\/` (PHP, some JSON emitters).
func escapeSlashes(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("/"), []byte(`\/`))
}

// percent percent-encodes v. lower selects lowercase hex digits.
func percent(v []byte, mode pctMode, lower bool) []byte {
	digits := hexDigits(!lower)
	out := make([]byte, 0, len(v)*3)
	for _, c := range v {
		switch {
		case pctKeep(c, mode):
			out = append(out, c)
		case c == ' ' && mode == pctQuery:
			out = append(out, '+')
		default:
			out = append(out, '%', digits[c>>4], digits[c&15])
		}
	}
	return out
}

// jsonEscape returns the body of the JSON string literal for v (no
// surrounding quotes). html escapes <, > and & as encoding/json does by
// default; ascii escapes every non-ASCII rune as \uXXXX (Python's default);
// upper selects uppercase hex digits in \u escapes. Invalid UTF-8 becomes
// the replacement character (escaped when ascii). U+2028 and U+2029 are always escaped, as encoding/json does.
func jsonEscape(v []byte, html, ascii, upper bool) []byte {
	digits := hexDigits(upper)
	u := func(out []byte, r rune) []byte {
		return append(out, '\\', 'u',
			digits[r>>12&15], digits[r>>8&15], digits[r>>4&15], digits[r&15])
	}
	out := make([]byte, 0, len(v)+8)
	for i := 0; i < len(v); {
		c := v[i]
		if c < utf8.RuneSelf {
			i++
			switch {
			case c == '"' || c == '\\':
				out = append(out, '\\', c)
			case c == '\n':
				out = append(out, '\\', 'n')
			case c == '\r':
				out = append(out, '\\', 'r')
			case c == '\t':
				out = append(out, '\\', 't')
			case c == '\b':
				out = append(out, '\\', 'b')
			case c == '\f':
				out = append(out, '\\', 'f')
			case c < 0x20, html && (c == '<' || c == '>' || c == '&'):
				out = u(out, rune(c))
			default:
				out = append(out, c)
			}
			continue
		}
		r, size := utf8.DecodeRune(v[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// encoding/json substitutes the replacement character.
			if ascii {
				out = u(out, utf8.RuneError)
			} else {
				out = utf8.AppendRune(out, utf8.RuneError)
			}
		case r == '\u2028' || r == '\u2029':
			out = u(out, r)
		case ascii && r > 0xFFFF:
			r -= 0x10000
			out = u(out, 0xD800+(r>>10))
			out = u(out, 0xDC00+(r&0x3FF))
		case ascii:
			out = u(out, r)
		default:
			out = append(out, v[i:i+size]...)
		}
		i += size
	}
	return out
}

// innerBase64 returns the base64 characters that depend only on v when v is
// preceded by align (0..2) unknown bytes and followed by unknown bytes. This
// is the substring that survives when v is embedded in a larger blob such as
// HTTP Basic credentials.
func innerBase64(enc *base64.Encoding, v []byte, align int) []byte {
	buf := make([]byte, align+len(v))
	copy(buf[align:], v)
	full := b64(enc.WithPadding(base64.NoPadding), buf)
	clear(buf)
	start := (8*align + 5) / 6
	end := 8 * (align + len(v)) / 6
	var out []byte
	if start < end {
		out = append(out, full[start:end]...)
	}
	clear(full)
	return out
}
