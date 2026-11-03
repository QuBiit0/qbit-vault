package prompt

import "bytes"

// inputKind selects how typed input is normalized.
type inputKind int

const (
	// valueInput is a secret value: surrounding whitespace is trimmed
	// (R-CAP-04), with the same bytes.TrimSpace rule as `set --stdin`.
	valueInput inputKind = iota
	// passphraseInput is a passphrase: only the line terminator is removed,
	// never other whitespace, so the same passphrase derives the same key
	// whichever backend read it (and `init --passphrase-stdin`).
	passphraseInput
)

// normalize applies one rule for every backend. The terminal readers already
// drop the line terminator; native helpers print the value followed by one.
// The result aliases b.
func normalize(b []byte, kind inputKind) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if kind == valueInput {
		return bytes.TrimSpace(b)
	}
	return b
}
