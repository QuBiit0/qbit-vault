// Package secret holds the Secret type: a value that renders as [REDACTED]
// through every formatting, encoding and logging path.
package secret

import (
	"fmt"
	"log/slog"
)

// Redacted is the only text a Secret ever renders as.
const Redacted = "[REDACTED]"

// payload lives behind a pointer on purpose. fmt does not call methods on
// unexported struct fields, so a Secret stored by value inside another struct
// would print its raw bytes if they were held inline. Behind a pointer, fmt
// prints only an address.
type payload struct {
	name string
	b    []byte
}

// Secret is a named secret value. The zero value is safe and empty.
type Secret struct {
	p *payload
}

// New copies value into a new Secret.
func New(name string, value []byte) Secret {
	b := make([]byte, len(value))
	copy(b, value)
	return Secret{p: &payload{name: name, b: b}}
}

// Name returns the secret's name.
func (s Secret) Name() string {
	if s.p == nil {
		return ""
	}
	return s.p.name
}

// Len returns the value length in bytes.
func (s Secret) Len() int {
	if s.p == nil {
		return 0
	}
	return len(s.p.b)
}

// Reveal returns a copy of the value. Only internal/exec may call it; the
// caller must wipe the returned slice when done.
func (s Secret) Reveal() []byte {
	if s.p == nil {
		return nil
	}
	out := make([]byte, len(s.p.b))
	copy(out, s.p.b)
	return out
}

// Wipe zeroes the stored bytes. Copies of the Secret share the payload and
// are wiped too.
func (s Secret) Wipe() {
	if s.p == nil {
		return
	}
	clear(s.p.b)
}

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer.
func (Secret) GoString() string { return Redacted }

// Format implements fmt.Formatter for every verb and flag combination.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }
