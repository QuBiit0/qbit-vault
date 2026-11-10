package secret_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/secret"
)

const fixture = "TESTSECRET_value_0123456789"

const redacted = "[REDACTED]"

// leaks reports whether s contains the fixture or its hex form. Failure
// messages must never print s itself.
func leaks(s string) bool {
	return strings.Contains(s, fixture) ||
		strings.Contains(s, fmt.Sprintf("%x", fixture)) ||
		strings.Contains(s, fmt.Sprintf("%X", fixture))
}

func newFixture() secret.Secret { return secret.New("API_KEY", []byte(fixture)) }

func TestVerbsRedact(t *testing.T) {
	s := newFixture()
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%10s", "%-10v", "%08d", "%c", "%U", "%e"}
	for _, v := range verbs {
		for _, arg := range []any{s, &s} {
			t.Run(v, func(t *testing.T) {
				out := fmt.Sprintf(v, arg)
				if leaks(out) {
					t.Fatalf("verb %s leaked (len %d)", v, len(out))
				}
				if !strings.Contains(out, redacted) {
					t.Fatalf("verb %s did not produce the redaction token (len %d)", v, len(out))
				}
			})
		}
	}
}

func TestStringers(t *testing.T) {
	s := newFixture()
	if s.String() != redacted {
		t.Fatal("String() is not the redaction token")
	}
	if s.GoString() != redacted {
		t.Fatal("GoString() is not the redaction token")
	}
	txt, err := s.MarshalText()
	if err != nil || string(txt) != redacted {
		t.Fatal("MarshalText() is not the redaction token")
	}
}

type exported struct {
	Name string
	Key  secret.Secret
}

type unexported struct {
	name string
	key  secret.Secret
}

type nested struct {
	Inner *exported
}

func TestSecretInsideContainers(t *testing.T) {
	values := map[string]any{
		"exported field":    exported{"n", newFixture()},
		"unexported field":  unexported{"n", newFixture()},
		"slice":             []secret.Secret{newFixture(), newFixture()},
		"map value":         map[string]secret.Secret{"k": newFixture()},
		"pointer to struct": &exported{"n", newFixture()},
		"nested pointer":    nested{Inner: &exported{"n", newFixture()}},
		"pointer slice":     []*secret.Secret{ptr(newFixture())},
		"interface slice":   []any{newFixture()},
	}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			t.Run(name+" "+verb, func(t *testing.T) {
				out := fmt.Sprintf(verb, v)
				if leaks(out) {
					t.Fatalf("leaked (len %d)", len(out))
				}
			})
		}
	}
}

func ptr(s secret.Secret) *secret.Secret { return &s }

func TestJSON(t *testing.T) {
	s := newFixture()

	direct, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(direct) != `"`+redacted+`"` {
		t.Fatalf("direct JSON is not the redaction token (len %d)", len(direct))
	}

	for name, v := range map[string]any{
		"struct":  exported{"n", s},
		"pointer": &exported{"n", s},
		"map":     map[string]secret.Secret{"k": s},
		"slice":   []secret.Secret{s},
		"nested":  nested{Inner: &exported{"n", s}},
	} {
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if leaks(string(out)) || !bytes.Contains(out, []byte(redacted)) {
			t.Fatalf("%s: bad JSON (len %d)", name, len(out))
		}
	}

	indented, err := json.MarshalIndent(exported{"n", s}, "", "  ")
	if err != nil || leaks(string(indented)) {
		t.Fatal("indented JSON leaked or failed")
	}
}

func TestSlog(t *testing.T) {
	s := newFixture()
	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(mk(&buf))
			l.Info("msg", "key", s, "ptr", &s, slog.Group("g", slog.Any("inner", s)))
			l.Info("msg", slog.Any("s", exported{"n", s}))
			out := buf.String()
			if leaks(out) {
				t.Fatalf("slog leaked (len %d)", len(out))
			}
			if !strings.Contains(out, redacted) {
				t.Fatalf("slog output lacks the redaction token (len %d)", len(out))
			}
		})
	}
}

func TestErrorAndPanicFormatting(t *testing.T) {
	s := newFixture()

	err := fmt.Errorf("failed with %v", s)
	if leaks(err.Error()) {
		t.Fatal("fmt.Errorf leaked")
	}
	wrapped := errors.Join(err, fmt.Errorf("again %+v", &s))
	if leaks(wrapped.Error()) {
		t.Fatal("joined error leaked")
	}

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected a panic")
			}
			for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
				if leaks(fmt.Sprintf(verb, r)) {
					t.Fatalf("recovered panic leaked with %s", verb)
				}
			}
		}()
		panic(s)
	}()
}

func TestRevealReturnsIndependentCopy(t *testing.T) {
	s := newFixture()
	got := s.Reveal()
	if string(got) != fixture {
		t.Fatal("Reveal did not return the stored value")
	}
	got[0] = 'X'
	if string(s.Reveal()) != fixture {
		t.Fatal("mutating the Reveal result changed the secret")
	}
}

func TestNewCopiesInput(t *testing.T) {
	in := []byte(fixture)
	s := secret.New("N", in)
	in[0] = 'X'
	if string(s.Reveal()) != fixture {
		t.Fatal("mutating the input changed the secret")
	}
}

func TestNameAndLen(t *testing.T) {
	s := newFixture()
	if s.Name() != "API_KEY" {
		t.Fatal("unexpected name")
	}
	if s.Len() != len(fixture) {
		t.Fatal("unexpected length")
	}
}

func TestWipe(t *testing.T) {
	s := newFixture()
	view := s // copies share the payload pointer
	s.Wipe()
	for _, b := range view.Reveal() {
		if b != 0 {
			t.Fatal("bytes not zeroed")
		}
	}
	if s.Len() != len(fixture) {
		t.Fatal("Wipe should keep the length")
	}
}

func TestZeroValue(t *testing.T) {
	var s secret.Secret
	if s.Name() != "" || s.Len() != 0 || len(s.Reveal()) != 0 {
		t.Fatal("zero value not empty")
	}
	s.Wipe()
	if fmt.Sprintf("%v %s %#v", s, s, s) != strings.Join([]string{redacted, redacted, redacted}, " ") {
		t.Fatal("zero value does not print redacted")
	}
	out, err := json.Marshal(s)
	if err != nil || string(out) != `"`+redacted+`"` {
		t.Fatal("zero value JSON is not redacted")
	}
}
