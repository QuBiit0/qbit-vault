package prompttest

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/prompt"
)

func TestFakeScriptAndCalls(t *testing.T) {
	f := &Fake{Script: []Answer{{Value: "TESTSECRET_v"}, {Index: 1}, {Yes: true}, {Value: "TESTSECRET_p"}, {Err: prompt.ErrCancelled}}}
	s, err := f.Secret(prompt.SecretRequest{Name: "A_KEY"})
	if err != nil || string(s.Reveal()) != "TESTSECRET_v" || s.Name() != "A_KEY" {
		t.Fatalf("Secret: %v", err)
	}
	if i, err := f.Choose("q", []string{"a", "b"}, 0); err != nil || i != 1 {
		t.Fatalf("Choose: %d, %v", i, err)
	}
	if y, err := f.Confirm("sure?"); err != nil || !y {
		t.Fatalf("Confirm: %v, %v", y, err)
	}
	if p, err := f.Passphrase(prompt.VaultPassphrase.Twice()); err != nil || string(p.Reveal()) != "TESTSECRET_p" {
		t.Fatalf("Passphrase: %v", err)
	}
	if _, err := f.Confirm("again?"); !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("scripted error: %v", err)
	}
	if _, err := f.Confirm("more?"); !errors.Is(err, ErrScriptExhausted) {
		t.Fatalf("exhausted: %v", err)
	}
	kinds := ""
	for _, c := range f.Calls {
		kinds += c.Kind + " "
		if strings.Contains(c.Q+c.Request.Name, "TESTSECRET_") {
			t.Error("a call recorded an answer")
		}
	}
	if kinds != "secret choose confirm passphrase confirm confirm " || !f.Calls[3].Confirm {
		t.Errorf("calls = %q", kinds)
	}
}

func TestFakeUnavailable(t *testing.T) {
	f := &Fake{Unavailable: true, Script: []Answer{{Yes: true}}}
	if _, err := f.Confirm("q"); !errors.Is(err, prompt.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.Secret(prompt.SecretRequest{}); !errors.Is(err, prompt.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestStream(t *testing.T) {
	var out bytes.Buffer
	b := Stream(strings.NewReader("y\n  TESTSECRET_v \n2\n"), &out)
	if y, err := b.Confirm("ok?"); err != nil || !y {
		t.Fatalf("Confirm: %v, %v", y, err)
	}
	s, err := b.Secret(prompt.SecretRequest{Name: "A_KEY"})
	if err != nil || string(s.Reveal()) != "TESTSECRET_v" {
		t.Fatalf("Secret: %v", err)
	}
	if i, err := b.Choose("q", []string{"a", "b"}, 0); err != nil || i != 1 {
		t.Fatalf("Choose: %d, %v", i, err)
	}
	if _, err := b.Confirm("eof?"); !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("eof: %v", err)
	}
	if strings.Contains(out.String(), "TESTSECRET_") || !strings.Contains(out.String(), "ok? [y/N] ") {
		t.Errorf("out = %q", out.String())
	}
}
