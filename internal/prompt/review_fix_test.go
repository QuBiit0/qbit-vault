package prompt

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// zenity and kdialog come from fixed system directories, never from PATH: a
// caller who controls PATH must not be able to substitute a helper.
func TestLinuxHelpersComeFromSystemDirs(t *testing.T) {
	env := func(exists ...string) Env {
		return Env{
			GOOS:   "linux",
			Getenv: func(k string) string { return map[string]string{"DISPLAY": ":0"}[k] },
			LookPath: func(n string) (string, error) {
				return "/evil/" + n, nil // a planted look-alike on PATH
			},
			Exists: func(p string) bool {
				for _, e := range exists {
					if p == e {
						return true
					}
				}
				return false
			},
		}
	}
	tests := []struct {
		name   string
		exists []string
		want   string
	}{
		{"usr bin", []string{"/usr/bin/zenity"}, "/usr/bin/zenity"},
		{"bin", []string{"/bin/kdialog"}, "/bin/kdialog"},
		{"usr local bin", []string{"/usr/local/bin/zenity"}, "/usr/local/bin/zenity"},
		{"usr bin wins over usr local", []string{"/usr/local/bin/zenity", "/usr/bin/zenity"}, "/usr/bin/zenity"},
		{"only on PATH", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, path := nativeFor(env(tt.exists...))
			if path != tt.want {
				t.Fatalf("path %q, want %q", path, tt.want)
			}
		})
	}
	b, err := SelectWith(Env{GOOS: "linux", Getenv: func(k string) string {
		if k == EnvBackend {
			return "zenity"
		}
		return ""
	}, LookPath: env().LookPath, Exists: env().Exists})
	if b != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forced zenity from PATH: %v %v", b, err)
	}
}

// A value longer than the read bound is refused, never truncated, on every
// backend.
func TestOversizeIsRefused(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxInput+10)

	t.Run("hidden terminal read", func(t *testing.T) {
		in := append(append([]byte{}, big...), '\r')
		got, err := readHidden(bytes.NewReader(in), &bytes.Buffer{}, func() {})
		if !errors.Is(err, ErrTooLarge) || got != nil {
			t.Fatalf("got %d bytes, %v", len(got), err)
		}
	})
	t.Run("terminal line read", func(t *testing.T) {
		in := append(append([]byte{}, big...), '\n')
		got, err := readLine(bytes.NewReader(in))
		if !errors.Is(err, ErrTooLarge) || got != nil {
			t.Fatalf("got %d bytes, %v", len(got), err)
		}
	})
	t.Run("native helper", func(t *testing.T) {
		f := &fakeRun{err: ErrTooLarge}
		sec, err := nativeOf(zenityTool{}, f).Secret(req)
		if !errors.Is(err, ErrTooLarge) || sec.Len() != 0 {
			t.Fatalf("got %d bytes, %v", sec.Len(), err)
		}
	})
	t.Run("exec runner", func(t *testing.T) {
		r, err := execRunner(context.Background(), helper("flood", ""))
		if !errors.Is(err, ErrTooLarge) || len(r.Stdout) != 0 {
			t.Fatalf("flood: %d bytes, %v", len(r.Stdout), err)
		}
	})
	if !strings.Contains(ErrTooLarge.Error(), "64 KiB") {
		t.Fatalf("message %q", ErrTooLarge)
	}
}

// Normalization is the same on every backend: values are trimmed (R-CAP-04),
// passphrases only lose their line terminator, so a passphrase typed in the
// dialog and on the terminal derives the same key.
func TestNormalizationMatchesAcrossBackends(t *testing.T) {
	const pass = "  TESTSECRET_pass word  "
	const value = "  TESTSECRET_value  "

	f := &fakeRun{res: []result{ok(pass + "\r\n")}}
	nsec, err := nativeOf(zenityTool{}, f).Passphrase(VaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := backendOf(pass)
	tsec, err := b.Passphrase(VaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if string(nsec.Reveal()) != pass || string(tsec.Reveal()) != pass {
		t.Fatalf("passphrase: native kept %d bytes, terminal kept %d, want %d", nsec.Len(), tsec.Len(), len(pass))
	}

	f = &fakeRun{res: []result{ok(value + "\n")}}
	nval, err := nativeOf(kdialogTool{}, f).Secret(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = backendOf(value)
	tval, err := b.Secret(req)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(value)
	if string(nval.Reveal()) != want || string(tval.Reveal()) != want {
		t.Fatalf("value: native %d bytes, terminal %d, want %d", nval.Len(), tval.Len(), len(want))
	}
}

var _ = exec.ErrNotFound
