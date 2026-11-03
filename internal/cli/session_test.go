package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/keychain"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

const (
	fxPass = "TESTSECRET_passphrase_0123456789"
	fxVal  = "TESTSECRET_value_0123456789"
)

// harness runs the CLI against one temporary vault home.
type harness struct {
	t    *testing.T
	home string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", "") // never let the passphrase unlock cache leave the test
	return &harness{t: t, home: filepath.Join(t.TempDir(), "vault-home")}
}

// run executes the CLI with stdin and returns exit code, stdout and stderr.
func (h *harness) run(stdin string, args ...string) (int, string, string) {
	h.t.Helper()
	return h.runExtra(stdin, nil, args...)
}

func (h *harness) runExtra(stdin string, extra []func(*globals) *cobra.Command, args ...string) (int, string, string) {
	h.t.Helper()
	stdinOverride = strings.NewReader(stdin)
	h.t.Cleanup(func() { stdinOverride = nil })
	var out, errb bytes.Buffer
	full := append([]string{"--home", h.home}, args...)
	code := execute(full, &out, &errb, envFrom(nil), extra...)
	return code, out.String(), errb.String()
}

// mustRun fails the test unless the command exits 0.
func (h *harness) mustRun(stdin string, args ...string) string {
	h.t.Helper()
	code, out, errs := h.run(stdin, args...)
	if code != exitcode.OK {
		h.t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, out, errs)
	}
	return out
}

// probe is a test-only command that opens the vault session and nothing else.
func probe(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:  "probe",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "opened")
			return err
		},
	}
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestSessionNotInitialized(t *testing.T) {
	h := newHarness(t)
	const msg = "no vault here; run 'gentle-vault init'"
	code, out, errs := h.runExtra("", []func(*globals) *cobra.Command{probe}, "probe")
	if code != exitcode.Failure || out != "" || errs != "error: "+msg+"\n" {
		t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = h.runExtra("", []func(*globals) *cobra.Command{probe}, "--json", "probe")
	want := `{"ok":false,"error":{"code":"not_initialized","message":"` + msg + `"}}` + "\n"
	if code != exitcode.Failure || out != want || errs != "" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(h.home); !os.IsNotExist(err) {
		t.Fatal("a failed open created the vault home")
	}
}

func TestSessionOpensInitializedVault(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "init")
	code, out, errs := h.runExtra("", []func(*globals) *cobra.Command{probe}, "probe")
	if code != exitcode.OK || out != "opened\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestSessionRefusals(t *testing.T) {
	t.Run("key missing from keychain is vault_locked", func(t *testing.T) {
		h := newHarness(t)
		h.mustRun("", "init")
		id, err := vault.ReadID(h.home)
		if err != nil {
			t.Fatal(err)
		}
		if err := keyring.Delete("gentle-vault", "master:"+id); err != nil {
			t.Fatal(err)
		}
		code, out, errs := h.runExtra("", []func(*globals) *cobra.Command{probe}, "--json", "probe")
		want := jsonOf(t, refusal.New(refusal.VaultLocked, "").Envelope())
		if code != exitcode.Locked || out != want || errs != "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		code, out, errs = h.runExtra("", []func(*globals) *cobra.Command{probe}, "probe")
		if code != exitcode.Locked || out != "" || errs != "error: vault is locked\n" {
			t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
		}
	})
	t.Run("damaged state is vault_corrupt", func(t *testing.T) {
		h := newHarness(t)
		h.mustRun("", "init")
		if err := os.WriteFile(filepath.Join(h.home, "state.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, errs := h.runExtra("", []func(*globals) *cobra.Command{probe}, "--json", "probe")
		want := jsonOf(t, refusal.New(refusal.VaultCorrupt, "").Envelope())
		if code != exitcode.Corrupt || out != want || errs != "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
	})
	t.Run("damaged vault file is vault_corrupt", func(t *testing.T) {
		h := newHarness(t)
		h.mustRun("", "init")
		if err := os.WriteFile(filepath.Join(h.home, "vault.enc"), []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, errs := h.runExtra("", []func(*globals) *cobra.Command{probe}, "probe")
		if code != exitcode.Corrupt || errs != "error: vault is corrupt; run 'gentle-vault restore'\n" {
			t.Fatalf("code=%d err=%q", code, errs)
		}
	})
}

func TestMapErr(t *testing.T) {
	busy := refusal.New(refusal.Internal, "").WithMessage("vault is busy").WithRetryable(true)
	tests := []struct {
		name string
		err  error
		want any // refusal.Refusal, or the error itself for passthrough/coded
	}{
		{"not found", fmt.Errorf("%w: GH", vault.ErrNotFound), refusal.New(refusal.UnknownSecret, "GH")},
		{"invalid name never echoed", fmt.Errorf("%w: must match x", vault.ErrInvalidName), refusal.New(refusal.InvalidName, "")},
		{"no project", vault.ErrNoProject, refusal.New(refusal.NoProject, "")},
		{"busy", vault.ErrLocked, busy},
		{"corrupt", fmt.Errorf("%w: x", vault.ErrCorrupt), refusal.New(refusal.VaultCorrupt, "")},
		{"rollback", vault.ErrRollback, refusal.New(refusal.VaultCorrupt, "")},
		{"keychain corrupt", keychain.ErrCorrupt, refusal.New(refusal.VaultCorrupt, "")},
		{"bad passphrase", keychain.ErrBadPassphrase, refusal.New(refusal.VaultLocked, "")},
		{"no key", keychain.ErrNoKey, refusal.New(refusal.VaultLocked, "")},
		{"unavailable", keychain.ErrUnavailable, refusal.New(refusal.VaultLocked, "")},
		{"missing vault", fmt.Errorf("vault: read vault: %w", os.ErrNotExist), errNotInitialized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapErr(tt.err, "GH")
			if jsonOf(t, got) != jsonOf(t, tt.want) {
				t.Fatalf("got  %#v\nwant %#v", got, tt.want)
			}
		})
	}
	other := errors.New("boom")
	if mapErr(other, "GH") != other {
		t.Fatal("unknown errors must pass through")
	}
	if mapErr(nil, "") != nil {
		t.Fatal("nil must stay nil")
	}
}
