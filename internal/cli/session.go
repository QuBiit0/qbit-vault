package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/keychain"
	"github.com/QuBiit0/gentle-vault/internal/prompt"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// stdinOverride replaces the process stdin; tests set it.
var stdinOverride io.Reader

func stdinOf(cmd *cobra.Command) io.Reader {
	if stdinOverride != nil {
		return stdinOverride
	}
	return cmd.InOrStdin()
}

// codedError is a failure with its own error code and exit status that is not
// a contract refusal (for example a missing vault).
type codedError struct {
	code string
	msg  string
	exit int
}

func (e codedError) Error() string { return e.msg }

var errNotInitialized = codedError{"not_initialized", "no vault here; run 'gentle-vault init'", exitcode.Failure}

// session is an unlocked, open vault for the duration of one command.
type session struct {
	v    *vault.Vault
	key  secret.Secret
	mode keychain.Mode
	home string
}

// close wipes the master key the session holds.
func (s *session) close() { s.key.Wipe() }

// openSession resolves the vault home, reads the vault id, unlocks the master
// key and opens the vault. Failures are already mapped to typed refusals or
// coded errors. A passphrase-mode vault opens through an unexpired unlock
// cache or, when there is a controlling terminal, a passphrase prompt (L6);
// otherwise it is locked.
func (g *globals) openSession() (*session, error) {
	home := g.Home()
	id, err := vault.ReadID(home)
	if err != nil {
		return nil, mapErr(err, "")
	}
	key, mode, err := keychain.Unlock(home, id, keychain.Options{Passphrase: g.unlockPassphrase})
	if err != nil {
		return nil, mapErr(err, "")
	}
	v, err := vault.Open(home, key)
	if err != nil && errors.Is(err, vault.ErrCorrupt) && !errors.Is(err, vault.ErrRollback) {
		// A vault the main key cannot open may be one a rekey re-sealed
		// before it could promote the new key: finish that rekey.
		if next, ok := g.finishRekey(home, id, key); ok {
			key.Wipe()
			key = next
			v, err = vault.Open(home, key)
		}
	}
	if err != nil {
		key.Wipe()
		return nil, mapErr(err, "")
	}
	return &session{v: v, key: key, mode: mode, home: home}, nil
}

// finishRekey completes a rekey interrupted after its new key was staged
// (docs/STORAGE.md § Master key): re-seal whatever is left, promote the key.
// It reports false, changing nothing, when no key is staged or the staged key
// cannot be read. The caller owns the returned key.
func (g *globals) finishRekey(home, id string, cur secret.Secret) (secret.Secret, bool) {
	opts := keychain.Options{Passphrase: g.unlockPassphrase}
	if has, err := keychain.HasStaged(home, id, opts); err != nil || !has {
		return secret.Secret{}, false
	}
	next, err := keychain.Staged(home, id, opts)
	if err != nil {
		return secret.Secret{}, false
	}
	if err := vault.Rekey(home, cur, next); err != nil {
		next.Wipe()
		return secret.Secret{}, false
	}
	// A failed promotion leaves the key staged; the next command retries.
	_ = keychain.Promote(home, id, next, opts)
	stderr := g.stderr
	if stderr == nil {
		stderr = io.Discard
	}
	fmt.Fprintln(stderr, "warning: an interrupted rekey was finished")
	g.record(stderr, audit.Record{Event: audit.EventWarning, Detail: "interrupted rekey finished"})
	return next, true
}

// mapErr turns a vault or keychain error into a typed refusal or coded error.
// name must already be a validated secret name (or ""); it is the only user
// text that can appear in a message. Unknown errors pass through unchanged.
func mapErr(err error, name string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, vault.ErrInvalidName):
		return refusal.New(refusal.InvalidName, "")
	case errors.Is(err, vault.ErrNotFound):
		return refusal.New(refusal.UnknownSecret, name)
	case errors.Is(err, vault.ErrNoProject):
		return refusal.New(refusal.NoProject, "")
	case errors.Is(err, vault.ErrLocked):
		// Until the contract has a dedicated type (slice 2.1 follow-up).
		return refusal.New(refusal.Internal, "").WithMessage("vault is busy").WithRetryable(true)
	case errors.Is(err, prompt.ErrCancelled):
		return errCancelled
	case errors.Is(err, prompt.ErrTimeout):
		return errTimedOut
	case errors.Is(err, prompt.ErrTrailingInput), errors.Is(err, prompt.ErrBadTimeout):
		return usageError{err.Error()}
	case errors.Is(err, prompt.ErrTooLarge):
		return usageError{"value too large"} // same message as set --stdin
	case errors.Is(err, prompt.ErrMismatch):
		return usageError{"passphrases do not match"}
	case errors.Is(err, keychain.ErrEmptyPassphrase):
		return usageError{"empty passphrase"}
	case errors.Is(err, prompt.ErrUnknownBackend):
		return usageError{err.Error()}
	case errors.Is(err, vault.ErrCorrupt), errors.Is(err, keychain.ErrCorrupt):
		return refusal.New(refusal.VaultCorrupt, "")
	case errors.Is(err, keychain.ErrBadPassphrase), errors.Is(err, keychain.ErrNoKey), errors.Is(err, keychain.ErrUnavailable):
		return refusal.New(refusal.VaultLocked, "")
	case errors.Is(err, os.ErrNotExist):
		return errNotInitialized
	default:
		return err
	}
}

// reportRefusal prints a typed refusal: one JSON envelope on stdout with
// --json, otherwise `error: <message>` on stderr.
func reportRefusal(stdout, stderr io.Writer, asJSON bool, r refusal.Refusal) int {
	if asJSON {
		_ = writeJSON(stdout, r.Envelope())
	} else {
		fmt.Fprintf(stderr, "error: %s\n", r.Message)
	}
	return r.ExitCode()
}
