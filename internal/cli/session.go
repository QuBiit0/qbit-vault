package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/keychain"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
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

var errNotInitialized = codedError{"not_initialized", "no vault here; run 'qbit-vault init'", exitcode.Failure}

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
	key, mode, err := keychain.Unlock(home, id, keychain.Options{Passphrase: g.passphraseSource()})
	if err != nil {
		return nil, mapErr(err, "")
	}
	if g.unlock.asked {
		g.recordUnlock()
	}
	v, key, err := g.openRecovering(home, id, key)
	if err != nil {
		key.Wipe()
		return nil, mapErr(err, "")
	}
	return &session{v: v, key: key, mode: mode, home: home}, nil
}

// noPromptKey is the internal switch of the no-prompt mode. It is read through
// getenv, which the in-process runner wraps, and it is not a valid environment
// variable name (it holds an "="): nothing in the real environment can set it.
const noPromptKey = "QBIT_VAULT_INTERNAL=no-prompt"

// noPrompt reports whether this command runs while the TUI owns the terminal,
// where a prompt would be drawn over the screen. The vault then opens through
// the OS keychain or an unexpired unlock cache only; anything else is the
// refusal vault_locked.
func (g *globals) noPrompt() bool { return g.getenv(noPromptKey) == "1" }

// passphraseSource is where a vault in passphrase mode with no cached key may
// get its passphrase: the prompt backend, or nowhere in the no-prompt mode.
// An agent call (broker or MCP) asks through its own dialog, which names the
// requester and may be switched off (agentPassphrase).
func (g *globals) passphraseSource() keychain.PassphraseFunc {
	switch {
	case g.noPrompt():
		return nil
	case g.broker:
		return g.agentPassphrase()
	}
	return g.unlockPassphrase
}

// errSessionLocked: the vault cannot be opened without a prompt or a repair.
var errSessionLocked = errors.New("vault locked")

// openSessionQuiet is openSession for the commands that must never prompt
// and never change anything on their own (`remote status`, the anchor check
// of `audit --verify`). It uses the OS keychain or an unexpired unlock cache
// and nothing else: no passphrase prompt, and no finishing of an interrupted
// rekey. A key it cannot get that way, or a vault that key does not open
// (a rekey waits to be finished), is errSessionLocked; every other failure is
// mapped as in openSession.
func (g *globals) openSessionQuiet() (*session, error) {
	home := g.Home()
	id, err := vault.ReadID(home)
	if err != nil {
		return nil, mapErr(err, "")
	}
	key, mode, err := keychain.Unlock(home, id, keychain.Options{})
	switch {
	case errors.Is(err, keychain.ErrUnavailable), errors.Is(err, keychain.ErrNoKey), errors.Is(err, keychain.ErrBadPassphrase):
		return nil, errSessionLocked
	case err != nil:
		return nil, mapErr(err, "")
	}
	v, err := vault.Open(home, key)
	if err != nil {
		key.Wipe()
		if errors.Is(err, vault.ErrCorrupt) && !errors.Is(err, vault.ErrRollback) {
			return nil, errSessionLocked
		}
		return nil, mapErr(err, "")
	}
	return &session{v: v, key: key, mode: mode, home: home}, nil
}

// openRecovering opens the vault with key. A vault the key cannot open (not a
// rolled-back one) may have been re-sealed by a rekey that died before it
// promoted the new key: that rekey is finished and the vault opened with the
// new key. It always returns the key to use from now on (the caller owns and
// wipes it), also with an error, so restore can repair a corrupt vault with
// the right key.
func (g *globals) openRecovering(home, id string, key secret.Secret) (*vault.Vault, secret.Secret, error) {
	v, err := vault.Open(home, key)
	if err != nil && errors.Is(err, vault.ErrCorrupt) && !errors.Is(err, vault.ErrRollback) {
		if next, ok := g.finishRekey(home, id, key); ok {
			key.Wipe()
			key = next
			v, err = vault.Open(home, key)
		}
	}
	return v, key, err
}

// finishRekey completes a rekey interrupted after its new key was staged
// (docs/STORAGE.md § Master key): re-seal whatever is left, promote the key.
// It reports false, changing nothing, when no key is staged or the staged key
// cannot be read. The caller owns the returned key.
func (g *globals) finishRekey(home, id string, cur secret.Secret) (secret.Secret, bool) {
	opts := keychain.Options{Passphrase: g.passphraseSource()}
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
		// Until the contract has a dedicated type.
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
