package cli

import (
	"errors"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/keychain"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/secret"
)

// newPrompt returns the prompt backend of one command, chosen by
// QBIT_VAULT_PROMPT. It is a seam: tests replace it with a fake, so no test
// needs a terminal. The real backend reads the controlling terminal, never
// the process stdin (L3).
var newPrompt = func(g *globals) (prompt.Backend, error) { return prompt.Select(g.getenv) }

func (g *globals) backend() (prompt.Backend, error) { return newPrompt(g) }

// errCancelled is what a command reports when the user gave up at a prompt
// (Ctrl-C, end of input, or a "no" to a confirmation). Nothing was written.
var errCancelled = codedError{"cancelled", "cancelled", exitcode.Failure}

// errTimedOut is the same outcome after the prompt timeout (docs/CLI.md).
var errTimedOut = codedError{"cancelled", prompt.ErrTimeout.Error(), exitcode.Failure}

// promptFail maps a failed prompt. A backend that cannot ask becomes a usage
// error naming what to do instead (hint, when not empty).
func promptFail(err error, hint string) error {
	if errors.Is(err, prompt.ErrUnavailable) {
		if hint == "" {
			return usageError{err.Error()}
		}
		return usageError{err.Error() + "; " + hint}
	}
	return mapErr(err, "")
}

// askPassphrase reads a passphrase from the prompt backend.
func (g *globals) askPassphrase(confirm bool) (secret.Secret, error) {
	b, err := g.backend()
	if err != nil {
		return secret.Secret{}, err
	}
	req := prompt.VaultPassphrase
	req.Confirm = confirm
	return b.Passphrase(req)
}

// unlockPassphrase is the keychain's passphrase source for unlocking a vault
// in passphrase mode with no cached key (L6). Without a terminal the vault
// stays locked, as before the prompt existed.
func (g *globals) unlockPassphrase(confirm bool) (secret.Secret, error) {
	pass, err := g.askPassphrase(confirm)
	if errors.Is(err, prompt.ErrUnavailable) {
		return secret.Secret{}, keychain.ErrUnavailable
	}
	return pass, err
}

// confirmChange asks a yes/no question before a destructive change made
// without --yes. A backend that cannot ask gives noTerminal; a "no" or a
// cancel is errCancelled: nothing was changed.
func confirmChange(ask prompt.Backend, q string, noTerminal error) error {
	ok, err := ask.Confirm(q)
	switch {
	case errors.Is(err, prompt.ErrUnavailable):
		return noTerminal
	case err != nil:
		return mapErr(err, "")
	case !ok:
		return errCancelled
	}
	return nil
}

// orInstead returns instead when err says nobody can be asked, else the
// mapped err.
func orInstead(err, instead error) error {
	if errors.Is(err, prompt.ErrUnavailable) {
		return instead
	}
	return mapErr(err, "")
}
