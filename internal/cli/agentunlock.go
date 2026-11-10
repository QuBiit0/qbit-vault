package cli

import (
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/keychain"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// envNoPromptUnlock turns off the passphrase dialog of agent calls: they
// refuse with vault_locked, as before the dialog existed. Commands the user
// runs are not affected (docs/CLI.md).
const envNoPromptUnlock = "QBIT_VAULT_NO_PROMPT_UNLOCK"

// msgLockedForAgent is what exec and list answer on a locked vault: they
// never open a dialog, so the agent is sent to the tool that can.
const msgLockedForAgent = "vault is locked; call secret_request to ask the user to unlock it"

// agentUnlock is what an agent call tells the unlock dialog, and what the
// dialog leaves behind for the audit record.
type agentUnlock struct {
	names []string // the secrets the call is about, already validated names
	layer string   // "global" or "project" when the caller said which
	never bool     // exec and list: no dialog, the call stays locked
	asked bool     // the user typed a passphrase for this call
}

// unlockReason is the text of the passphrase dialog of an agent call: who
// wants what, so the user can tell a real need from a stray dialog. The
// layer is named only when the caller states it: a locked vault cannot say
// where a name lives.
func (g *globals) unlockReason(names []string, layer string) string {
	who := limitRunes(prompt.Requester(hostOf(g.Session), ""), maxUnlockWho)
	var valid []string
	for _, n := range names {
		if vault.ValidName(n) {
			valid = append(valid, n)
		}
	}
	if len(valid) == 0 {
		return who + " needs the vault. Unlock it to continue."
	}
	what := strings.Join(valid[:min(len(valid), maxUnlockNames)], ", ")
	if more := len(valid) - maxUnlockNames; more > 0 {
		what += " and " + strconv.Itoa(more) + " more"
	}
	if layer == "global" || layer == "project" {
		what += " (" + layer + ")"
	}
	return who + " wants to use " + what + ". Unlock the vault to continue."
}

// The dialog text is bounded: the requester comes from the caller's session
// and the names from its request, and neither may fill the dialog.
const (
	maxUnlockWho   = 40
	maxUnlockNames = 5
)

// limitRunes cuts s to n runes, marking the cut.
func limitRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// agentPassphrase is the passphrase source of an agent call (S5): the prompt
// backend, one dialog at a time through the same gate as every other dialog,
// ended by the call's own context. It runs inside keychain.Unlock, before any
// vault lock is taken. Nil when this call must not ask.
func (g *globals) agentPassphrase() keychain.PassphraseFunc {
	if g.unlock.never || g.getenv(envNoPromptUnlock) == "1" {
		return nil
	}
	return func(confirm bool) (secret.Secret, error) {
		release, err := g.takeDialogTurn()
		if err != nil {
			return secret.Secret{}, err
		}
		defer release()
		b, err := g.backend()
		if err != nil {
			return secret.Secret{}, keychain.ErrUnavailable
		}
		req := prompt.VaultPassphrase
		req.Confirm = confirm
		req.Reason = g.unlockReason(g.unlock.names, g.unlock.layer)
		pass, err := b.Passphrase(req)
		switch {
		case err == nil:
			g.unlock.asked = true
		case g.callGone():
			return secret.Secret{}, errCallCancelled()
		case errors.Is(err, prompt.ErrUnavailable):
			return secret.Secret{}, keychain.ErrUnavailable
		}
		return pass, err
	}
}

// recordUnlock audits an unlock an agent call asked for: the requester and
// the secrets it named, never the passphrase.
func (g *globals) recordUnlock() {
	g.record(io.Discard, audit.Record{Event: audit.EventUnlock, By: "agent", Names: g.unlock.names,
		Detail: prompt.Requester(hostOf(g.Session), "")})
}

// lockedHint rewrites the vault_locked refusal of a path that never asks.
func lockedHint(err error) error {
	var rf refusal.Refusal
	if errors.As(err, &rf) && rf.Type == refusal.VaultLocked {
		return rf.WithMessage(msgLockedForAgent)
	}
	return err
}
