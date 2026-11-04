package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/keychain"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

type lockBody struct {
	OK       bool   `json:"ok"`
	Locked   bool   `json:"locked"`
	Keychain string `json:"keychain"`
}

type unlockBody struct {
	OK        bool    `json:"ok"`
	Unlocked  bool    `json:"unlocked"`
	Keychain  string  `json:"keychain"`
	Cached    bool    `json:"cached"`
	ExpiresAt *string `json:"expires_at"`
}

// newLock drops the passphrase unlock cache (docs/CLI.md). In keychain mode
// there is nothing to drop. It never asks anything and reads no key.
func newLock(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Passphrase mode: drop the cached master key",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home := g.Home()
			id, err := vault.ReadID(home)
			if err != nil {
				return mapErr(err, "")
			}
			mode, err := keychain.ModeOf(home, keychain.Options{})
			if err != nil {
				return mapErr(err, "")
			}
			locked := mode == keychain.ModePassphrase
			if locked {
				if err := keychain.Lock(id, keychain.Options{}); err != nil {
					return err
				}
			}
			out := cmd.OutOrStdout()
			if g.JSON {
				return writeJSON(out, lockBody{OK: true, Locked: locked, Keychain: string(mode)})
			}
			if locked {
				_, err = fmt.Fprintln(out, "vault locked: the cached master key was removed")
			} else {
				_, err = fmt.Fprintf(out, "nothing to lock: the master key is in the OS keychain (%s)\n", mode)
			}
			return err
		},
	}
}

// newUnlock refreshes the passphrase unlock cache: it always asks the
// passphrase, checks that the key opens the vault and caches it where a
// memory-backed cache exists. In keychain mode it only checks the key.
func newUnlock(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Passphrase mode: ask the passphrase and refresh the cached master key",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home := g.Home()
			id, err := vault.ReadID(home)
			if err != nil {
				return mapErr(err, "")
			}
			key, mode, cached, exp, err := keychain.Refresh(home, id, keychain.Options{Passphrase: g.askPassphrase})
			if err != nil {
				return promptFail(err, "")
			}
			_, key, err = g.openRecovering(home, id, key)
			defer key.Wipe()
			if err != nil {
				return mapErr(err, "")
			}
			body := unlockBody{OK: true, Unlocked: true, Keychain: string(mode), Cached: cached}
			if cached {
				s := exp.UTC().Format(time.RFC3339)
				body.ExpiresAt = &s
			}
			out := cmd.OutOrStdout()
			if g.JSON {
				return writeJSON(out, body)
			}
			switch {
			case mode != keychain.ModePassphrase:
				_, err = fmt.Fprintf(out, "unlocked: the master key is in the OS keychain (%s)\n", mode)
			case cached:
				_, err = fmt.Fprintf(out, "vault unlocked until %s\n", *body.ExpiresAt)
			default:
				_, err = fmt.Fprintln(out, "passphrase ok; this platform has no unlock cache, so the passphrase is asked on each use")
			}
			return err
		},
	}
}
