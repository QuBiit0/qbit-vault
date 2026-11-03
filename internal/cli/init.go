package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/keychain"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// newVaultID is replaceable so tests can pin the id.
var newVaultID = vault.NewID

const maxPassphraseBytes = 4096

type initBody struct {
	OK          bool   `json:"ok"`
	Initialized bool   `json:"initialized"`
	Home        string `json:"home"`
	Keychain    string `json:"keychain,omitempty"`
}

// newInit is the vault-only init of slice 1.4: a master key and an empty
// vault. It never reads the environment for values and never registers hosts.
func newInit(g *globals) *cobra.Command {
	var passphrase, passphraseStdin bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create an empty vault and its master key",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if passphraseStdin && !passphrase {
				return usageError{"--passphrase-stdin requires --passphrase"}
			}
			if passphrase && !passphraseStdin {
				return usageError{"passphrase mode needs --passphrase-stdin until interactive prompts are available"}
			}
			home := g.Home()
			out := cmd.OutOrStdout()
			switch _, err := vault.ReadID(home); {
			case err == nil:
				if g.JSON {
					return writeJSON(out, initBody{OK: true, Home: home})
				}
				_, err := fmt.Fprintf(out, "vault already initialized at %s\n", home)
				return err
			case !errors.Is(err, os.ErrNotExist):
				return mapErr(err, "")
			}

			opts := keychain.Options{ForcePassphrase: passphrase}
			if passphrase {
				pass, err := readPassphrase(stdinOf(cmd))
				if err != nil {
					return err
				}
				defer clear(pass)
				opts.Passphrase = func(bool) (secret.Secret, error) { return secret.New("passphrase", pass), nil }
			}

			id := newVaultID()
			key, mode, err := keychain.Setup(home, id, opts)
			if err != nil {
				if errors.Is(err, keychain.ErrKeyExists) {
					return errors.New("a key already exists for this vault location")
				}
				return mapErr(err, "")
			}
			defer key.Wipe()
			if _, err := vault.Init(home, id, key); err != nil {
				removeKey(home, id, mode, opts)
				if errors.Is(err, vault.ErrExists) {
					// A vault file without a state file: damaged, not new.
					return refusal.New(refusal.VaultCorrupt, "")
				}
				return mapErr(err, "")
			}
			if g.JSON {
				return writeJSON(out, initBody{OK: true, Initialized: true, Home: home, Keychain: string(mode)})
			}
			_, err = fmt.Fprintf(out, "vault initialized at %s (keychain: %s)\n", home, mode)
			return err
		},
	}
	f := cmd.Flags()
	f.BoolVar(&passphrase, "passphrase", false, "protect the master key with a passphrase instead of the OS keychain")
	f.BoolVar(&passphraseStdin, "passphrase-stdin", false, "read the passphrase from the first line of stdin (until interactive prompts exist)")
	return cmd
}

// removeKey deletes the key Setup just created, so a failed vault.Init does
// not leave an orphan (slice 1.3 follow-up).
func removeKey(home, id string, mode keychain.Mode, opts keychain.Options) {
	if mode == keychain.ModePassphrase {
		_ = os.Remove(filepath.Join(home, "key.enc")) // keychain's key file name
		_ = keychain.Lock(id, opts)
		return
	}
	_ = keychain.NewOS().Delete(id)
}

// readPassphrase reads the first line of r. The caller wipes the result.
func readPassphrase(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxPassphraseBytes+1))
	if err != nil {
		return nil, errors.New("cannot read the passphrase from stdin")
	}
	if len(b) > maxPassphraseBytes {
		clear(b)
		return nil, usageError{"passphrase too long"}
	}
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		clear(b[i:])
		b = b[:i]
	}
	b = bytes.TrimRight(b, "\r")
	if len(bytes.TrimSpace(b)) == 0 {
		clear(b)
		return nil, usageError{"empty passphrase"}
	}
	return b, nil
}
