package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/keychain"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

type rekeyBody struct {
	OK       bool   `json:"ok"`
	Rekeyed  bool   `json:"rekeyed"`
	Keychain string `json:"keychain"`
	Remote   string `json:"remote,omitempty"`
}

var errNotPromoted = codedError{"internal", "the new master key is staged but not yet active; the next command finishes the rekey", exitcode.Failure}

// newRekey rotates the master key without a window in which a crash loses
// the vault: stage the new key, re-seal every file (vault.Rekey, resumable),
// then promote it. A rekey refused before anything was re-sealed discards the
// staged key; an interrupted one is finished by the next command
// (openSession). In passphrase mode the passphrase is asked to wrap the new
// key and must match the current one; changing it is not part of rekey.
func newRekey(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "rekey",
		Short: "Rotate the master key",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			if st, err := vault.ReadRemote(s.home); err != nil {
				return mapErr(err, "")
			} else if st != nil {
				return g.rekeySynced(cmd, s, st)
			}
			id, err := vault.ReadID(s.home)
			if err != nil {
				return mapErr(err, "")
			}
			next, err := keychain.NewKey()
			if err != nil {
				return err
			}
			defer next.Wipe()
			opts := keychain.Options{Passphrase: g.askPassphrase}
			if err := keychain.Stage(s.home, id, s.key, next, opts); err != nil {
				return promptFail(err, "")
			}
			if err := vault.Rekey(s.home, s.key, next); err != nil {
				// Nothing re-sealed yet: drop the staged key so it can never be
				// mistaken for a pending rekey.
				if errors.Is(err, vault.ErrRekeyNotStarted) {
					_ = keychain.Unstage(s.home, id, opts)
				}
				return mapErr(err, "")
			}
			if err := keychain.Promote(s.home, id, next, opts); err != nil {
				return errNotPromoted
			}
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventRekey, Detail: string(s.mode)})
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), rekeyBody{OK: true, Rekeyed: true, Keychain: string(s.mode)})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "master key rotated (keychain: %s)\n", s.mode)
			return err
		},
	}
}

// rekeySynced is rekey on a vault that syncs: the account key is rotated for
// every device and nobody is revoked (REMOTE_SYNC § 4.5, last paragraph). It
// is user-only because it shows the new recovery key out of band.
func (g *globals) rekeySynced(cmd *cobra.Command, s *session, st *vault.Remote) error {
	ask, show, err := g.userBackend(true)
	if err != nil {
		return err
	}
	if g.remoteOff() {
		return errRemoteOff
	}
	if err := askYes(ask, "Rotate the master key of your vault on "+serverHost(st.Server)+"? Every device switches to the new key, and the recovery key is replaced."); err != nil {
		return err
	}
	res, err := g.rotateAccount(cmd, s, ask, show, "")
	if err != nil {
		return err
	}
	if g.JSON {
		return writeJSON(cmd.OutOrStdout(), rekeyBody{OK: true, Rekeyed: true, Keychain: string(s.mode), Remote: remoteSynced})
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "master key rotated (keychain: %s); the account is now generation %d\n", s.mode, res.generation)
	return err
}
