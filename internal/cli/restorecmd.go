package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/keychain"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

type backupOut struct {
	ID    string   `json:"id"`
	Files []string `json:"files"`
}

type backupsBody struct {
	OK      bool        `json:"ok"`
	Backups []backupOut `json:"backups"`
}

type restoreBody struct {
	OK       bool   `json:"ok"`
	Restored string `json:"restored"`
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

const msgBackupKey = "backup cannot be opened with the current or a retired key"

// newRestore lists the encrypted backups or swaps one back in (docs/CLI.md).
// It works when the live vault is corrupt or rolled back: that is the case
// the vault_corrupt refusal points here for.
func newRestore(g *globals) *cobra.Command {
	var (
		list bool
		from string
		yes  bool
	)
	cmd := &cobra.Command{
		Use:   "restore --list | --from ID [--yes]",
		Short: "List encrypted backups or restore the vault from one",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if list == cmd.Flags().Changed("from") {
				return usageError{"choose --list or --from"}
			}
			home := g.Home()
			if list {
				return restoreList(g, cmd, home)
			}
			if !vault.ValidBackupID(from) {
				return usageError{"invalid backup id"}
			}
			var ask prompt.Backend
			if !yes {
				var err error
				if ask, err = g.backend(); err != nil {
					return orInstead(err, usageError{"confirmation required; pass --yes"})
				}
			}
			id, err := vault.ReadID(home)
			switch {
			case errors.Is(err, os.ErrNotExist):
				return errNotInitialized
			case err != nil:
				// The live state is unreadable: unlock with the snapshot's id.
				if id, err = vault.ReadBackupID(home, from); err != nil {
					if errors.Is(err, os.ErrNotExist) || errors.Is(err, vault.ErrNotFound) {
						return usageError{"no backup " + from}
					}
					return mapErr(err, "")
				}
			}
			if !hasBackup(home, from) {
				return usageError{"no backup " + from}
			}
			if !yes {
				if err := confirmChange(ask, "Restore the vault from "+from+"? The current vault is backed up first.", usageError{"confirmation required; pass --yes"}); err != nil {
					return err
				}
			}
			key, _, err := keychain.Unlock(home, id, keychain.Options{Passphrase: g.unlockPassphrase})
			if err != nil {
				return mapErr(err, "")
			}
			// Finish an interrupted rekey first, so the restored body and the
			// snapshot of the current state are sealed under the right key.
			// Any other open failure is what restore is here to repair.
			_, key, _ = g.openRecovering(home, id, key)
			defer key.Wipe()
			switch err := vault.Restore(home, from, key); {
			case errors.Is(err, vault.ErrNotFound):
				return usageError{"no backup " + from}
			case errors.Is(err, vault.ErrBackupKey):
				return refusal.New(refusal.VaultCorrupt, "").WithMessage(msgBackupKey)
			case err != nil:
				return mapErr(err, "")
			}
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventRestore, Detail: from})
			remoteState := g.pushAfterOpen(cmd)
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), restoreBody{OK: true, Restored: from, Remote: remoteState})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "restored the vault from %s (the previous state was backed up first)\n", from)
			return err
		},
	}
	f := cmd.Flags()
	f.BoolVar(&list, "list", false, "list the encrypted backups, newest first")
	f.StringVar(&from, "from", "", "restore the vault from this backup id (see --list)")
	f.BoolVar(&yes, "yes", false, "restore without asking (for scripts)")
	return cmd
}

func hasBackup(home, id string) bool {
	bs, err := vault.ListBackups(home)
	if err != nil {
		return false
	}
	for _, b := range bs {
		if b.ID == id {
			for _, f := range b.Files {
				if f == "vault.enc" {
					return true
				}
			}
		}
	}
	return false
}

func restoreList(g *globals, cmd *cobra.Command, home string) error {
	if _, err := vault.ReadID(home); errors.Is(err, os.ErrNotExist) {
		return errNotInitialized
	}
	bs, err := vault.ListBackups(home)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if g.JSON {
		body := backupsBody{OK: true, Backups: []backupOut{}}
		for _, b := range bs {
			body.Backups = append(body.Backups, backupOut{ID: b.ID, Files: nonNil(b.Files)})
		}
		return writeJSON(out, body)
	}
	if len(bs) == 0 {
		_, err = fmt.Fprintln(out, "no backups")
		return err
	}
	var sb strings.Builder
	for _, b := range bs {
		fmt.Fprintf(&sb, "%s  %s\n", b.ID, strings.Join(b.Files, ", "))
	}
	_, err = fmt.Fprint(out, sb.String())
	return err
}
