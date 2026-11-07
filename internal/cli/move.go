package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

type moveBody struct {
	OK      bool        `json:"ok"`
	Name    string      `json:"name"`
	From    string      `json:"from"`
	To      string      `json:"to"`
	Project *projectRef `json:"project"`
	// GrantsDropped counts the grants the move dropped; omitted when none.
	GrantsDropped int `json:"grants_dropped,omitempty"`
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

type relinkBody struct {
	OK      bool   `json:"ok"`
	From    string `json:"from"`
	To      string `json:"to"`
	Secrets int    `json:"secrets"`
	// GrantsDropped counts the project grants relink dropped; omitted when none.
	GrantsDropped int `json:"grants_dropped,omitempty"`
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

func newMv(g *globals) *cobra.Command {
	var (
		to  string
		yes bool
	)
	cmd := &cobra.Command{
		Use:   "mv NAME --to global|project [--yes]",
		Short: "Move a secret between the global layer and the current project",
		Args:  nameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			switch to {
			case "global", "project":
			case "":
				return usageError{"choose --to global or --to project"}
			default:
				return usageError{"invalid --to: must be global or project"}
			}
			if err := checkName(name); err != nil {
				return err
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			// A move always has the current project on one side.
			proj, err := vault.ProjectLayer(cwd)
			if err != nil {
				return mapErr(err, "")
			}
			from, dest := proj, vault.Global()
			if to == "project" {
				from, dest = vault.Global(), proj
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			// The moved record's grants no longer apply (R-LAYER-05).
			res, err := s.v.MoveWithGrants(name, from, dest, yes, newGrantsEditor())
			if errors.Is(err, vault.ErrExists) {
				// Overwriting asks on the controlling terminal (L4); with none,
				// --yes is required.
				exists := usageError{name + " already exists in " + layerName(dest) + "; pass --yes to overwrite"}
				ask, berr := g.backend()
				if berr != nil {
					return orInstead(berr, exists)
				}
				if err := confirmChange(ask, name+" already exists in "+whereText(dest)+"; overwrite?", exists); err != nil {
					return err
				}
				res, err = s.v.MoveWithGrants(name, from, dest, true, newGrantsEditor())
			}
			if err != nil {
				return mapErr(err, name)
			}
			g.noteGrantsReset(cmd.ErrOrStderr(), res.Reset)
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventMv, Names: []string{name}, Layer: auditLayer(dest), Detail: layerName(from) + "->" + layerName(dest)})
			remoteState := g.pushAfterCmd(cmd, s)
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), moveBody{OK: true, Name: name, From: layerName(from), To: layerName(dest), Project: projectOf(proj), GrantsDropped: res.Changed, Remote: remoteState})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "moved %s from %s to %s\n", name, layerText(from), layerText(dest))
			return err
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "target layer: global or project")
	cmd.Flags().BoolVar(&yes, "yes", false, "overwrite a same-named secret in the target layer without asking")
	return cmd
}

func newRelink(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "relink OLD_ROOT NEW_ROOT",
		Short: "Repoint a project layer after moving or re-cloning a repository",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usageError{"usage: relink OLD_ROOT NEW_ROOT"}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			n, res, err := s.v.RelinkWithGrants(args[0], args[1], newGrantsEditor())
			switch {
			case errors.Is(err, vault.ErrNotFound):
				return usageError{"OLD_ROOT has no project layer"}
			case errors.Is(err, vault.ErrExists):
				return usageError{"NEW_ROOT already has a project layer"}
			case err != nil:
				return mapErr(err, "")
			}
			g.noteGrantsReset(cmd.ErrOrStderr(), res.Reset)
			cwd, _ := os.Getwd()
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventRelink, Cwd: cwd})
			remoteState := g.pushAfterCmd(cmd, s)
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), relinkBody{OK: true, From: args[0], To: args[1], Secrets: n, GrantsDropped: res.Changed, Remote: remoteState})
			}
			noun := "secrets"
			if n == 1 {
				noun = "secret"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "relinked %d %s from %s to %s\n", n, noun, args[0], args[1])
			return err
		},
	}
}
