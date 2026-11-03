package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

type moveBody struct {
	OK      bool        `json:"ok"`
	Name    string      `json:"name"`
	From    string      `json:"from"`
	To      string      `json:"to"`
	Project *projectRef `json:"project"`
}

type relinkBody struct {
	OK      bool   `json:"ok"`
	From    string `json:"from"`
	To      string `json:"to"`
	Secrets int    `json:"secrets"`
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
			// TODO(slice 1.6): drop the grants of the moved record here
			// (R-LAYER-05).
			if err := s.v.Move(name, from, dest, yes); err != nil {
				if errors.Is(err, vault.ErrExists) {
					return usageError{name + " already exists in " + layerName(dest) + "; pass --yes to overwrite"}
				}
				return mapErr(err, name)
			}
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventMv, Names: []string{name}, Layer: auditLayer(dest), Detail: layerName(from) + "->" + layerName(dest)})
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), moveBody{OK: true, Name: name, From: layerName(from), To: layerName(dest), Project: projectOf(proj)})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "moved %s from %s to %s\n", name, layerText(from), layerText(dest))
			return err
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "target layer: global or project")
	cmd.Flags().BoolVar(&yes, "yes", false, "overwrite a same-named secret in the target layer")
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
			// TODO(slice 1.6): repoint the project grants of this layer too.
			n, err := s.v.Relink(args[0], args[1])
			switch {
			case errors.Is(err, vault.ErrNotFound):
				return usageError{"OLD_ROOT has no project layer"}
			case errors.Is(err, vault.ErrExists):
				return usageError{"NEW_ROOT already has a project layer"}
			case err != nil:
				return mapErr(err, "")
			}
			cwd, _ := os.Getwd()
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventRelink, Cwd: cwd})
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), relinkBody{OK: true, From: args[0], To: args[1], Secrets: n})
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
