package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

type linkBody struct {
	OK      bool   `json:"ok"`
	Label   string `json:"label"`
	Root    string `json:"root"`
	Secrets int    `json:"secrets"`
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

// newLink binds a project layer synced from another device to a checkout on
// this one (docs/CLI.md, REMOTE_SYNC.md § 7.5). It is user-only: confirmed
// on the prompt backend, and refused as not_model_callable without one,
// because a link decides which directory receives a project's secrets.
func newLink(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "link LABEL [DIR]",
		Short: "Bind a project layer synced from another device to this repository",
		Args: func(_ *cobra.Command, args []string) error {
			switch {
			case len(args) == 0:
				return usageError{"give the label of the project layer to link"}
			case len(args) > 2:
				return usageError{"unexpected arguments"}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			label, dir := args[0], ""
			if len(args) == 2 {
				dir = args[1]
			} else {
				var err error
				if dir, err = getwd(); err != nil {
					return err
				}
			}
			root, ok, err := vault.ProjectRoot(dir)
			if err != nil {
				return mapErr(err, "")
			}
			if !ok {
				return mapErr(vault.ErrNoProject, "")
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			ask, err := g.backend()
			if err != nil {
				return refusal.New(refusal.NotModelCallable, "")
			}
			yes, err := ask.Confirm(fmt.Sprintf("Use the secrets of project %s in %s?", label, root))
			switch {
			case errors.Is(err, prompt.ErrUnavailable):
				return refusal.New(refusal.NotModelCallable, "")
			case err != nil:
				return mapErr(err, "")
			case !yes:
				return errCancelled
			}
			n, err := s.v.Link(label, root)
			switch {
			case errors.Is(err, vault.ErrNotFound):
				return usageError{"no unlinked project layer has that label"}
			case errors.Is(err, vault.ErrAmbiguous):
				return usageError{"several unlinked project layers have that label"}
			case errors.Is(err, vault.ErrExists):
				return usageError{"this repository already has a project layer"}
			case err != nil:
				return mapErr(err, "")
			}
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventLink, Layer: "project:" + root, Detail: fmt.Sprintf("secrets=%d", n)})
			remoteState := g.pushAfterCmd(cmd, s)
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), linkBody{OK: true, Label: label, Root: root, Secrets: n, Remote: remoteState})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "linked %s to %s (%d %s)\n", oneLine(label), root, n, plural(n, "secret", "secrets"))
			return err
		},
	}
}
