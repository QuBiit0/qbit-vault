package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/merge"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// Sync conflicts (docs/REMOTE_SYNC.md § 7.4). `remote conflicts` lists the
// kept versions without any value; `remote resolve` settles one. Neither
// message echoes a secret name: it is text the user typed or another device
// wrote.

var (
	errNoConflict = codedError{"not_found", "no sync conflict for that name", exitcode.Failure}
	errUnlinked   = codedError{"not_found", "that project layer is not linked on this device; run 'qbit-vault link'", exitcode.Failure}
)

// winnerLabel names the device whose version won, from the roster.
func winnerLabel(roster map[string]merge.Device, id string) string {
	if d, ok := roster[id]; ok && d.Label != "" {
		return oneLine(d.Label)
	}
	return "unknown device"
}

type conflictRow struct {
	Name    string `json:"name"`
	Layer   string `json:"layer"`
	Project string `json:"project,omitempty"`
	LostAt  string `json:"lost_at"`
	Winner  string `json:"winner"`
	Deleted bool   `json:"deleted,omitempty"`
}

func newRemoteConflicts(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "conflicts",
		Short: "List the versions kept after a double edit (never values)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			if _, err := requireRemote(s); err != nil {
				return err
			}
			list, err := s.v.Conflicts()
			if err != nil {
				return mapErr(err, "")
			}
			roster, err := s.v.Roster()
			if err != nil {
				return mapErr(err, "")
			}
			rows := make([]conflictRow, 0, len(list))
			for _, c := range list {
				r := conflictRow{Name: c.Name, Layer: layerName(c.Layer), LostAt: oneLine(c.LostAt), Winner: winnerLabel(roster, c.WinnerDevice), Deleted: c.Deleted}
				if c.Layer.Project {
					r.Project = oneLine(c.Layer.Label)
				}
				rows = append(rows, r)
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					OK        bool          `json:"ok"`
					Conflicts []conflictRow `json:"conflicts"`
				}{true, rows})
			}
			w := cmd.OutOrStdout()
			if len(rows) == 0 {
				_, err := fmt.Fprintln(w, "no sync conflicts")
				return err
			}
			for _, r := range rows {
				layer, kind := r.Layer, "edit"
				if r.Project != "" {
					layer = "project:" + r.Project
				}
				if r.Deleted {
					kind = "deletion"
				}
				if _, err := fmt.Fprintf(w, "%s  %s  kept %s lost at %s to %s\n", r.Name, layer, kind, r.LostAt, r.Winner); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// conflictLayer is the layer a resolution acts on: the one the flags name,
// else the only layer that holds a kept version under name.
func conflictLayer(s *session, name string, lf layerFlags, cwd string) (vault.Layer, error) {
	if lf.explicit() {
		return lf.pick(cwd)
	}
	list, err := s.v.Conflicts()
	if err != nil {
		return vault.Layer{}, mapErr(err, "")
	}
	var found []vault.Layer
	for _, c := range list {
		if c.Name != name {
			continue
		}
		dup := false
		for _, l := range found {
			dup = dup || sameLayer(l, c.Layer)
		}
		if !dup {
			found = append(found, c.Layer)
		}
	}
	switch {
	case len(found) == 0:
		return vault.Layer{}, errNoConflict
	case len(found) > 1:
		return vault.Layer{}, usageError{"several layers hold a conflict for that name; choose --global or --project"}
	case found[0].Project && found[0].Root == "":
		return vault.Layer{}, errUnlinked
	}
	return found[0], nil
}

func newRemoteResolve(g *globals) *cobra.Command {
	var (
		lf   layerFlags
		keep string
	)
	cmd := &cobra.Command{
		Use:   "resolve NAME [--global|--project] --keep current|conflict",
		Short: "Settle a sync conflict: keep the current version or swap in the kept one",
		Args:  nameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := lf.validate(); err != nil {
				return err
			}
			if keep != string(vault.KeepCurrent) && keep != string(vault.KeepConflict) {
				return usageError{"--keep must be current or conflict"}
			}
			if err := checkName(name); err != nil {
				return err
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			if _, err := requireRemote(s); err != nil {
				return err
			}
			ask, _, err := g.userBackend(false)
			if err != nil {
				return err
			}
			layer, err := conflictLayer(s, name, lf, cwd)
			if err != nil {
				return err
			}
			q := fmt.Sprintf("Resolve the sync conflict of %s (%s): keep the current version and discard the kept one?", name, layerText(layer))
			if keep == string(vault.KeepConflict) {
				q = fmt.Sprintf("Resolve the sync conflict of %s (%s): swap in the kept version? The current one becomes the kept one.", name, layerText(layer))
			}
			if err := askYes(ask, q); err != nil {
				return err
			}
			switch err := s.v.ResolveConflict(layer, name, vault.Keep(keep)); {
			case errors.Is(err, vault.ErrNoConflict):
				return errNoConflict
			case errors.Is(err, vault.ErrAmbiguousConflict):
				return usageError{"more than one version was kept for that name; use --keep current to discard them"}
			case err != nil:
				return mapErr(err, name)
			}
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventRemote, Names: []string{name}, Layer: auditLayer(layer), Detail: "conflict resolved (keep " + keep + ")"})
			remoteState := g.pushAfterCmd(cmd, s)
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					OK     bool   `json:"ok"`
					Name   string `json:"name"`
					Layer  string `json:"layer"`
					Keep   string `json:"keep"`
					Remote string `json:"remote,omitempty"`
				}{true, name, layerName(layer), keep, remoteState})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "resolved %s (%s): kept the %s version\n", name, layerText(layer), keep)
			return err
		},
	}
	lf.bind(cmd)
	cmd.Flags().StringVar(&keep, "keep", "", "which version survives: current or conflict")
	return cmd
}
