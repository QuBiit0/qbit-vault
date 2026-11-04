package cli

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/doctor"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/hosts/claude"
)

// hostRegistry returns the host adapters of this build: Claude Code now, Codex
// and Pi when they land (docs/ROADMAP.md 3.3, 3.5). Tests replace it.
var hostRegistry = func(*globals) *hosts.Registry { return hosts.NewRegistry(claude.New()) }

// hostEnv is what host adapters need to know about this machine: the vault
// home and the user's home directory (a path, never a value).
func (g *globals) hostEnv() hosts.Env {
	uh, _ := os.UserHomeDir()
	return hosts.Env{VaultHome: g.Home(), UserHome: uh}
}

// runDoctor builds the read-only report. The vault is opened the way
// `remote status` does it: no prompt, no unfinished rekey.
func (g *globals) runDoctor() doctor.Report {
	return doctor.Run(doctor.Inputs{
		Home:     g.Home(),
		Env:      g.hostEnv(),
		Registry: hostRegistry(g),
		Open: func() (string, error) {
			s, err := g.openSessionQuiet()
			switch {
			case err == nil:
				mode := string(s.mode)
				s.close()
				return mode, nil
			case errors.Is(err, errSessionLocked):
				return "", doctor.ErrLocked
			default:
				return "", err
			}
		},
	})
}

// newDoctor is `doctor` (docs/CLI.md): a read-only health report, exit 0 when
// healthy and 1 when any check is not ok.
func newDoctor(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Read-only health report",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep := g.runDoctor()
			out := cmd.OutOrStdout()
			if g.JSON {
				if err := writeJSON(out, rep); err != nil {
					return err
				}
			} else if err := rep.WriteHuman(out); err != nil {
				return err
			}
			if !rep.OK {
				return exitError{exitcode.Failure}
			}
			return nil
		},
	}
}
