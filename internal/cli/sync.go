package cli

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/doctor"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// Host statuses of the sync and uninstall reports (the `status` of --json).
const (
	statusUpToDate   = "up_to_date"
	statusRepaired   = "repaired"
	statusRegistered = "registered"
	statusFailed     = "failed"
	statusNoAdapter  = "no_adapter"
	statusReverted   = "reverted"
)

// hostEntry is a host recorded in state.json; adapter is nil when this build
// has none for it.
type hostEntry struct {
	name    string
	adapter hosts.Adapter
}

// recordedHosts lists the hosts recorded in state.json: those this build has
// an adapter for in registry order, then the others by name.
func recordedHosts(reg *hosts.Registry, recorded map[string]vault.HostState) []hostEntry {
	var out []hostEntry
	for _, a := range reg.All() {
		if _, ok := recorded[a.Name()]; ok {
			out = append(out, hostEntry{a.Name(), a})
		}
	}
	var rest []string
	for n := range recorded {
		if _, ok := reg.Get(n); !ok {
			rest = append(rest, n)
		}
	}
	sort.Strings(rest)
	for _, n := range rest {
		out = append(out, hostEntry{name: n})
	}
	return out
}

type syncHostBody struct {
	Name   string   `json:"name"`
	Status string   `json:"status"`
	Steps  []string `json:"steps"`
}

type hostSyncBody struct {
	OK     bool           `json:"ok"`
	Hosts  []syncHostBody `json:"hosts"`
	Doctor *doctor.Report `json:"doctor"`
}

// newSync is `sync` (docs/CLI.md): it re-applies the registration steps of the
// hosts recorded in state.json, which repairs drift and picks up a moved
// binary, and finishes with the doctor report. A host that was only detected
// is never registered unless --agents names it. It writes a config file or
// state.json only when something differs, and never reads or stores a secret.
// This is not vault sync: that is `remote`.
func newSync(g *globals) *cobra.Command {
	var agents []string
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Re-apply the recorded host registrations (not vault sync: see 'remote')",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var extra []hosts.Adapter
			if cmd.Flags().Changed("agents") {
				var err error
				if extra, err = g.pickHosts(cmd, agents); err != nil {
					return err
				}
			}
			home := g.Home()
			switch _, err := vault.ReadID(home); {
			case err == nil:
			case errors.Is(err, os.ErrNotExist):
				return errNotInitialized
			default:
				return mapErr(err, "")
			}
			recorded, err := vault.ReadHosts(home)
			if err != nil {
				return mapErr(err, "")
			}
			entries := recordedHosts(hostRegistry(g), recorded)

			// What runs: the recorded hosts with an adapter, then --agents.
			var run []hosts.Adapter
			seen := map[string]bool{}
			for _, e := range entries {
				if e.adapter != nil {
					run = append(run, e.adapter)
					seen[e.name] = true
				}
			}
			for _, a := range extra {
				if !seen[a.Name()] {
					run = append(run, a)
					seen[a.Name()] = true
					entries = append(entries, hostEntry{a.Name(), a})
				}
			}
			byHost := map[string]hosts.Result{}
			for _, r := range hosts.Apply(g.hostEnv(), run) {
				byHost[r.Host] = r
			}

			body := hostSyncBody{Hosts: []syncHostBody{}}
			var lines, failed []string
			for _, e := range entries {
				hb := syncHostBody{Name: e.name, Steps: []string{}}
				if e.adapter == nil {
					hb.Status = statusNoAdapter
					lines = append(lines, "host "+e.name+": no adapter in this build; left as is")
					body.Hosts = append(body.Hosts, hb)
					continue
				}
				r := byHost[e.name]
				for _, s := range r.Steps {
					if s.Changed {
						hb.Steps = append(hb.Steps, s.Name)
					}
				}
				_, wasRecorded := recorded[e.name]
				switch {
				case r.Err() != nil:
					hb.Status = statusFailed
					step := r.FailedStep()
					if step == "" {
						step = "state"
					}
					failed = append(failed, e.name+" ("+step+")")
				case !wasRecorded:
					hb.Status = statusRegistered
				case r.Changed():
					hb.Status = statusRepaired
				default:
					hb.Status = statusUpToDate
				}
				lines = append(lines, syncLine(r, hb))
				body.Hosts = append(body.Hosts, hb)
			}
			if len(entries) == 0 {
				lines = append(lines, "no hosts registered; run 'qbit-vault init'")
			}

			rep := g.runDoctor()
			body.OK, body.Doctor = rep.OK, &rep
			var fail error
			if len(failed) > 0 {
				body.OK = false
				fail = codedError{"host_failed", "host registration failed: " + strings.Join(failed, ", "), exitcode.Failure}
			}
			out := cmd.OutOrStdout()
			if g.JSON {
				if fail != nil {
					return fail
				}
				if err := writeJSON(out, body); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintln(out, strings.Join(lines, "\n")); err != nil {
					return err
				}
				if err := rep.WriteHuman(out); err != nil {
					return err
				}
				if fail != nil {
					return fail
				}
			}
			if !rep.OK {
				return exitError{exitcode.Failure}
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&agents, "agents", nil, "also register these hosts, comma-separated (default: only the recorded ones)")
	return cmd
}

// syncLine is the human line of one host.
func syncLine(r hosts.Result, b syncHostBody) string {
	switch b.Status {
	case statusFailed:
		if r.FailedStep() != "" {
			return "host " + r.Host + ": failed at " + r.FailedStep()
		}
		return "host " + r.Host + ": failed to save its receipts"
	case statusRegistered, statusRepaired:
		return "host " + r.Host + ": " + b.Status + " (" + strings.Join(b.Steps, ", ") + ")"
	}
	return "host " + r.Host + ": up to date"
}
