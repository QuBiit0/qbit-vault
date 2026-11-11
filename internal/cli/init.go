package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/doctor"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/hosts"
	"github.com/qbitdevz/qbit-vault/internal/hosts/codex"
	"github.com/qbitdevz/qbit-vault/internal/hosts/pi"
	"github.com/qbitdevz/qbit-vault/internal/keychain"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// newVaultID is replaceable so tests can pin the id.
var newVaultID = vault.NewID

const maxPassphraseBytes = 4096

type initBody struct {
	OK          bool           `json:"ok"`
	Initialized bool           `json:"initialized"`
	Home        string         `json:"home"`
	Keychain    string         `json:"keychain,omitempty"`
	Hosts       []initHostBody `json:"hosts,omitempty"`
	Doctor      *doctor.Report `json:"doctor,omitempty"`
}

// initHostBody is one host of the init report: the steps that wrote a config
// file in this run (empty when nothing changed).
type initHostBody struct {
	Name    string   `json:"name"`
	Changed bool     `json:"changed"`
	Steps   []string `json:"steps"`
}

const agentsNone = "none"

const (
	// restartAgentsLine ends an init that wrote a host config: a running
	// agent loaded its config before.
	restartAgentsLine = "Restart your coding agents so they load QBit Vault."
	// hostFailureHint ends the error of a failed host registration.
	hostFailureHint = "; run 'qbit-vault doctor' for details"
)

// pickHosts resolves --agents before anything is created: no flag selects the
// detected hosts, a list selects those hosts whether or not they are
// detected, and `none` selects nothing.
func (g *globals) pickHosts(cmd *cobra.Command, agents []string) ([]hosts.Adapter, error) {
	reg := hostRegistry(g)
	if !cmd.Flags().Changed("agents") {
		return reg.Detected(g.hostEnv()), nil
	}
	var names []string
	for _, a := range agents {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			names = append(names, a)
		}
	}
	switch {
	case len(names) == 0:
		return nil, usageError{"--agents needs host names or '" + agentsNone + "'"}
	case slices.Contains(names, agentsNone):
		if len(names) > 1 {
			return nil, usageError{"--agents " + agentsNone + " cannot be combined with host names"}
		}
		return nil, nil
	}
	sel, err := reg.Pick(names)
	if err != nil {
		if len(reg.Names()) == 0 {
			return nil, usageError{"unknown agent; no hosts are available in this build"}
		}
		return nil, usageError{"unknown agent; available: " + strings.Join(reg.Names(), ", ")}
	}
	return sel, nil
}

// newInit is `init`: it creates the master key and an empty vault when there
// is none, registers the selected hosts (idempotently, on every run) and
// finishes with the doctor report. It never reads the environment for values
// and never asks for, reads or stores a secret.
func newInit(g *globals) *cobra.Command {
	var passphrase, passphraseStdin bool
	var agents []string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create an empty vault and register the coding-agent hosts",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if passphraseStdin && !passphrase {
				return usageError{"--passphrase-stdin requires --passphrase"}
			}
			selected, err := g.pickHosts(cmd, agents)
			if err != nil {
				return err
			}
			home := g.Home()
			out := cmd.OutOrStdout()
			body := initBody{OK: true, Home: home}
			line := "vault already initialized at " + home
			switch _, err := vault.ReadID(home); {
			case err == nil:
			case !errors.Is(err, os.ErrNotExist):
				return mapErr(err, "")
			default:
				mode, err := g.createVault(cmd, passphrase, passphraseStdin)
				if err != nil {
					return err
				}
				body.Initialized, body.Keychain = true, string(mode)
				line = fmt.Sprintf("vault initialized at %s (keychain: %s)", home, mode)
				if mode == keychain.ModePassphrase && !passphrase {
					line += "\nno OS keychain found (WSL or a headless Linux?): the master key is protected by the passphrase you just set; 'qbit-vault unlock' opens it"
				}
			}

			results := hosts.Apply(g.hostEnv(), selected)
			rep := g.runDoctor()
			body.OK = rep.OK
			show := len(results) > 0 || !rep.OK // a vault-only run keeps its one line

			var failed []string
			changed := false
			for _, r := range results {
				hb := initHostBody{Name: r.Host, Changed: r.Changed(), Steps: []string{}}
				for _, s := range r.Steps {
					if s.Changed {
						hb.Steps = append(hb.Steps, s.Name)
					}
				}
				body.Hosts = append(body.Hosts, hb)
				changed = changed || hb.Changed
				if r.Err() != nil {
					step := r.FailedStep()
					if step == "" {
						step = "state"
					}
					failed = append(failed, r.Host+" ("+step+")")
				}
			}
			var fail error
			if len(failed) > 0 {
				fail = codedError{"host_failed", "host registration failed: " + strings.Join(failed, ", ") + hostFailureHint, exitcode.Failure}
			}

			if g.JSON {
				if fail != nil {
					return fail
				}
				if show {
					body.Doctor = &rep
				}
				if err := writeJSON(out, body); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintln(out, line); err != nil {
					return err
				}
				for i, r := range results {
					if _, err := fmt.Fprintln(out, hostLine(r, body.Hosts[i])); err != nil {
						return err
					}
					for _, hint := range []string{extensionHint(r), codexTrustHint(r)} {
						if hint == "" {
							continue
						}
						if _, err := fmt.Fprintln(out, hint); err != nil {
							return err
						}
					}
				}
				if show {
					if err := rep.WriteHuman(out); err != nil {
						return err
					}
				}
				if changed {
					if _, err := fmt.Fprintln(out, restartAgentsLine); err != nil {
						return err
					}
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
	f := cmd.Flags()
	f.BoolVar(&passphrase, "passphrase", false, "protect the master key with a passphrase instead of the OS keychain")
	f.BoolVar(&passphraseStdin, "passphrase-stdin", false, "read the passphrase from the first line of stdin instead of asking on the terminal")
	f.StringSliceVar(&agents, "agents", nil, "hosts to register, comma-separated, or 'none' (default: the hosts detected on this machine)")
	return cmd
}

// extensionHint is the optional install suggestion printed under the line of a
// host that has an extension, once that host is registered. It is text only:
// qbit-vault never runs it (invariant 8: installing needs the network). JSON
// output does not carry it.
func extensionHint(r hosts.Result) string {
	if r.Host != pi.Name || r.Err() != nil {
		return ""
	}
	return "  Pi extension (optional, run it yourself): " + pi.ExtensionInstallCommand + "\n  with plain Pi: " + pi.ExtensionInstallCommandPi
}

// codexTrustHint tells the user to trust the hooks just written: Codex skips
// a new or changed hook until it is reviewed in /hooks, so without this step
// the output guard would silently not run. Text only; qbit-vault never writes
// Codex's trust state.
func codexTrustHint(r hosts.Result) string {
	if r.Host != codex.Name || r.Err() != nil {
		return ""
	}
	for _, s := range r.Steps {
		if s.Name == "hooks" && s.Changed {
			return "  Codex skips new hooks until you trust them: open /hooks in Codex and trust the qbit-vault hooks."
		}
	}
	return ""
}

// hostLine is the human line of one host.
func hostLine(r hosts.Result, b initHostBody) string {
	switch {
	case r.Err() != nil && r.FailedStep() != "":
		return "host " + r.Host + ": failed at " + r.FailedStep()
	case r.Err() != nil:
		return "host " + r.Host + ": failed to save its receipts"
	case b.Changed:
		return "host " + r.Host + ": registered (" + strings.Join(b.Steps, ", ") + ")"
	default:
		return "host " + r.Host + ": up to date"
	}
}

// createVault makes the master key and the empty vault of a new home.
func (g *globals) createVault(cmd *cobra.Command, passphrase, passphraseStdin bool) (keychain.Mode, error) {
	home := g.Home()
	opts := keychain.Options{ForcePassphrase: passphrase}
	switch {
	case passphrase && passphraseStdin:
		pass, err := readPassphrase(stdinOf(cmd))
		if err != nil {
			return "", err
		}
		defer clear(pass)
		opts.Passphrase = func(bool) (secret.Secret, error) { return secret.New("passphrase", pass), nil }
	default:
		// Asked twice through the prompt backend, never from stdin. Without
		// --passphrase it is only asked when no OS keychain is reachable (WSL,
		// a headless Linux box), so init does not fail there.
		opts.Passphrase = g.askPassphrase
	}

	id := newVaultID()
	key, mode, err := keychain.Setup(home, id, opts)
	if err != nil {
		if errors.Is(err, keychain.ErrKeyExists) {
			return "", errors.New("a master key already exists for this vault home; run 'qbit-vault doctor'")
		}
		if !passphrase && (errors.Is(err, prompt.ErrUnavailable) || errors.Is(err, keychain.ErrUnavailable)) {
			return "", usageError{"no OS keychain found and no terminal to ask for a passphrase; run 'qbit-vault init --passphrase --passphrase-stdin'"}
		}
		return "", promptFail(err, "use --passphrase-stdin")
	}
	defer key.Wipe()
	if _, err := vault.Init(home, id, key); err != nil {
		removeKey(home, id, mode, opts)
		if errors.Is(err, vault.ErrExists) {
			// A vault file without a state file: damaged, not new.
			return "", refusal.New(refusal.VaultCorrupt, "")
		}
		return "", mapErr(err, "")
	}
	g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventInit, Detail: string(mode)})
	return mode, nil
}

// removeKey deletes the key Setup just created, so a failed vault.Init does
// not leave an orphan.
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
