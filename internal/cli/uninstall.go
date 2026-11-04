package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// purgeWord is what the user types to confirm --purge (PRD R-INS-09).
const purgeWord = "purge"

var errPurgeWord = codedError{"cancelled", "the confirmation word did not match; nothing was changed", exitcode.Failure}

type uninstallStepBody struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
}

type uninstallHostBody struct {
	Name   string              `json:"name"`
	Status string              `json:"status"`
	Steps  []uninstallStepBody `json:"steps"`
}

type uninstallBody struct {
	OK     bool                `json:"ok"`
	Home   string              `json:"home"`
	Purged bool                `json:"purged"`
	Hosts  []uninstallHostBody `json:"hosts"`
}

// newUninstall is `uninstall [--purge]` (docs/CLI.md, PRD R-INS-09): it
// reverts every host recorded in state.json through hosts.RevertHost (the file
// is restored byte for byte when it is still ours, otherwise only our entries
// are removed) and forgets a host only when its revert succeeded. The vault
// stays. With --purge, and only after the user types the word `purge`, it then
// deletes the vault home and the key's keychain entry. It is user-only: it
// asks through the prompt backend and is refused without one.
func newUninstall(g *globals) *cobra.Command {
	var purge bool
	cmd := &cobra.Command{
		Use:   "uninstall [--purge]",
		Short: "Revert the host registrations; with --purge also delete the vault",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ask, _, err := g.userBackend(false)
			if err != nil {
				return err
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

			// Everything that can refuse comes before the first change.
			if purge {
				if err := confirmPurge(g, ask, &home, len(entries)); err != nil {
					return err
				}
			} else if len(entries) > 0 {
				names := make([]string, len(entries))
				for i, e := range entries {
					names[i] = e.name
				}
				if err := askYes(ask, "Revert the qbit-vault registrations in "+strings.Join(names, ", ")+"? The vault stays."); err != nil {
					return err
				}
			}

			body := uninstallBody{Home: home, Hosts: []uninstallHostBody{}}
			var lines, failed []string
			reverted := 0
			for _, e := range entries {
				hb := uninstallHostBody{Name: e.name, Steps: []uninstallStepBody{}}
				if e.adapter == nil {
					hb.Status = statusNoAdapter
					failed = append(failed, e.name+" (no adapter)")
					lines = append(lines, "host "+e.name+": no adapter in this build; kept in state.json")
					body.Hosts = append(body.Hosts, hb)
					continue
				}
				done, err := hosts.RevertHost(g.hostEnv(), e.adapter)
				var parts []string
				for _, d := range done {
					hb.Steps = append(hb.Steps, uninstallStepBody{d.Step, string(d.Outcome)})
					parts = append(parts, d.Step+" "+string(d.Outcome))
				}
				if err != nil {
					step := "state"
					var re *hosts.RevertError
					if errors.As(err, &re) {
						step = re.Step
					}
					hb.Status = statusFailed
					failed = append(failed, e.name+" ("+step+")")
					lines = append(lines, "host "+e.name+": failed at "+step+"; kept in state.json")
				} else {
					hb.Status = statusReverted
					reverted++
					if len(parts) == 0 {
						parts = []string{"nothing to revert"}
					}
					lines = append(lines, "host "+e.name+": "+strings.Join(parts, ", "))
				}
				body.Hosts = append(body.Hosts, hb)
			}
			if len(entries) == 0 {
				lines = append(lines, "no hosts registered")
			}

			var fail error
			if len(failed) > 0 {
				fail = codedError{"host_revert_failed", "uninstall failed: " + strings.Join(failed, ", "), exitcode.Failure}
			}
			switch {
			case purge && fail == nil:
				if err := purgeVault(home); err != nil {
					return err
				}
				body.Purged = true
				lines = append(lines, "vault purged: "+home)
			case purge:
				lines = append(lines, "vault kept at "+home+" (not purged: a host was not reverted)")
			default:
				lines = append(lines, "vault kept at "+home)
			}
			if !body.Purged && len(entries) > 0 {
				g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventUninstall, Detail: fmt.Sprintf("reverted %d of %d hosts", reverted, len(entries))})
			}

			body.OK = fail == nil
			out := cmd.OutOrStdout()
			if g.JSON {
				if fail != nil {
					return fail
				}
				return writeJSON(out, body)
			}
			if _, err := fmt.Fprintln(out, strings.Join(lines, "\n")); err != nil {
				return err
			}
			return fail
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "also delete the vault and its keychain entry, after typing '"+purgeWord+"'")
	return cmd
}

// confirmPurge runs every check of --purge before the first change and asks
// the user to type the word. It leaves the absolute vault path in *home.
func confirmPurge(g *globals, ask prompt.Backend, home *string, hostCount int) error {
	abs, err := filepath.Abs(*home)
	if err != nil {
		return usageError{"cannot resolve the vault directory"}
	}
	*home = abs
	uh, _ := os.UserHomeDir()
	if err := safePurgeTarget(abs, uh); err != nil {
		return codedError{"unsafe_purge", err.Error(), exitcode.Failure}
	}
	rem, err := vault.ReadRemote(abs)
	if err != nil {
		return mapErr(err, "")
	}
	if rem != nil {
		// uninstall never touches the server: the device must leave the
		// account first, or its place in the roster would stay behind.
		return codedError{"sync_configured", "this vault syncs with " + rem.Server + "; run 'qbit-vault remote logout' first, then purge", exitcode.Failure}
	}
	word, err := askText(ask, prompt.SecretRequest{
		Name:    "confirmation",
		Reason:  fmt.Sprintf("Type '%s' to revert %d host registration(s) and permanently delete the vault at %s and its key in the OS keychain", purgeWord, hostCount, abs),
		Host:    "cli",
		Visible: true,
	})
	if err != nil {
		return err
	}
	if word != purgeWord {
		return errPurgeWord
	}
	return nil
}

// safePurgeTarget refuses to delete anything but a vault home: it must be an
// absolute, clean path to a real directory (not a symlink), and neither the
// user's home, one of its parents nor a filesystem root.
func safePurgeTarget(home, userHome string) error {
	bad := errors.New("refusing to delete this directory: it does not look like a vault home")
	if home == "" || !filepath.IsAbs(home) || filepath.Clean(home) != home || filepath.Dir(home) == home {
		return bad
	}
	if userHome != "" {
		rel, err := filepath.Rel(home, filepath.Clean(userHome))
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return bad // home is the user's home or one of its parents
		}
	}
	fi, err := os.Lstat(home)
	if err != nil || !fi.IsDir() || isLink(home) {
		return bad
	}
	// Everything in it must be something a vault keeps (docs/STORAGE.md):
	// a --home pointed at a folder of the user's own files is refused.
	entries, err := os.ReadDir(home)
	if err != nil {
		return bad
	}
	for _, e := range entries {
		if !vaultEntry(e.Name(), e.IsDir()) {
			return bad
		}
	}
	return nil
}

// isLink reports whether path is a symlink, or a junction or other reparse
// point (Lstat reports those as irregular on Windows): purge never follows
// one, whatever a Go version makes of IsDir for it.
func isLink(path string) bool {
	fi, err := os.Lstat(path)
	return err != nil || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0
}

// vaultFiles and vaultDirs are what a vault home holds; locks and the temp
// files of atomic writes are matched by shape.
var (
	vaultFiles = map[string]bool{"vault.enc": true, "state.json": true, "grants.enc": true, "audit.jsonl": true,
		"audit.head": true, "key.enc": true, "config.yaml": true, "bindings.yaml": true, "dumpguard.yaml": true}
	vaultDirs = map[string]bool{"backups": true, "keys": true, "remote": true}
)

func vaultEntry(name string, dir bool) bool {
	if dir {
		return vaultDirs[name]
	}
	if vaultFiles[name] || strings.HasSuffix(name, ".lock") {
		return true
	}
	// Temp files of atomic writes: <vault file>.tmp.<...> or .tmp-<...>.
	for _, sep := range []string{".tmp.", ".tmp-"} {
		if base, _, ok := strings.Cut(name, sep); ok && vaultFiles[base] {
			return true
		}
	}
	return false
}

// purgeVault deletes the vault home, then the key's OS keychain entry (or the
// passphrase unlock cache). It deletes nothing else.
func purgeVault(home string) error {
	id, err := vault.ReadID(home)
	if err != nil {
		return mapErr(err, "")
	}
	mode, err := keychain.ModeOf(home, keychain.Options{})
	if err != nil {
		return mapErr(err, "")
	}
	// Checked again right before the delete: the directory may have changed
	// while the user was typing the word.
	uh, _ := os.UserHomeDir()
	if err := safePurgeTarget(home, uh); err != nil {
		return codedError{"unsafe_purge", err.Error(), exitcode.Failure}
	}
	if err := os.RemoveAll(home); err != nil {
		return codedError{"purge_failed", "cannot delete the vault directory", exitcode.Failure}
	}
	if mode == keychain.ModePassphrase {
		_ = keychain.Lock(id, keychain.Options{}) // key.enc went with the directory
		return nil
	}
	if err := keychain.NewOS().Delete(id); err != nil && !errors.Is(err, keychain.ErrNoKey) {
		return codedError{"purge_failed", "the vault directory was deleted, but its keychain entry could not be", exitcode.Failure}
	}
	return nil
}
