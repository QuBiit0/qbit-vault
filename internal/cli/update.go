package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/minisign"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/selfupdate"
)

const (
	envReleasesAPI = "QBIT_VAULT_RELEASES_API"
	envNoSync      = "QBIT_VAULT_NO_SYNC"

	defaultReleasesAPI = "https://api.github.com/repos/qbitdevz/qbit-vault/releases/latest"

	msgNotRelease = "this build is not a release; install with the one-line installer or 'go install github.com/qbitdevz/qbit-vault/cmd/qbit-vault@latest'"
)

// Seams of `update`: tests point it at a temp copy of the binary, another OS
// and a fake re-registration; they never replace the test binary.
var (
	updateTarget = func() (string, error) {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.EvalSymlinks(exe)
	}
	updateGOOS   = runtime.GOOS
	updateGOARCH = runtime.GOARCH
	// updateResync re-applies the host registrations with the new binary.
	updateResync = resyncWithNewBinary
	// updateKey verifies the release signature. Nil is the key pinned in the
	// binary; only tests set it, to a throwaway key. No flag or variable reaches it.
	updateKey *minisign.PublicKey
)

type updateBody struct {
	OK              bool   `json:"ok"`
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"update_available"`
	Updated         bool   `json:"updated,omitempty"`
}

// updateAPI is the releases API URL: QBIT_VAULT_RELEASES_API when set, as for
// the installers, else the latest stable release of the repository.
func updateAPI(getenv func(string) string) string {
	if v := getenv(envReleasesAPI); v != "" {
		return v
	}
	return defaultReleasesAPI
}

func updateFailed(msg string) error { return codedError{"update_failed", msg, exitcode.Failure} }

// resyncWithNewBinary runs `sync` of the binary just installed, so the
// registrations, the agent skill and the adapters are those of the new
// version (the running one is the old code, and on Windows its path is the
// renamed copy).
func resyncWithNewBinary(ctx context.Context, g *globals, target string, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, target, "--home", g.Home(), "sync")
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Run()
}

// newUpdate is `update` (docs/CLI.md): it brings this binary to the latest
// release, verified with the SHA-256 of checksums.txt, after a confirmation
// the model cannot give. It never opens the vault and reads no secret.
func newUpdate(g *globals) *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "update [--check]",
		Short: "Update qbit-vault to the latest release (user-only)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdate(cmd, g, check)
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only report whether a newer release exists")
	return cmd
}

func runUpdate(cmd *cobra.Command, g *globals, check bool) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	out, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	current := Version
	if !check && !selfupdate.IsRelease(current) {
		return usageError{msgNotRelease}
	}
	var target string
	if !check {
		var err error
		if target, err = updateTarget(); err != nil {
			return updateFailed("cannot find this binary: re-run the install command")
		}
		if updateGOOS == "windows" {
			// Aside copies of earlier upgrades go now if nothing runs them.
			selfupdate.CleanOld(target)
		}
	}

	client := selfupdate.NewClient(current, updateAPI(g.getenv))
	client.Key = updateKey
	rel, err := client.Latest(ctx)
	if err != nil {
		return updateFailed(err.Error())
	}
	// A build that is not a release is older than any release.
	newer, err := selfupdate.Newer(current, rel.Tag)
	if err != nil {
		newer = true
	}
	body := updateBody{OK: true, Current: current, Latest: rel.Tag, UpdateAvailable: newer}

	if check || !newer {
		if g.JSON {
			return writeJSON(out, body)
		}
		if newer {
			_, err = fmt.Fprintf(out, "update available: %s -> %s\n", current, rel.Tag)
		} else {
			_, err = fmt.Fprintf(out, "qbit-vault %s is up to date\n", current)
		}
		return err
	}

	cannotReplace := updateFailed("cannot replace " + target + ": re-run the install command")
	dir := filepath.Dir(target)
	if selfupdate.CanReplace(dir) != nil {
		return cannotReplace
	}
	ask, err := g.backend()
	if err != nil {
		return refusal.New(refusal.NotModelCallable, "")
	}
	ok, err := ask.Confirm(fmt.Sprintf("Update QBit Vault %s to %s?", current, rel.Tag))
	switch {
	case errors.Is(err, prompt.ErrUnavailable):
		return refusal.New(refusal.NotModelCallable, "")
	case err != nil:
		return mapErr(err, "")
	case !ok:
		return errCancelled
	}

	tmp, err := client.Download(ctx, rel, updateGOOS, updateGOARCH, dir)
	if err != nil {
		return updateFailed(err.Error())
	}
	if err := selfupdate.Replace(target, tmp, updateGOOS); err != nil {
		os.Remove(tmp)
		return cannotReplace
	}
	body.Updated = true

	var syncText string
	// Re-apply the recorded registrations like the installers: only when the
	// vault is set up (state.json exists; it is not opened), and not with
	// QBIT_VAULT_NO_SYNC=1.
	if _, err := os.Stat(filepath.Join(g.Home(), "state.json")); err == nil {
		if g.getenv(envNoSync) == "1" {
			fmt.Fprintln(stderr, "skipped 'qbit-vault sync' (QBIT_VAULT_NO_SYNC=1); run it yourself so your agents use this binary")
		} else {
			// What sync printed (host lines, the Codex /hooks notice) is shown
			// after the "updated" line; --json keeps its single object.
			var syncOut bytes.Buffer
			if err := updateResync(ctx, g, target, &limitedWriter{w: &syncOut, left: maxSyncOutput}, stderr); err != nil {
				fmt.Fprintln(stderr, "'qbit-vault sync' reported a problem; run 'qbit-vault doctor', then restart your agents")
			}
			syncText = syncOut.String()
		}
	}
	if g.JSON {
		return writeJSON(out, body)
	}
	if _, err = fmt.Fprintf(out, "updated qbit-vault %s -> %s; restart your agents so they load the new version\n", current, rel.Tag); err != nil {
		return err
	}
	_, err = io.WriteString(out, syncText)
	return err
}

// maxSyncOutput bounds what is kept of the output of sync.
const maxSyncOutput = 64 << 10

// limitedWriter keeps the first left bytes and drops the rest without failing,
// so the child never blocks on a full pipe.
type limitedWriter struct {
	w    io.Writer
	left int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > l.left {
		p = p[:l.left]
	}
	l.left -= len(p)
	if _, err := l.w.Write(p); err != nil {
		return 0, err
	}
	return n, nil
}
