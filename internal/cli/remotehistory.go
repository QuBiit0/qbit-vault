package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/merge"
	"github.com/qbitdevz/qbit-vault/internal/remote"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// Server history and restore (docs/REMOTE_SYNC.md § 7.6). History is the
// last versions the server kept; restore writes the difference to one of
// them as new changes, so it syncs like an edit.

const historyLimit = 10

var (
	errVersionGone      = codedError{"restore_unavailable", "that version is not on the server; run 'qbit-vault remote history'", exitcode.Failure}
	errVersionOlderKey  = codedError{"restore_unavailable", "that version was sealed under an older account key and cannot be restored", exitcode.Failure}
	errVersionUnsealed  = codedError{"remote_auth", "the requested version could not be verified", exitcode.Failure}
	unknownDeviceLabel  = "unknown device"
	historyConnectLimit = 20 * time.Second
)

// writerLabel names the device that wrote a version, from the roster.
func writerLabel(roster map[string]merge.Device, id string) string {
	if d, ok := roster[id]; ok && d.Label != "" {
		return oneLine(d.Label)
	}
	return unknownDeviceLabel
}

// connectFor opens an authenticated client for a command that talks to the
// server; the caller cancels the context.
func (g *globals) connectFor(cmd *cobra.Command, s *session, st *vault.Remote, budget time.Duration) (context.Context, *remote.Client, thisDevice, func(), error) {
	d, err := s.device()
	if err != nil {
		return nil, nil, thisDevice{}, nil, err
	}
	ctx, cancel := netCtx(cmd, budget)
	c, err := g.connect(ctx, st, d)
	if err != nil {
		cancel()
		d.wipe()
		return nil, nil, thisDevice{}, nil, err
	}
	return ctx, c, d, func() { cancel(); d.wipe() }, nil
}

type versionRow struct {
	Version int64  `json:"version"`
	Device  string `json:"device"`
	At      string `json:"at"`
}

func newRemoteHistory(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "history",
		Short: "List the last versions the server kept",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			st, err := requireRemote(s)
			if err != nil {
				return err
			}
			roster, err := s.v.Roster()
			if err != nil {
				return mapErr(err, "")
			}
			ctx, c, _, done, err := g.connectFor(cmd, s, st, historyConnectLimit)
			if err != nil {
				return err
			}
			defer done()
			list, err := c.Versions(ctx)
			if err != nil {
				return g.remoteFail(err, "this device was refused by the server")
			}
			if len(list) > historyLimit {
				list = list[:historyLimit]
			}
			rows := make([]versionRow, 0, len(list))
			for _, v := range list {
				rows = append(rows, versionRow{Version: v.Version, Device: writerLabel(roster, v.Writer), At: oneLine(v.CreatedAt)})
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					OK       bool         `json:"ok"`
					Versions []versionRow `json:"versions"`
				}{true, rows})
			}
			w := cmd.OutOrStdout()
			for _, r := range rows {
				if _, err := fmt.Fprintf(w, "%d  %s  %s\n", r.Version, r.Device, r.At); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newRemoteRestore(g *globals) *cobra.Command {
	var version string
	cmd := &cobra.Command{
		Use:   "restore --version N",
		Short: "Make the vault equal to a version the server kept",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if version == "" {
				return usageError{"missing --version"}
			}
			n, err := strconv.ParseInt(version, 10, 64)
			if err != nil || n < 1 {
				return usageError{"invalid --version: must be a positive number"}
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
			if g.remoteOff() {
				return errRemoteOff
			}
			body, label, at, err := g.fetchVersion(cmd, s, n)
			if err != nil {
				return err
			}
			defer clear(body)
			q := fmt.Sprintf("Restore the vault to server version %d (written by %s, %s)? Records that differ are replaced; the current state stays in the local backups.", n, label, at)
			if err := askYes(ask, q); err != nil {
				return err
			}
			// Only now does anything change: the round brings this device up
			// to date (and pushes what it holds), then the difference is
			// written against the newest state.
			if err := g.syncBeforeRestore(cmd, s); err != nil {
				return err
			}
			changed, err := s.v.RestoreRecords(body)
			if err != nil {
				return mapErr(err, "")
			}
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventRemote, Detail: "restored version " + strconv.FormatInt(n, 10)})
			remoteState := g.pushAfterCmd(cmd, s)
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					OK       bool   `json:"ok"`
					Restored int64  `json:"restored"`
					Changed  int    `json:"changed"`
					Remote   string `json:"remote,omitempty"`
				}{true, n, changed, remoteState})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "restored version %d (%d records changed)\n", n, changed)
			return err
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "the server version to restore (see 'remote history')")
	return cmd
}

// fetchVersion downloads version n and verifies it: AEAD, and an AAD whose
// account is this one, whose generation is the current one and whose version
// is n. The server is not trusted to have sent what was asked. It changes
// nothing, locally or on the server, so a cancelled restore leaves no trace;
// a version sealed under a newer account key needs a sync first. It returns
// the plaintext body (the caller wipes it), the writer's label and the write
// time.
func (g *globals) fetchVersion(cmd *cobra.Command, s *session, n int64) ([]byte, string, string, error) {
	st, err := requireRemote(s)
	if err != nil {
		return nil, "", "", err
	}
	ctx, c, _, done, err := g.connectFor(cmd, s, st, 60*time.Second)
	if err != nil {
		return nil, "", "", err
	}
	defer done()
	vv, err := c.GetVersion(ctx, n)
	if errors.Is(err, remote.ErrNotFound) {
		return nil, "", "", errVersionGone
	} else if err != nil {
		return nil, "", "", g.remoteFail(err, "this device was refused by the server")
	}
	if gen, ok := peekGeneration(vv.Blob); ok && gen < st.Generation {
		return nil, "", "", errVersionOlderKey
	} else if ok && gen > st.Generation {
		return nil, "", "", errRecoveryStale
	}
	keys := remote.Subkeys(s.key)
	defer keys.Vault.Wipe()
	defer keys.Anchor.Wipe()
	defer keys.Pairing.Wipe()
	body, aad, err := remote.OpenObject(keys.Vault, st.AccountID, vv.Blob)
	if err != nil || aad.Generation != st.Generation || aad.Version != n || vv.Version != n {
		clear(body)
		return nil, "", "", errVersionUnsealed
	}
	if _, err := parseBody(body); err != nil {
		clear(body)
		return nil, "", "", errVersionUnsealed
	}
	roster, err := s.v.Roster()
	if err != nil {
		clear(body)
		return nil, "", "", mapErr(err, "")
	}
	return body, writerLabel(roster, aad.Writer), oneLine(aad.CreatedAt), nil
}

// syncBeforeRestore is the round that precedes a confirmed restore, so the
// records other devices wrote are replaced too.
func (g *globals) syncBeforeRestore(cmd *cobra.Command, s *session) error {
	st, err := requireRemote(s)
	if err != nil {
		return err
	}
	ctx, c, d, done, err := g.connectFor(cmd, s, st, 60*time.Second)
	if err != nil {
		return err
	}
	defer done()
	_, err = g.syncRound(ctx, s, c, d.id)
	return err
}
