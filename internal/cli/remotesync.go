package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/merge"
	"github.com/QuBiit0/qbit-vault/internal/remote"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// One sync round (docs/REMOTE_SYNC.md § 7.2) and the commands that only read
// the sync state. The ordinary commands run a round too (§ 7.1).

const maxRoundTries = 3

type roundResult struct {
	Result  string // synced, up_to_date or pending
	Version int64
	Reason  string
	// Discarded is how many old conflicts this round's merge dropped.
	Discarded int
}

// canon is the comparable form of a body: nil collections are empty, so two
// bodies that mean the same compare equal.
func canon(b *merge.Body) []byte {
	c := *b
	c.Schema = 2
	if c.Global == nil {
		c.Global = map[string]merge.Record{}
	}
	if c.Projects == nil {
		c.Projects = map[string]*merge.Project{}
	}
	for _, p := range c.Projects {
		if p.Secrets == nil {
			p.Secrets = map[string]merge.Record{}
		}
	}
	if c.Tombstones == nil {
		c.Tombstones = []merge.Tombstone{}
	}
	if c.Conflicts == nil {
		c.Conflicts = []merge.Conflict{}
	}
	if c.Devices == nil {
		c.Devices = map[string]merge.Device{}
	}
	out, _ := json.Marshal(&c)
	return out
}

func parseBody(raw []byte) (*merge.Body, error) {
	var b merge.Body
	if err := json.Unmarshal(raw, &b); err != nil || b.Schema != 2 {
		return nil, errors.New("the synced vault is not readable")
	}
	return &b, nil
}

// loadBase returns the body this device last agreed on with the server; ok
// is false when there is none (a device that has never synced).
func loadBase(v *vault.Vault) (*merge.Body, bool, error) {
	raw, err := v.Base()
	if err != nil && !errors.Is(err, os.ErrNotExist) && v.ResealRemoteFiles() == nil {
		raw, err = v.Base() // a key swap died before base.enc followed the key
	}
	if errors.Is(err, os.ErrNotExist) {
		return &merge.Body{Schema: 2}, false, nil
	}
	if err != nil {
		return nil, false, mapErr(err, "")
	}
	defer clear(raw)
	b, err := parseBody(raw)
	return b, err == nil, err
}

// summaryOf counts what `remote status` shows, for a vault that later
// cannot be opened without a prompt. A read failure leaves no summary.
func summaryOf(s *session, deviceID string) vault.RemoteSummary {
	roster, err := s.v.Roster()
	if err != nil {
		return vault.RemoteSummary{}
	}
	conflicts, err := s.v.ConflictCount()
	if err != nil {
		return vault.RemoteSummary{}
	}
	sum := vault.RemoteSummary{At: nowUTC(), Conflicts: conflicts}
	for id, d := range roster {
		if d.RevokedAt != nil {
			continue
		}
		sum.Devices++
		if id != deviceID && d.AddedBy == "recovery" {
			sum.RecoveryAdded++
		}
	}
	return sum
}

func saveRemoteState(home string, st *vault.Remote) error {
	if err := vault.WriteRemote(home, st); err != nil {
		return mapErr(err, "")
	}
	return nil
}

// syncRound runs one round for the vault in s with an authenticated client.
// Network calls happen outside the vault lock; only the merge holds it. A
// failure to reach the server leaves the local change committed and the push
// pending. A higher generation on the server first runs the key swap of
// REMOTE_SYNC § 4.5 (adoptGeneration); a lower one is a rollback.
func (g *globals) syncRound(ctx context.Context, s *session, c *remote.Client, deviceID string) (res roundResult, rerr error) {
	st, err := requireRemote(s)
	if err != nil {
		return roundResult{}, err
	}
	discarded := 0 // conflicts dropped by merges that were applied
	defer func() {
		if discarded > 0 {
			res.Discarded = discarded
			g.record(stderrOf(g), audit.Record{Event: audit.EventWarning, Detail: strconv.Itoa(discarded) + " old conflict(s) discarded"})
		}
	}()
	for try := 0; try < maxRoundTries; try++ {
		keys := remote.Subkeys(s.key) // changes when a key swap runs
		base, haveBase, err := loadBase(s.v)
		if err != nil {
			return roundResult{}, err
		}
		have := st.LastVersion
		if !haveBase {
			have = 0 // never trust "not modified" without a base to merge against
		}
		vv, err := c.GetVault(ctx, have)
		if err != nil {
			return g.roundFailed(s, st, err)
		}
		rver, remoteBody, newer := st.LastVersion, base, false
		if !vv.NotModified {
			if gen, ok := peekGeneration(vv.Blob); ok && gen < st.Generation {
				return roundResult{}, errRollback
			} else if ok && gen > st.Generation {
				// Sealed under a key this device does not have yet.
				if err := g.adoptGeneration(ctx, s, st, c, vv, gen); err != nil {
					return roundResult{}, err
				}
				continue
			}
			body, aad, err := remote.OpenObject(keys.Vault, st.AccountID, vv.Blob)
			if err != nil {
				return roundResult{}, codedError{"remote_auth", "the server's vault could not be verified", 1}
			}
			switch {
			case aad.Generation != st.Generation, aad.Version != vv.Version, aad.Version < st.LastVersion:
				clear(body)
				return roundResult{}, errRollback
			}
			remoteBody, err = parseBody(body)
			clear(body)
			if err != nil {
				return roundResult{}, codedError{"remote_auth", "the server's vault could not be verified", 1}
			}
			rver, newer = vv.Version, vv.Version > st.LastVersion
		}

		var (
			merged  []byte
			push    bool
			applied bool
			added   []merge.Device
			dropped int
		)
		err = s.v.ApplyBody(func(local []byte) ([]byte, error) {
			l, err := parseBody(local)
			if err != nil {
				return nil, err
			}
			m := merge.Merge(base, l, remoteBody, deviceID, time.Now())
			for id, d := range m.Devices {
				if _, had := l.Devices[id]; !had && id != deviceID && d.RevokedAt == nil {
					added = append(added, d)
				}
			}
			push = st.PendingPush || !bytes.Equal(canon(m), canon(remoteBody))
			if push {
				if d, ok := m.Devices[deviceID]; ok {
					d.LastSync = &merge.LastSync{Version: rver + 1, At: nowUTC()}
					m.Devices[deviceID] = d
				}
			}
			merged = canon(m)
			if bytes.Equal(merged, canon(l)) {
				return nil, nil
			}
			applied, dropped = true, m.Discarded
			return merged, nil
		})
		if err != nil {
			return roundResult{}, mapErr(err, "")
		}

		discarded += dropped
		if haveBase {
			g.warnNewDevices(added)
		}
		st.LastPullAt = nowUTC()
		if !push {
			if err := s.v.SaveBase(merged); err != nil {
				return roundResult{}, mapErr(err, "")
			}
			st.LastVersion, st.PendingPush = rver, false
			st.Summary = summaryOf(s, deviceID)
			if err := saveRemoteState(s.home, st); err != nil {
				return roundResult{}, err
			}
			result := "up_to_date"
			if applied || newer {
				result = "synced"
			}
			g.uploadAnchor(ctx, s, st, c, deviceID)
			return roundResult{Result: result, Version: rver}, nil
		}

		blob, err := remote.SealObject(keys.Vault, remote.ObjectAAD{AccountID: st.AccountID, Generation: st.Generation,
			Version: rver + 1, Writer: deviceID, CreatedAt: nowUTC()}, merged)
		if err != nil {
			return roundResult{}, err
		}
		ver, err := c.PutVault(ctx, rver, blob)
		if errors.Is(err, remote.ErrConflict) {
			continue // somebody pushed first: pull and merge again
		}
		if err != nil {
			return g.roundFailed(s, st, err)
		}
		if err := s.v.SaveBase(merged); err != nil {
			return roundResult{}, mapErr(err, "")
		}
		st.LastVersion, st.PendingPush = ver, false
		st.Summary = summaryOf(s, deviceID)
		if err := saveRemoteState(s.home, st); err != nil {
			return roundResult{}, err
		}
		g.uploadAnchor(ctx, s, st, c, deviceID)
		return roundResult{Result: "synced", Version: ver}, nil
	}
	st.PendingPush = true
	if err := saveRemoteState(s.home, st); err != nil {
		return roundResult{}, err
	}
	return roundResult{Result: "pending", Version: st.LastVersion, Reason: "the server changed while syncing; will retry"}, nil
}

// roundFailed records that the push is pending when the server could not be
// reached and returns the typed error.
func (g *globals) roundFailed(s *session, st *vault.Remote, err error) (roundResult, error) {
	if errors.Is(err, remote.ErrUnreachable) || errors.Is(err, remote.ErrRateLimited) {
		st.PendingPush = true
		_ = vault.WriteRemote(s.home, st)
	}
	return roundResult{}, g.remoteFail(err, "this device was refused by the server")
}

type syncBody struct {
	OK      bool   `json:"ok"`
	Result  string `json:"result"`
	Version int64  `json:"version"`
	Reason  string `json:"reason,omitempty"`
}

func newRemoteSync(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Run one sync round now (pull, merge, push)",
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
			var res roundResult
			if g.remoteOff() {
				st.PendingPush = true
				if err := saveRemoteState(s.home, st); err != nil {
					return err
				}
				res = roundResult{Result: "pending", Version: st.LastVersion, Reason: "remote calls are disabled by " + envNoRemote}
			} else if res, err = g.syncNow(cmd, s, st); err != nil {
				return err
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), syncBody{OK: true, Result: res.Result, Version: res.Version, Reason: res.Reason})
			}
			if res.Discarded > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "%d old conflict(s) were discarded; the current values are unchanged\n", res.Discarded)
			}
			var line string
			switch res.Result {
			case "synced":
				line = fmt.Sprintf("synced (version %d)\n", res.Version)
			case "up_to_date":
				line = fmt.Sprintf("up to date (version %d)\n", res.Version)
			default:
				line = "pending: " + res.Reason + "\n"
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), line)
			return err
		},
	}
}

// syncNow connects and runs one round; an unreachable server leaves the
// push pending.
func (g *globals) syncNow(cmd *cobra.Command, s *session, st *vault.Remote) (roundResult, error) {
	d, err := s.device()
	if err != nil {
		return roundResult{}, err
	}
	defer d.wipe()
	ctx, cancel := netCtx(cmd, 60*time.Second)
	defer cancel()
	c, err := g.connect(ctx, st, d)
	if err != nil {
		if errors.Is(err, errUnreachable) {
			st.PendingPush = true
			_ = vault.WriteRemote(s.home, st)
		}
		return roundResult{}, err
	}
	return g.syncRound(ctx, s, c, d.id)
}

// ---- status and devices: read-only, never prompt, never touch the network ----

type statusBody struct {
	OK                bool     `json:"ok"`
	Server            string   `json:"server"`
	Account           string   `json:"account"`
	Device            string   `json:"device"`
	Generation        int      `json:"generation"`
	Version           int64    `json:"version"`
	LastSync          string   `json:"last_sync"`
	PendingPush       bool     `json:"pending_push"`
	Conflicts         *int     `json:"conflicts"` // null while locked
	Devices           *int     `json:"devices"`   // null while locked
	Locked            bool     `json:"locked"`
	CountsFrom        string   `json:"counts_from,omitempty"` // "last_sync" while locked
	RecoveryConfirmed bool     `json:"recovery_confirmed"`
	Anchor            string   `json:"anchor"`
	Warnings          []string `json:"warnings"`
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func newRemoteStatus(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the sync state of this device",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Read-only and never prompting: state.json needs no key; the
			// roster and the conflict count do, so without a key that opens
			// the vault as it is they read "locked".
			home := g.Home()
			if _, err := vault.ReadID(home); err != nil {
				return mapErr(err, "")
			}
			st, err := requireRemoteAt(home)
			if err != nil {
				return err
			}
			var (
				roster    map[string]merge.Device
				conflicts int
			)
			s, err := g.openSessionQuiet()
			locked := errors.Is(err, errSessionLocked)
			switch {
			case err != nil && !locked:
				return err
			case err == nil:
				defer s.close()
				if roster, err = s.v.Roster(); err != nil {
					return mapErr(err, "")
				}
				if conflicts, err = s.v.ConflictCount(); err != nil {
					return mapErr(err, "")
				}
			}
			id, _ := vault.ReadDeviceID(home)
			live, label := 0, ""
			for did, d := range roster {
				if d.RevokedAt == nil {
					live++
				}
				if did == id {
					label = oneLine(d.Label)
				}
			}
			out := statusBody{OK: true, Server: st.Server, Account: short(st.AccountID), Device: short(id), Generation: st.Generation,
				Version: st.LastVersion, LastSync: st.LastPullAt, PendingPush: st.PendingPush, Locked: locked,
				RecoveryConfirmed: !st.RecoveryUnconfirmed, Anchor: anchorText(home), Warnings: []string{}}
			cached := locked && st.Summary.At != ""
			switch {
			case !locked:
				out.Conflicts, out.Devices = &conflicts, &live
			case cached:
				conflicts, live = st.Summary.Conflicts, st.Summary.Devices
				out.Conflicts, out.Devices, out.CountsFrom = &conflicts, &live, "last_sync"
				if n := st.Summary.RecoveryAdded; n > 0 {
					out.Warnings = append(out.Warnings, fmt.Sprintf("%d %s added by recovery", n, plural(n, "device", "devices")))
				}
			}
			if st.PendingPush {
				out.Warnings = append(out.Warnings, "pending push")
			}
			if conflicts > 0 {
				out.Warnings = append(out.Warnings, fmt.Sprintf("%d sync conflicts", conflicts))
			}
			if st.RecoveryUnconfirmed {
				out.Warnings = append(out.Warnings, "recovery key not confirmed")
			}
			for did, d := range roster {
				if did != id && d.RevokedAt == nil && (d.AddedBy == "recovery") {
					out.Warnings = append(out.Warnings, "device added by recovery: "+oneLine(d.Label))
				}
			}
			sort.Strings(out.Warnings)
			if g.JSON {
				if err := writeJSON(cmd.OutOrStdout(), out); err != nil {
					return err
				}
			} else {
				last := out.LastSync
				if last == "" {
					last = "never"
				}
				yn := map[bool]string{true: "yes", false: "no"}
				w := cmd.OutOrStdout()
				device, nConflicts, nDevices := fmt.Sprintf("%s (%s)", out.Device, label), strconv.Itoa(conflicts), strconv.Itoa(live)
				switch {
				case cached:
					device, nConflicts, nDevices = out.Device, nConflicts+" (as of the last sync)", nDevices+" (as of the last sync)"
				case locked:
					device, nConflicts, nDevices = out.Device, lockedText, lockedText
				}
				fmt.Fprintf(w, "server:        %s\naccount:       %s\ndevice:        %s\ngeneration:    %d\nversion:       %d\nlast sync:     %s\npending push:  %s\nconflicts:     %s\ndevices:       %s\nanchor:        %s\n",
					st.Server, out.Account, device, st.Generation, st.LastVersion, last, yn[st.PendingPush], nConflicts, nDevices, out.Anchor)
				for _, w2 := range out.Warnings {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warningText(w2))
				}
			}
			if len(out.Warnings) > 0 {
				return exitError{exitcode.Failure}
			}
			return nil
		},
	}
}

// lockedText stands for what `remote status` cannot read without the key.
const lockedText = "locked (run 'qbit-vault unlock')"

// anchorText is the anchor state `remote status` shows: when the last audit
// anchor was uploaded, or none.
func anchorText(home string) string {
	if at, ok, err := vault.ReadAnchorAt(home); err == nil && ok {
		return at.UTC().Format(time.RFC3339)
	}
	return "none uploaded"
}

// warningText is the stderr line of a status warning.
func warningText(w string) string {
	if w == "pending push" {
		return "not synced (changes are waiting for the server); run 'qbit-vault remote sync'"
	}
	return w
}

type deviceRow struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	AddedBy   string `json:"added_by"`
	AddedAt   string `json:"added_at,omitempty"`
	LastSync  string `json:"last_sync,omitempty"`
	Revoked   bool   `json:"revoked"`
	RevokedAt string `json:"revoked_at,omitempty"`
	This      bool   `json:"this"`
}

func newRemoteDevices(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "devices",
		Short: "List the devices of the synced vault",
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
			roster, err := s.v.Roster()
			if err != nil {
				return mapErr(err, "")
			}
			me, _ := vault.ReadDeviceID(s.home)
			rows := make([]deviceRow, 0, len(roster))
			for id, d := range roster {
				// Every field comes from a body another device wrote: one line each.
				r := deviceRow{ID: oneLine(id), Label: oneLine(d.Label), AddedBy: oneLine(d.AddedBy), AddedAt: oneLine(d.AddedAt), This: id == me}
				if d.LastSync != nil {
					r.LastSync = oneLine(d.LastSync.At)
				}
				if d.RevokedAt != nil {
					r.Revoked, r.RevokedAt = true, oneLine(*d.RevokedAt)
				}
				rows = append(rows, r)
			}
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].AddedAt != rows[j].AddedAt {
					return rows[i].AddedAt < rows[j].AddedAt
				}
				return rows[i].ID < rows[j].ID
			})
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					OK      bool        `json:"ok"`
					Devices []deviceRow `json:"devices"`
				}{true, rows})
			}
			w := cmd.OutOrStdout()
			for _, r := range rows {
				last := r.LastSync
				if last == "" {
					last = "never"
				}
				line := fmt.Sprintf("%s  %s  added: %s  last sync: %s", r.ID, r.Label, r.AddedBy, last)
				if r.Revoked {
					line += "  revoked: " + r.RevokedAt
				}
				if r.This {
					line += "  (this device)"
				}
				if _, err := fmt.Fprintln(w, line); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// warnNewDevices audits a device this device did not know that joined by
// pairing or recovery (REMOTE_SYNC § 4.3), so an unexpected one is visible.
func (g *globals) warnNewDevices(added []merge.Device) {
	sort.Slice(added, func(i, j int) bool { return added[i].AddedAt < added[j].AddedAt })
	for _, d := range added {
		if d.AddedBy == "pairing" || d.AddedBy == "recovery" {
			g.record(stderrOf(g), audit.Record{Event: audit.EventWarning, Detail: "device added: " + oneLine(d.Label) + " via " + d.AddedBy})
		}
	}
}
