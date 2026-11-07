package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/merge"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/remote"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// errRecoveryStale: the account key changed since this device last synced
// (another device rotated it, or a rotation here did not finish locally).
var errRecoveryStale = codedError{"internal", "the account key changed since the last sync; run 'qbit-vault remote sync', then try again", exitcode.Failure}

// rotated is what a finished rotation reports.
type rotated struct{ generation int }

// rotateAccount runs steps 1-5 of the order in remoterekey.go. revoke is the
// device to revoke ("" for none). The caller has already confirmed with the
// person.
func (g *globals) rotateAccount(cmd *cobra.Command, s *session, ask prompt.Backend, show prompt.Shower, revoke string) (rotated, error) {
	me, err := s.device()
	if err != nil {
		return rotated{}, err
	}
	defer me.wipe()
	st, err := requireRemote(s)
	if err != nil {
		return rotated{}, err
	}
	ctx, cancel := netCtx(cmd, 60*time.Second)
	defer cancel()
	c, err := g.connect(ctx, st, me)
	if err != nil {
		return rotated{}, err
	}
	for try := 0; try < maxRoundTries; try++ {
		res, err := g.syncRound(ctx, s, c, me.id)
		if err != nil {
			return rotated{}, err
		}
		if res.Result == remotePending {
			continue // somebody pushed while syncing: pull again
		}
		if st, err = requireRemote(s); err != nil {
			return rotated{}, err
		}
		out, retry, err := g.rotateOnce(ctx, cmd, s, st, c, me, ask, show, revoke)
		if retry {
			continue
		}
		return out, err
	}
	return rotated{}, errRotateConflict
}

// rotateOnce builds and sends one rekey against the server version st holds.
// retry is true when the server said the base was stale.
func (g *globals) rotateOnce(ctx context.Context, cmd *cobra.Command, s *session, st *vault.Remote, c *remote.Client, me thisDevice, ask prompt.Backend, show prompt.Shower, revoke string) (out rotated, retry bool, err error) {
	devs, err := c.Devices(ctx)
	if err != nil {
		return rotated{}, false, g.remoteFail(err, "this device was refused by the server")
	}
	raw, err := s.v.Body()
	if err != nil {
		return rotated{}, false, mapErr(err, "")
	}
	mb, err := parseBody(raw)
	clear(raw)
	if err != nil {
		return rotated{}, false, mapErr(err, "")
	}
	if mb.Devices == nil {
		mb.Devices = map[string]merge.Device{}
	}
	at := nowUTC()
	if revoke != "" {
		d, ok := mb.Devices[revoke]
		switch {
		case revoke == me.id:
			return rotated{}, false, errRevokeSelf
		case !ok:
			return rotated{}, false, errRevokeUnknown
		case d.RevokedAt != nil:
			return rotated{}, false, errRevokeAlready
		}
		d.RevokedAt = &at
		mb.Devices[revoke] = d
	}
	gen := st.Generation + 1
	if d, ok := mb.Devices[me.id]; ok {
		d.LastSync = &merge.LastSync{Version: st.LastVersion + 1, At: at}
		mb.Devices[me.id] = d
	}

	next, err := keychain.NewKey()
	if err != nil {
		return rotated{}, false, err
	}
	defer next.Wipe()
	rk, rkText, err := remote.NewRecoveryKey()
	if err != nil {
		return rotated{}, false, err
	}
	defer rk.Wipe()
	rec := remote.RecoveryFromKey(rk)

	envs, drop, orphans := map[string][]byte{}, []string{}, []string{}
	for _, di := range devs {
		d, ok := mb.Devices[di.ID]
		switch {
		case di.ID == revoke:
			drop = append(drop, di.ID)
		case !ok:
			// On the server but in no roster (an approve whose roster write
			// failed): nobody can see it, so the rotation cuts it off.
			drop = append(drop, di.ID)
			orphans = append(orphans, di.ID)
		case d.RevokedAt != nil:
			drop = append(drop, di.ID) // revoked in the roster, still on the server
		default:
			box, err := base64.StdEncoding.DecodeString(d.BoxPub)
			if err != nil {
				return rotated{}, false, errNotInRoster
			}
			env, err := remote.SealKeyEnvelope(me.key, box, remote.EnvelopeAAD{AccountID: st.AccountID, DeviceID: di.ID, Generation: gen, Issuer: me.id}, next)
			if err != nil {
				return rotated{}, false, err
			}
			envs[di.ID] = env
		}
	}
	plain := canon(mb)
	defer clear(plain)
	blob, err := remote.SealObject(remote.Subkeys(next).Vault, remote.ObjectAAD{AccountID: st.AccountID, Generation: gen,
		Version: st.LastVersion + 1, Writer: me.id, CreatedAt: at}, plain)
	if err != nil {
		return rotated{}, false, err
	}
	recEnv, err := remote.SealRecovery(rec.Wrap, st.AccountID, gen, next)
	if err != nil {
		return rotated{}, false, err
	}

	// Pessimistic until the person has confirmed the new recovery key.
	was := st.RecoveryUnconfirmed
	st.RecoveryUnconfirmed = true
	if err := saveRemoteState(s.home, st); err != nil {
		return rotated{}, false, err
	}
	ver, err := c.Rekey(ctx, remote.RekeyRequest{Base: st.LastVersion, Generation: gen, Blob: blob, Envelopes: envs,
		Recovery: rec, RecoveryEnvelope: recEnv, Revoke: drop})
	if err != nil {
		st.RecoveryUnconfirmed = was
		_ = saveRemoteState(s.home, st)
		switch {
		case errors.Is(err, remote.ErrConflict):
			return rotated{}, true, nil
		case errors.Is(err, remote.ErrInvalid):
			return rotated{}, false, errServerFailed
		}
		return rotated{}, false, g.remoteFail(err, "this device was refused by the server")
	}
	// The account is on generation g+1 from here on.
	if err := crashAt("after-server"); err != nil {
		return rotated{}, false, err
	}
	if err := g.swapKey(s, next); err != nil {
		return rotated{}, false, errRotateHalf
	}
	if revoke != "" {
		if err := s.v.EditRoster(func(r map[string]merge.Device) {
			if d, ok := r[revoke]; ok && d.RevokedAt == nil {
				d.RevokedAt = &at
				r[revoke] = d
			}
		}); err != nil {
			return rotated{}, false, errRotateHalf
		}
	}
	if err := s.v.SaveBase(plain); err != nil {
		return rotated{}, false, errRotateHalf
	}
	st.Generation, st.LastVersion, st.PendingPush, st.LastPullAt = gen, ver, false, nowUTC()
	if err := saveRemoteState(s.home, st); err != nil {
		return rotated{}, false, errRotateHalf
	}
	if revoke != "" {
		g.auditRemote(cmd, "device revoked "+revoke)
	}
	for _, id := range orphans {
		g.auditRemote(cmd, "device revoked "+id)
		fmt.Fprintf(cmd.ErrOrStderr(), "unknown device %s was revoked\n", id)
	}
	g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventRekey, Detail: fmt.Sprintf("remote generation %d", gen)})

	if err := confirmRecoveryKey(ask, show, rkText); err != nil {
		return rotated{generation: gen}, false, err
	}
	st.RecoveryUnconfirmed = false
	if err := saveRemoteState(s.home, st); err != nil {
		return rotated{}, false, err
	}
	return rotated{generation: gen}, false, nil
}

// ---- remote revoke-device ID (§ 4.5) ----

func newRemoteRevokeDevice(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke-device ID",
		Short: "Revoke a device and rotate the account key",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError{"give the device id: remote revoke-device ID"}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			st, err := requireRemote(s)
			if err != nil {
				return err
			}
			ask, show, err := g.userBackend(true)
			if err != nil {
				return err
			}
			if g.remoteOff() {
				return errRemoteOff
			}
			roster, err := s.v.Roster()
			if err != nil {
				return mapErr(err, "")
			}
			me, _ := vault.ReadDeviceID(s.home)
			d, ok := roster[id]
			switch {
			case id == me:
				return errRevokeSelf
			case !deviceIDRE.MatchString(id) || !ok:
				return errRevokeUnknown
			case d.RevokedAt != nil:
				return errRevokeAlready
			}
			last := "never"
			if d.LastSync != nil {
				last = oneLine(d.LastSync.At)
			}
			host := serverHost(st.Server)
			if err := askYes(ask, fmt.Sprintf("Revoke device %s (last sync %s) on %s? It will lose access to the synced vault; the account key and the recovery key will be replaced.", oneLine(d.Label), last, host)); err != nil {
				return err
			}
			res, err := g.rotateAccount(cmd, s, ask, show, id)
			if err != nil {
				return err
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					OK         bool   `json:"ok"`
					Revoked    string `json:"revoked"`
					Generation int    `json:"generation"`
				}{true, id, res.generation})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "revoked %s (%s); the account key is now generation %d\n", oneLine(d.Label), id, res.generation)
			return err
		},
	}
}

// ---- remote recovery-key --rotate (§ 4.6) ----

// newRemoteRecoveryKey replaces the recovery key through PUT /v1/recovery;
// the account key and the vault stay as they are. A recovery key that may
// have been seen while the master key also may have been is a case for
// `rekey`, which replaces both.
func newRemoteRecoveryKey(g *globals) *cobra.Command {
	var rotate bool
	cmd := &cobra.Command{
		Use:   "recovery-key --rotate",
		Short: "Replace the recovery key",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !rotate {
				return usageError{"give --rotate to replace the recovery key"}
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			st, err := requireRemote(s)
			if err != nil {
				return err
			}
			ask, show, err := g.userBackend(true)
			if err != nil {
				return err
			}
			if g.remoteOff() {
				return errRemoteOff
			}
			if err := askYes(ask, "Replace the recovery key for your vault on "+serverHost(st.Server)+"? The old recovery key stops working."); err != nil {
				return err
			}
			if err := g.rotateRecovery(cmd, s, st, ask, show); err != nil {
				return err
			}
			g.auditRemote(cmd, "recovery key rotated")
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					OK      bool `json:"ok"`
					Rotated bool `json:"rotated"`
				}{true, true})
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "recovery key rotated")
			return err
		},
	}
	cmd.Flags().BoolVar(&rotate, "rotate", false, "replace the recovery key")
	return cmd
}

// rotateRecovery replaces only the recovery key (REMOTE_SYNC § 4.6): a new
// recovery envelope of the current account key at the current generation.
// The state says "unconfirmed" from before the server call until the person
// confirms the new key, so a failure in between keeps status warning.
func (g *globals) rotateRecovery(cmd *cobra.Command, s *session, st *vault.Remote, ask prompt.Backend, show prompt.Shower) error {
	me, err := s.device()
	if err != nil {
		return err
	}
	defer me.wipe()
	ctx, cancel := netCtx(cmd, 60*time.Second)
	defer cancel()
	c, err := g.connect(ctx, st, me)
	if err != nil {
		return err
	}
	rk, rkText, err := remote.NewRecoveryKey()
	if err != nil {
		return err
	}
	defer rk.Wipe()
	rec := remote.RecoveryFromKey(rk)
	env, err := remote.SealRecovery(rec.Wrap, st.AccountID, st.Generation, s.key)
	if err != nil {
		return err
	}
	was := st.RecoveryUnconfirmed
	st.RecoveryUnconfirmed = true
	if err := saveRemoteState(s.home, st); err != nil {
		return err
	}
	if err := c.RotateRecovery(ctx, st.Generation, rec, env); err != nil {
		st.RecoveryUnconfirmed = was
		_ = saveRemoteState(s.home, st)
		if errors.Is(err, remote.ErrConflict) {
			return errRecoveryStale
		}
		return g.remoteFail(err, "this device was refused by the server")
	}
	if err := confirmRecoveryKey(ask, show, rkText); err != nil {
		return err
	}
	st.RecoveryUnconfirmed = false
	return saveRemoteState(s.home, st)
}
