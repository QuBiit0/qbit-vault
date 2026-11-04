package cli

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/keychain"
	"github.com/QuBiit0/gentle-vault/internal/merge"
	"github.com/QuBiit0/gentle-vault/internal/prompt"
	"github.com/QuBiit0/gentle-vault/internal/remote"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// Account lifecycle commands (docs/REMOTE_SYNC.md § 4): register, join,
// approve and logout. All of them are user-only.

const (
	nameInvite   = "invite code"
	nameRecovery = "recovery key"
	nameLastFour = "recovery key, last four characters"
	namePairing  = "pairing code"
	nameLabel    = "device label"
	nameConfirm  = "confirmation code"

	maxKeyChecks = 5
)

func (g *globals) auditRemote(cmd *cobra.Command, detail string) {
	g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventRemote, Detail: detail})
}

type accountBody struct {
	OK         bool   `json:"ok"`
	Registered bool   `json:"registered,omitempty"`
	Joined     bool   `json:"joined,omitempty"`
	Server     string `json:"server"`
	Account    string `json:"account"`
	Version    int64  `json:"version,omitempty"`
}

// ---- register (§ 4.1) ----

func newRemoteRegister(g *globals) *cobra.Command {
	var server, caFile string
	cmd := &cobra.Command{
		Use:   "register --server URL",
		Short: "Register this vault on a gentle-vault-server as the first device",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if server == "" {
				return usageError{"give the server with --server URL"}
			}
			c, err := remote.NewClient(server, caFile)
			if err != nil {
				return clientErr(err)
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			if st, err := vault.ReadRemote(s.home); err != nil {
				return mapErr(err, "")
			} else if st != nil {
				return usageError{"this vault already syncs; run 'gentle-vault remote logout' first"}
			}
			ask, show, err := g.userBackend(true)
			if err != nil {
				return err
			}
			if g.remoteOff() {
				return errRemoteOff
			}
			ctx, cancel := netCtx(cmd, 60*time.Second)
			defer cancel()
			if _, err := c.Info(ctx); err != nil {
				return remoteErr(err, "")
			}
			host := serverHost(server)
			invite, err := askText(ask, prompt.SecretRequest{Name: nameInvite, Reason: "Register this vault on " + host, Host: "cli"})
			if err != nil {
				return err
			}
			if err := askYes(ask, "Sync this vault to "+host+"? Secrets are encrypted on this device before upload; the server can never read them."); err != nil {
				return err
			}

			deviceID, err := vault.ReadDeviceID(s.home)
			if err != nil || deviceID == "" {
				return errors.New("this vault has no device id")
			}
			accountID, err := randomHex(16)
			if err != nil {
				return err
			}
			dk, err := newDeviceSecret()
			if err != nil {
				return err
			}
			defer dk.Wipe()
			rk, rkText, err := remote.NewRecoveryKey()
			if err != nil {
				return err
			}
			defer rk.Wipe()
			dev, rec := remote.DeviceFromSecret(dk), remote.RecoveryFromKey(rk)
			entry := merge.Device{Label: deviceLabel(), SignPub: b64(dev.SignPub), BoxPub: b64(dev.BoxPub),
				AddedAt: nowUTC(), AddedBy: "register", LastSync: &merge.LastSync{Version: 1, At: nowUTC()}}

			raw, err := s.v.Body()
			if err != nil {
				return mapErr(err, "")
			}
			mb, err := parseBody(raw)
			clear(raw)
			if err != nil {
				return mapErr(err, "")
			}
			if mb.Devices == nil {
				mb.Devices = map[string]merge.Device{}
			}
			mb.Devices[deviceID] = entry
			plain := canon(mb)
			defer clear(plain)

			keys := remote.Subkeys(s.key)
			vaultObj, err := remote.SealObject(keys.Vault, remote.ObjectAAD{AccountID: accountID, Generation: 1, Version: 1, Writer: deviceID, CreatedAt: nowUTC()}, plain)
			if err != nil {
				return err
			}
			keyEnv, err := remote.SealKeyEnvelope(dev, dev.BoxPub, remote.EnvelopeAAD{AccountID: accountID, DeviceID: deviceID, Generation: 1, Issuer: deviceID}, s.key)
			if err != nil {
				return err
			}
			recEnv, err := remote.SealRecovery(rec.Wrap, accountID, 1, s.key)
			if err != nil {
				return err
			}
			if err := c.CreateAccount(ctx, remote.NewAccount{Invite: invite, AccountID: accountID, DeviceID: deviceID, Device: dev,
				Recovery: rec, RecoveryEnvelope: recEnv, KeyEnvelope: keyEnv, Vault: vaultObj}); err != nil {
				return remoteErr(err, "the invite code is invalid or already used")
			}

			// The account exists: keep what the device needs before showing
			// the recovery key, so a cancel there loses nothing.
			if err := s.v.SaveDeviceSecret(dk); err != nil {
				return mapErr(err, "")
			}
			if err := s.v.SaveBase(plain); err != nil {
				return mapErr(err, "")
			}
			if err := s.v.EditRoster(func(r map[string]merge.Device) { r[deviceID] = entry }); err != nil {
				return mapErr(err, "")
			}
			st := &vault.Remote{Server: server, CAFile: caFile, AccountID: accountID, Generation: 1, LastVersion: 1, LastPullAt: nowUTC(), RecoveryUnconfirmed: true}
			if err := vault.WriteRemote(s.home, st); err != nil {
				return mapErr(err, "")
			}
			g.auditRemote(cmd, "registered")

			if err := confirmRecoveryKey(ask, show, rkText); err != nil {
				return err
			}
			st.RecoveryUnconfirmed = false
			if err := vault.WriteRemote(s.home, st); err != nil {
				return mapErr(err, "")
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), accountBody{OK: true, Registered: true, Server: server, Account: short(accountID)})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "registered with %s (account %s)\n", host, short(accountID))
			return err
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "server URL (https://, or http:// to localhost)")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "trust this CA certificate file for TLS")
	return cmd
}

// clientErr maps NewClient failures; a bad CA file is a usage error.
func clientErr(err error) error {
	if errors.Is(err, remote.ErrInsecureURL) {
		return remoteErr(err, "")
	}
	return usageError{"cannot use the CA file"}
}

// confirmRecoveryKey shows the recovery key and asks for its last four
// characters; a wrong answer shows it again (§ 4.1 step 5).
func confirmRecoveryKey(ask prompt.Backend, show prompt.Shower, rkText string) error {
	want := codeText(rkText)
	want = want[len(want)-4:]
	for range maxKeyChecks {
		if err := show.Show("Recovery key", "Write this recovery key down and keep it offline. It is the only way to open your vault on a new machine if you lose access to every device.\n\n"+rkText+"\n"); err != nil {
			return userFail(err)
		}
		got, err := askText(ask, prompt.SecretRequest{Name: nameLastFour, Reason: "Check that you saved the recovery key", Host: "cli"})
		if err != nil {
			return err
		}
		if sameCode(got, want) {
			return nil
		}
	}
	return errCancelled
}

// ---- join (§ 4.2-4.4) ----

func newRemoteJoin(g *globals) *cobra.Command {
	var server, caFile string
	var viaRecovery bool
	cmd := &cobra.Command{
		Use:   "join --server URL [--recovery]",
		Short: "Add this machine to a synced vault",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if server == "" {
				return usageError{"give the server with --server URL"}
			}
			c, err := remote.NewClient(server, caFile)
			if err != nil {
				return clientErr(err)
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			if st, err := vault.ReadRemote(s.home); err != nil {
				return mapErr(err, "")
			} else if st != nil {
				return usageError{"this vault already syncs; run 'gentle-vault remote logout' first"}
			}
			ask, _, err := g.userBackend(false)
			if err != nil {
				return err
			}
			if g.remoteOff() {
				return errRemoteOff
			}
			ctx, cancel := netCtx(cmd, 60*time.Second)
			defer cancel()
			if _, err := c.Info(ctx); err != nil {
				return remoteErr(err, "")
			}
			all, err := s.v.ListAll()
			if err != nil {
				return mapErr(err, "")
			}
			host := serverHost(server)
			q := "Join the synced vault on " + host + "?"
			if n := len(all); n > 0 {
				q += fmt.Sprintf(" %d local %s will be added to the synced vault on %s.", n, plural(n, "secret", "secrets"), host)
			}
			if err := askYes(ask, q); err != nil {
				return err
			}
			deviceID, err := vault.ReadDeviceID(s.home)
			if err != nil || deviceID == "" {
				return errors.New("this vault has no device id")
			}
			dk, err := newDeviceSecret()
			if err != nil {
				return err
			}
			defer dk.Wipe()
			j := &joining{g: g, cmd: cmd, s: s, c: c, ask: ask, server: server, caFile: caFile, host: host,
				deviceID: deviceID, dk: dk, dev: remote.DeviceFromSecret(dk)}
			if viaRecovery {
				err = j.byRecovery(ctx)
			} else {
				err = j.byPairing(ctx)
			}
			if err != nil {
				return err
			}
			defer j.mk.Wipe()
			// The wait may have used up the first budget.
			fctx, fcancel := netCtx(cmd, 60*time.Second)
			defer fcancel()
			return j.finish(fctx)
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "server URL (https://, or http:// to localhost)")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "trust this CA certificate file for TLS")
	cmd.Flags().BoolVar(&viaRecovery, "recovery", false, "use the recovery key instead of pairing")
	return cmd
}

// joining carries a join from "I hold the account key" to "synced".
type joining struct {
	g        *globals
	cmd      *cobra.Command
	s        *session
	c        *remote.Client
	ask      prompt.Backend
	server   string
	caFile   string
	host     string
	deviceID string
	dk       secret.Secret
	dev      remote.Device

	mk         secret.Secret
	accountID  string
	generation int
	how        string
	entry      *merge.Device // roster entry this device adds itself (recovery)
}

// dropDevice removes this device from the server, best effort: it was
// registered by an approval that this side then refused.
func (j *joining) dropDevice() {
	ctx, cancel := netCtx(j.cmd, 10*time.Second)
	defer cancel()
	c, err := remote.NewClient(j.server, j.caFile)
	if err != nil {
		return
	}
	if c.Login(ctx, j.deviceID, j.dev) == nil {
		_ = c.DeleteSelf(ctx)
	}
}

func (j *joining) byPairing(ctx context.Context) error {
	p, err := j.c.CreatePairing(ctx, j.deviceID, j.dev)
	if err != nil {
		return remoteErr(err, "")
	}
	j.printPairing(p.Code)
	if pairingHook != nil {
		pairingHook(p.Code)
	}
	res, err := j.wait(p)
	if err != nil {
		return err
	}
	mk, aad, err := remote.OpenKeyEnvelope(j.dev, res.IssuerSignPub, res.Envelope)
	if err != nil || aad.AccountID != res.AccountID || aad.DeviceID != j.deviceID || aad.Issuer != res.Issuer {
		j.dropDevice()
		return errPairingFailed
	}
	eph, err := remote.EnvelopeEphPub(res.Envelope)
	if err != nil {
		mk.Wipe()
		j.dropDevice()
		return errPairingFailed
	}
	want := remote.ConfirmationCode(remote.Subkeys(mk).Pairing, p.Code, j.deviceID, eph)
	typed, err := askText(j.ask, prompt.SecretRequest{Name: nameConfirm, Reason: "Type the confirmation code shown on the device that approved this one", Host: "cli"})
	if err != nil {
		mk.Wipe()
		j.dropDevice()
		return err
	}
	if !sameCode(typed, want) {
		mk.Wipe()
		j.dropDevice()
		return errPairingFailed
	}
	// The approval registered this device: authenticate it before anything
	// local changes, so a refusal leaves the vault as it was.
	lctx, cancel := netCtx(j.cmd, 30*time.Second)
	defer cancel()
	if err := j.c.Login(lctx, j.deviceID, j.dev); err != nil {
		mk.Wipe()
		return remoteErr(err, "this device was refused by the server")
	}
	j.mk, j.accountID, j.generation, j.how = mk, res.AccountID, aad.Generation, "pairing"
	return nil
}

// printPairing shows the pairing code, which is a public-key fingerprint and
// safe on any stream; with --json stdout stays one object, so it goes to
// stderr.
func (j *joining) printPairing(code string) {
	w := j.cmd.OutOrStdout()
	if j.g.JSON {
		w = j.cmd.ErrOrStderr()
	}
	fmt.Fprintf(w, "pairing code: %s\nOn a device that already syncs, run 'gentle-vault remote approve'.\n", code)
}

// wait polls until the pairing is approved, expired or interrupted (§ 4.2).
func (j *joining) wait(p remote.Pairing) (remote.PollResult, error) {
	ctx, stop := signal.NotifyContext(j.cmd.Context(), interruptSignals...)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, pairPollFor)
	defer cancel()
	for {
		res, err := j.c.PollPairing(ctx, p.Code, p.PollSecret)
		switch {
		case ctx.Err() != nil:
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return remote.PollResult{}, errPairingGone
			}
			return remote.PollResult{}, errCancelled
		case errors.Is(err, remote.ErrNotFound), errors.Is(err, remote.ErrAuth):
			return remote.PollResult{}, errPairingGone
		case err != nil:
			return remote.PollResult{}, remoteErr(err, "")
		case res.Status == "approved":
			return res, nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(pairPollEvery):
		}
	}
}

func (j *joining) byRecovery(ctx context.Context) error {
	text, err := askText(j.ask, prompt.SecretRequest{Name: nameRecovery, Reason: "Recover the vault on " + j.host, Host: "cli"})
	if err != nil {
		return err
	}
	const notRecognized = "recovery key not recognized"
	rk, err := remote.ParseRecoveryKey(text)
	if err != nil {
		return codedError{"remote_auth", notRecognized, 1}
	}
	defer rk.Wipe()
	rec := remote.RecoveryFromKey(rk)
	accountID, err := j.c.RecoveryLogin(ctx, rec)
	if errors.Is(err, remote.ErrNotFound) {
		err = remote.ErrAuth
	}
	if err != nil {
		return remoteErr(err, notRecognized)
	}
	_, env, err := j.c.RecoveryEnvelope(ctx)
	if err != nil {
		return remoteErr(err, notRecognized)
	}
	mk, gen, err := remote.OpenRecovery(rec.Wrap, accountID, env)
	if err != nil {
		return codedError{"remote_auth", notRecognized, 1}
	}
	keyEnv, err := remote.SealKeyEnvelope(j.dev, j.dev.BoxPub, remote.EnvelopeAAD{AccountID: accountID, DeviceID: j.deviceID, Generation: gen, Issuer: j.deviceID}, mk)
	if err != nil {
		mk.Wipe()
		return err
	}
	if err := j.c.RegisterByRecovery(ctx, j.deviceID, j.dev, keyEnv); err != nil {
		mk.Wipe()
		return remoteErr(err, notRecognized)
	}
	if err := j.c.Login(ctx, j.deviceID, j.dev); err != nil {
		mk.Wipe()
		return remoteErr(err, "this device was refused by the server")
	}
	j.mk, j.accountID, j.generation, j.how = mk, accountID, gen, "recovery"
	j.entry = &merge.Device{Label: deviceLabel(), SignPub: b64(j.dev.SignPub), BoxPub: b64(j.dev.BoxPub), AddedAt: nowUTC(), AddedBy: "recovery"}
	return nil
}

// finish adopts the account key (§ 4.2 step 8, § 4.4): the local files are
// re-sealed with it and the old key is retired, like rekey, then the first
// round merges the local vault into the account against an empty base.
func (j *joining) finish(ctx context.Context) error {
	home := j.s.home
	id, err := vault.ReadID(home)
	if err != nil {
		return mapErr(err, "")
	}
	opts := keychain.Options{Passphrase: j.g.askPassphrase}
	if err := keychain.Stage(home, id, j.s.key, j.mk, opts); err != nil {
		return promptFail(err, "")
	}
	if err := vault.Rekey(home, j.s.key, j.mk); err != nil {
		if errors.Is(err, vault.ErrRekeyNotStarted) {
			_ = keychain.Unstage(home, id, opts)
		}
		return mapErr(err, "")
	}
	if err := keychain.Promote(home, id, j.mk, opts); err != nil {
		return errNotPromoted
	}
	nv, err := vault.Open(home, j.mk)
	if err != nil {
		return mapErr(err, "")
	}
	if err := nv.SaveDeviceSecret(j.dk); err != nil {
		return mapErr(err, "")
	}
	if j.entry != nil {
		if err := nv.EditRoster(func(r map[string]merge.Device) { r[j.deviceID] = *j.entry }); err != nil {
			return mapErr(err, "")
		}
	}
	st := &vault.Remote{Server: j.server, CAFile: j.caFile, AccountID: j.accountID, Generation: j.generation}
	if err := vault.WriteRemote(home, st); err != nil {
		return mapErr(err, "")
	}
	j.g.auditRemote(j.cmd, "joined ("+j.how+")")
	res, err := j.g.syncRound(ctx, &session{v: nv, key: j.mk, mode: j.s.mode, home: home}, j.c, j.deviceID)
	if err != nil {
		return err
	}
	if j.g.JSON {
		return writeJSON(j.cmd.OutOrStdout(), accountBody{OK: true, Joined: true, Server: j.server, Account: short(j.accountID), Version: res.Version})
	}
	_, err = fmt.Fprintf(j.cmd.OutOrStdout(), "joined %s (account %s, version %d)\n", j.host, short(j.accountID), res.Version)
	return err
}

// ---- approve (§ 4.2 steps 3-6) ----

type approveBody struct {
	OK       bool   `json:"ok"`
	Approved bool   `json:"approved"`
	Device   string `json:"device"`
	Label    string `json:"label"`
}

func newRemoteApprove(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "approve",
		Short: "Approve a new device that is waiting to join",
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
			ask, show, err := g.userBackend(true)
			if err != nil {
				return err
			}
			if g.remoteOff() {
				return errRemoteOff
			}
			host := serverHost(st.Server)
			typed, err := askText(ask, prompt.SecretRequest{Name: namePairing, Reason: "Approve a new device on " + host, Host: "cli"})
			if err != nil {
				return err
			}
			label, err := askText(ask, prompt.SecretRequest{Name: nameLabel, Reason: "Name the new device", Host: "cli", Visible: true})
			if err != nil {
				return err
			}
			label = oneLine(label)
			if label == "" {
				return usageError{"the device label is empty"}
			}
			code := regroup(typed, 4)

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
			keys, err := c.ReadPairing(ctx, code)
			if errors.Is(err, remote.ErrNotFound) || errors.Is(err, remote.ErrInvalid) {
				return errPairingGone
			}
			if err != nil {
				return remoteErr(err, "")
			}
			if remote.PairingCode(keys.SignPub, keys.BoxPub) != code {
				return errPairingFailed // the server tried to substitute its own device key
			}
			// The fingerprint covers the keys, not the id: an id already in
			// the roster (or this device's) would overwrite that entry.
			roster, err := s.v.Roster()
			if err != nil {
				return mapErr(err, "")
			}
			if _, taken := roster[keys.DeviceID]; taken || keys.DeviceID == me.id {
				return errPairingFailed
			}
			if err := askYes(ask, fmt.Sprintf("Add device %s to your vault on %s? It will be able to read every secret.", label, host)); err != nil {
				return err
			}
			if _, err := g.syncRound(ctx, s, c, me.id); err != nil {
				return err
			}
			env, err := remote.SealKeyEnvelope(me.key, keys.BoxPub, remote.EnvelopeAAD{AccountID: st.AccountID, DeviceID: keys.DeviceID, Generation: st.Generation, Issuer: me.id}, s.key)
			if err != nil {
				return err
			}
			if err := c.ApprovePairing(ctx, code, env); err != nil {
				if errors.Is(err, remote.ErrNotFound) || errors.Is(err, remote.ErrInvalid) {
					return errPairingGone
				}
				return remoteErr(err, "")
			}
			entry := merge.Device{Label: label, SignPub: b64(keys.SignPub), BoxPub: b64(keys.BoxPub), AddedAt: nowUTC(), AddedBy: "pairing"}
			if err := s.v.EditRoster(func(r map[string]merge.Device) { r[keys.DeviceID] = entry }); err != nil {
				return mapErr(err, "")
			}
			g.auditRemote(cmd, "approved "+keys.DeviceID)
			if _, err := g.syncRound(ctx, s, c, me.id); err != nil {
				var ce codedError
				if !errors.As(err, &ce) || ce.code != "remote_unreachable" {
					return err
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: not synced (server unreachable); will retry")
			}

			eph, err := remote.EnvelopeEphPub(env)
			if err != nil {
				return err
			}
			conf := remote.ConfirmationCode(remote.Subkeys(s.key).Pairing, code, keys.DeviceID, eph)
			if err := show.Show("Confirmation code", "Type this code on the new device.\n\n"+conf+"\n"); err != nil {
				return userFail(err)
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), approveBody{OK: true, Approved: true, Device: keys.DeviceID, Label: label})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "approved %s (%s)\n", oneLine(label), keys.DeviceID)
			return err
		},
	}
}

// ---- logout (§ 4.6) ----

func newRemoteLogout(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Stop syncing on this device; the local vault and key stay",
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
			ask, _, err := g.userBackend(false)
			if err != nil {
				return err
			}
			host := serverHost(st.Server)
			if err := askYes(ask, "Stop syncing this vault on "+host+"? The local vault and key stay."); err != nil {
				return err
			}
			if !g.remoteOff() {
				g.forgetOnServer(cmd, s, st)
			}
			if err := s.v.ClearRemoteFiles(); err != nil {
				return mapErr(err, "")
			}
			if err := vault.WriteRemote(s.home, nil); err != nil {
				return mapErr(err, "")
			}
			g.auditRemote(cmd, "logged out")
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					OK        bool `json:"ok"`
					LoggedOut bool `json:"logged_out"`
				}{true, true})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "logged out of %s; the local vault and key stay\n", host)
			return err
		},
	}
}

// forgetOnServer deletes this device on the server, best effort: logging
// out works offline too.
func (g *globals) forgetOnServer(cmd *cobra.Command, s *session, st *vault.Remote) {
	d, err := s.device()
	if err != nil {
		return
	}
	defer d.wipe()
	ctx, cancel := netCtx(cmd, 10*time.Second)
	defer cancel()
	if c, err := g.connect(ctx, st, d); err == nil {
		_ = c.DeleteSelf(ctx)
	}
}
