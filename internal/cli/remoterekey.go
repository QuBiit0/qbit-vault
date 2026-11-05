package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/remote"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// Master-key rotation and device revocation (docs/REMOTE_SYNC.md § 4.5, § 4.6)
// and the key swap other devices run when a round sees a higher generation
// (§ 7.2 step 2).
//
// Order of a rotation, chosen so that no crash or failure leaves this device
// unable to open its local vault or the server's current version:
//
//  1. Pull, merge and push, so the server holds everything this device has.
//  2. Build MK', RK' and every sealed object in memory. Nothing durable
//     changes except recovery_unconfirmed = true in state.json (a pessimistic
//     flag: if the process dies before RK' is shown, status keeps warning).
//  3. POST /v1/rekey: the only step that changes the account, atomic on the
//     server. Before it, a failure (409, unreachable, refusal) changes nothing
//     here, and the flag is put back.
//  4. Local swap through the staged, resumable path (keychain.Stage,
//     vault.Rekey, keychain.Promote), then device.enc and base.enc.
//  5. Show RK' and ask for its last four characters.
//
// A crash after 3 leaves the server on generation g+1 while this device is on
// g, but the server holds this device's own key envelope for g+1 (issuer =
// this device, step 3), so the next round takes the ordinary path of a device
// that sees a higher generation: GET /v1/keys/self, verify, swap. A crash
// inside 4 is finished by openSession (a staged key) and by the same swap
// (which skips the re-seal when the key already is the new one); the two
// remote files that follow the key are re-sealed from the retired list
// (vault.ResealRemoteFiles). Doing the local swap first would be unsafe: if
// step 3 then failed, this device would hold a key the account never had.

var (
	errRevoked        = codedError{"device_revoked", "this device was revoked; sync is now off here and the local vault is intact", exitcode.Failure}
	errRotateConflict = codedError{"internal", "the server changed while rotating the key; try again", exitcode.Failure}
	errKeyUnverified  = codedError{"remote_auth", "the new account key could not be verified; this device keeps its current key", exitcode.Failure}
	errRotateHalf     = codedError{"internal", "the account key was rotated on the server but this device could not finish; run 'qbit-vault remote sync'", exitcode.Failure}
	errNotInRoster    = codedError{"internal", "a device on the server is missing from the roster; run 'qbit-vault remote sync' and try again", exitcode.Failure}
)

var (
	errRevokeSelf    = usageError{"this device cannot revoke itself; use 'qbit-vault remote logout'"}
	errRevokeUnknown = usageError{"no such device in this vault's roster"}
	errRevokeAlready = usageError{"that device is already revoked"}
)

// crashAt is called at named points of a rotation; only a build with the
// crashseam tag lets a test stop the command there (remotecrash_on.go).

var deviceIDRE = regexp.MustCompile(`^[a-z0-9]{1,64}$`)

// remoteFail maps a client failure; a revoked device also turns sync off.
func (g *globals) remoteFail(err error, auth string) error {
	if errors.Is(err, remote.ErrRevoked) {
		return g.deviceRevoked()
	}
	return remoteErr(err, auth)
}

// deviceRevoked turns sync off on this device (the vault, its key and its
// backups stay) and returns the typed error.
func (g *globals) deviceRevoked() error {
	if err := vault.DisableRemote(g.Home()); err != nil {
		return mapErr(err, "")
	}
	g.record(stderrOf(g), audit.Record{Event: audit.EventRemote, Detail: "device revoked: sync turned off"})
	return errRevoked
}

func sameSecret(a, b secret.Secret) bool {
	x, y := a.Reveal(), b.Reveal()
	defer clear(x)
	defer clear(y)
	return bytes.Equal(x, y)
}

// swapKey moves the local files from the session's key to mk through the
// staged, resumable path and makes mk the session's key. A key that already
// is mk (a swap that died after promoting) only finishes the remote files.
// The caller keeps ownership of mk.
func (g *globals) swapKey(s *session, mk secret.Secret) error {
	if !sameSecret(s.key, mk) {
		id, err := vault.ReadID(s.home)
		if err != nil {
			return mapErr(err, "")
		}
		opts := keychain.Options{Passphrase: g.askPassphrase}
		if err := keychain.Stage(s.home, id, s.key, mk, opts); err != nil {
			return promptFail(err, "")
		}
		if err := vault.Rekey(s.home, s.key, mk); err != nil {
			if errors.Is(err, vault.ErrRekeyNotStarted) {
				_ = keychain.Unstage(s.home, id, opts)
			}
			return mapErr(err, "")
		}
		if err := crashAt("after-rekey"); err != nil {
			return err
		}
		if err := keychain.Promote(s.home, id, mk, opts); err != nil {
			return errNotPromoted
		}
		if err := crashAt("after-promote"); err != nil {
			return err
		}
	}
	// The vault keeps the key it is opened with: give it a copy of its own,
	// so wiping the caller's mk cannot erase it. The copy is wiped on every
	// path that does not hand it to the session.
	raw := mk.Reveal()
	own := secret.New("master", raw)
	clear(raw)
	handed := false
	defer func() {
		if !handed {
			own.Wipe()
		}
	}()
	nv, err := vault.Open(s.home, own)
	if err != nil {
		return mapErr(err, "")
	}
	if err := nv.ResealRemoteFiles(); err != nil {
		return mapErr(err, "")
	}
	s.key.Wipe()
	s.key, s.v, handed = own, nv, true
	return nil
}

// peekGeneration reads the generation a remote object claims in its
// cleartext AAD. It is a hint only: nothing is trusted until the object
// opens with a key.
func peekGeneration(blob []byte) (int, bool) {
	var o struct {
		AAD struct {
			Generation int `json:"generation"`
		} `json:"aad"`
	}
	if json.Unmarshal(blob, &o) != nil || o.AAD.Generation < 1 {
		return 0, false
	}
	return o.AAD.Generation, true
}

// adoptGeneration is the key swap of a device that sees generation gen on the
// server (§ 4.5, § 7.2 step 2). The new key is accepted only from an
// envelope issued by a non-revoked device of this device's own roster, whose
// signature and AAD verify, and only if it opens the server's current vault.
func (g *globals) adoptGeneration(ctx context.Context, s *session, st *vault.Remote, c *remote.Client, vv remote.VaultVersion, gen int) error {
	me, err := s.device()
	if err != nil {
		return err
	}
	defer me.wipe()
	egen, env, err := c.KeysSelf(ctx)
	if err != nil {
		return g.remoteFail(err, "this device was refused by the server")
	}
	if egen != gen {
		return errKeyUnverified
	}
	roster, err := s.v.Roster()
	if err != nil {
		return mapErr(err, "")
	}
	var mk secret.Secret
	found := false
	for id, d := range roster {
		if d.RevokedAt != nil {
			continue
		}
		pub, err := base64.StdEncoding.DecodeString(d.SignPub)
		if err != nil {
			continue
		}
		k, aad, err := remote.OpenKeyEnvelope(me.key, pub, env)
		if err != nil {
			continue
		}
		if aad.Issuer != id || aad.AccountID != st.AccountID || aad.DeviceID != me.id || aad.Generation != gen {
			k.Wipe()
			continue
		}
		mk, found = k, true
		break
	}
	if !found {
		return errKeyUnverified
	}
	defer mk.Wipe()
	body, aad, err := remote.OpenObject(remote.Subkeys(mk).Vault, st.AccountID, vv.Blob)
	if err != nil || aad.Generation != gen || aad.Version != vv.Version {
		return errKeyUnverified
	}
	_, perr := parseBody(body)
	clear(body)
	if perr != nil {
		return errKeyUnverified
	}
	if err := g.swapKey(s, mk); err != nil {
		return err
	}
	st.Generation = gen
	if err := saveRemoteState(s.home, st); err != nil {
		return err
	}
	g.record(stderrOf(g), audit.Record{Event: audit.EventRemote, Detail: fmt.Sprintf("adopted generation %d", gen)})
	return nil
}
