package cli

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/prompt"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
	"github.com/QuBiit0/gentle-vault/internal/remote"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// The `remote` commands (docs/CLI.md § Remote sync, docs/REMOTE_SYNC.md § 4).
// Every message here is a fixed string: none carries a value, a key, a code
// or a token, and none echoes what the server or the user sent.

const envNoRemote = "GENTLE_VAULT_NO_REMOTE"

// Test seams for the pairing wait of `remote join` (§ 4.2): the poll
// interval, how long to wait, and a hook that runs once the pairing exists,
// before the first poll (a test plays the person approving on the other
// device there).
var (
	pairingHook   func(code string)
	pairPollEvery = 2 * time.Second
	pairPollFor   = 10 * time.Minute
)

// Typed failures of REMOTE_SYNC.md § 11.
var (
	errNotConfigured = codedError{"remote_not_configured", "this vault does not sync; run 'gentle-vault remote register' or 'remote join'", exitcode.Failure}
	errUnreachable   = codedError{"remote_unreachable", "the server is unreachable; try again later", exitcode.Failure}
	errRemoteOff     = codedError{"remote_unreachable", "remote calls are disabled by " + envNoRemote, exitcode.Failure}
	errRemoteAuth    = codedError{"remote_auth", "the server refused the request", exitcode.Failure}
	errIncompatible  = codedError{"server_incompatible", "the server speaks another API version; upgrade gentle-vault or the server", exitcode.Failure}
	errRollback      = codedError{"remote_rollback", "the server offered a version older than one already seen", exitcode.Corrupt}
	errPairingFailed = codedError{"pairing_failed", "the pairing could not be confirmed", exitcode.Failure}
	errPairingGone   = codedError{"pairing_failed", "the pairing was not found or has expired", exitcode.Failure}
	errServerFailed  = codedError{"internal", "the server failed or refused the request", exitcode.Failure}
)

// interruptSignals end the pairing wait.
var interruptSignals = []os.Signal{os.Interrupt}

func newRemote(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Sync the vault between machines through gentle-vault-server",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usageError{"unknown command"}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if g.JSON {
				return usageError{"no command given"}
			}
			return cmd.Help()
		},
	}
	cmd.AddCommand(newRemoteRegister(g), newRemoteJoin(g), newRemoteApprove(g), newRemoteSync(g),
		newRemoteStatus(g), newRemoteDevices(g), newRemoteLogout(g), newRemoteRevokeDevice(g), newRemoteRecoveryKey(g),
		newRemoteConflicts(g), newRemoteResolve(g), newRemoteHistory(g), newRemoteRestore(g))
	return cmd
}

// remoteErr maps a client failure to its typed error. auth is the message
// for a refused credential in this context.
func remoteErr(err error, auth string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, remote.ErrForged):
		return errPairingFailed
	case errors.Is(err, remote.ErrRevoked):
		return errRevoked
	case errors.Is(err, remote.ErrInsecureURL):
		return usageError{"the server URL must be https:// (http:// only to localhost), without credentials"}
	case errors.Is(err, remote.ErrUnreachable):
		return errUnreachable
	case errors.Is(err, remote.ErrRateLimited):
		return codedError{"remote_unreachable", "the server is limiting requests; try again later", exitcode.Failure}
	case errors.Is(err, remote.ErrIncompatible):
		return errIncompatible
	case errors.Is(err, remote.ErrAuth):
		if auth == "" {
			return errRemoteAuth
		}
		return codedError{"remote_auth", auth, exitcode.Failure}
	case errors.Is(err, remote.ErrTooLarge):
		return codedError{"internal", "the vault is too large for this server", exitcode.Failure}
	case errors.Is(err, remote.ErrNotFound), errors.Is(err, remote.ErrInvalid), errors.Is(err, remote.ErrServer), errors.Is(err, remote.ErrConflict):
		return errServerFailed
	}
	return mapErr(err, "")
}

// userFail maps a failed prompt: a backend that cannot ask or show is the
// refusal not_model_callable (these commands are user-only).
func userFail(err error) error {
	if errors.Is(err, prompt.ErrUnavailable) {
		return refusal.New(refusal.NotModelCallable, "")
	}
	return mapErr(err, "")
}

// userBackend returns the prompt backend of a user-only remote command and,
// when needShow, its Shower. With none, the command is not_model_callable.
func (g *globals) userBackend(needShow bool) (prompt.Backend, prompt.Shower, error) {
	ask, err := g.backend()
	if err != nil {
		return nil, nil, refusal.New(refusal.NotModelCallable, "")
	}
	sh, _ := ask.(prompt.Shower)
	if needShow && sh == nil {
		return nil, nil, refusal.New(refusal.NotModelCallable, "")
	}
	return ask, sh, nil
}

// askText reads one answer through the prompt backend and wipes the secret.
func askText(b prompt.Backend, req prompt.SecretRequest) (string, error) {
	s, err := b.Secret(req)
	if err != nil {
		return "", userFail(err)
	}
	defer s.Wipe()
	raw := s.Reveal()
	defer clear(raw)
	return strings.TrimSpace(string(raw)), nil
}

// askYes asks a yes/no question; no or a cancel is errCancelled.
func askYes(b prompt.Backend, q string) error {
	ok, err := b.Confirm(q)
	switch {
	case err != nil:
		return userFail(err)
	case !ok:
		return errCancelled
	}
	return nil
}

func (g *globals) remoteOff() bool { return g.getenv(envNoRemote) == "1" }

func serverHost(server string) string {
	if u, err := url.Parse(server); err == nil && u.Host != "" {
		return u.Host
	}
	return "the server"
}

func netCtx(cmd *cobra.Command, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(cmd.Context(), d)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("random source failed")
	}
	return hex.EncodeToString(b), nil
}

func newDeviceSecret() (secret.Secret, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return secret.Secret{}, errors.New("random source failed")
	}
	defer clear(b)
	return secret.New("device", b), nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// deviceLabel names this machine in the roster until the user renames it.
func deviceLabel() string {
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return oneLine(strings.TrimSpace(h))
	}
	return "this device"
}

// codeText reduces what the user typed (a pairing, confirmation or recovery
// code) to its characters: case, dashes and spaces do not matter, I and L
// read as 1 and O as 0 (Crockford base32).
func codeText(s string) string {
	s = strings.ToUpper(s)
	return strings.NewReplacer("-", "", " ", "", "\t", "", "I", "1", "L", "1", "O", "0").Replace(s)
}

// sameCode compares two codes without leaking where they differ.
func sameCode(a, b string) bool {
	x, y := codeText(a), codeText(b)
	return len(x) == len(y) && subtle.ConstantTimeCompare([]byte(x), []byte(y)) == 1
}

// regroup writes a typed code in the shape the server knows it by.
func regroup(s string, size int) string {
	s = codeText(s)
	var parts []string
	for len(s) > size {
		parts, s = append(parts, s[:size]), s[size:]
	}
	return strings.Join(append(parts, s), "-")
}

// thisDevice is the device secret, keys and id of the vault in s.
type thisDevice struct {
	id  string
	dk  secret.Secret
	key remote.Device
}

func (d thisDevice) wipe() { d.dk.Wipe() }

func (s *session) device() (thisDevice, error) {
	id, err := vault.ReadDeviceID(s.home)
	if err != nil {
		return thisDevice{}, mapErr(err, "")
	}
	if id == "" {
		return thisDevice{}, errors.New("this vault has no device id")
	}
	dk, err := s.v.DeviceSecret()
	if err != nil && s.v.ResealRemoteFiles() == nil {
		// A key swap that died after the vault changed key and before this
		// file did: bring it to the current key and read it again.
		dk, err = s.v.DeviceSecret()
	}
	if err != nil {
		return thisDevice{}, mapErr(err, "")
	}
	return thisDevice{id: id, dk: dk, key: remote.DeviceFromSecret(dk)}, nil
}

// connect opens an authenticated client for the vault's server.
func (g *globals) connect(ctx context.Context, st *vault.Remote, d thisDevice) (*remote.Client, error) {
	if g.remoteOff() {
		return nil, errRemoteOff
	}
	c, err := remote.NewClient(st.Server, st.CAFile)
	if err != nil {
		return nil, remoteErr(err, "")
	}
	if err := c.Login(ctx, d.id, d.key); err != nil {
		return nil, g.remoteFail(err, "this device was refused by the server")
	}
	return c, nil
}

// requireRemote returns the vault's remote state or errNotConfigured.
func requireRemote(s *session) (*vault.Remote, error) { return requireRemoteAt(s.home) }

// requireRemoteAt is requireRemote for a command that holds no session.
func requireRemoteAt(home string) (*vault.Remote, error) {
	st, err := vault.ReadRemote(home)
	if err != nil {
		return nil, mapErr(err, "")
	}
	if st == nil {
		return nil, errNotConfigured
	}
	return st, nil
}
