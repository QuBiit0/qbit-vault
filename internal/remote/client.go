package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// The HTTP client of the sync API (REMOTE_SYNC.md § 5-6). It sends only
// sealed objects, public keys and the auth material the protocol names;
// errors are typed and never carry a response body, a token or a code.

var (
	ErrInsecureURL = errors.New("remote: the server URL must be https:// (http:// only to localhost)")
	ErrUnreachable = errors.New("remote: server unreachable")
	ErrAuth        = errors.New("remote: not authorized")
	// ErrRevoked is the server's device_revoked: this device was removed by
	// a revocation. It is not an ErrAuth.
	ErrRevoked      = errors.New("remote: this device was revoked")
	ErrConflict     = errors.New("remote: a newer version exists")
	ErrNotFound     = errors.New("remote: not found")
	ErrInvalid      = errors.New("remote: request refused as invalid")
	ErrTooLarge     = errors.New("remote: too large")
	ErrRateLimited  = errors.New("remote: rate limited")
	ErrServer       = errors.New("remote: server error")
	ErrIncompatible = errors.New("remote: the server speaks another API version")
	// ErrForged means the server answered with something other than what
	// this device computed itself (a pairing id that is not its fingerprint).
	ErrForged = errors.New("remote: the server's answer does not match this device")
)

// The ids a server returns end up in the roster, the audit log and the
// terminal; the server is untrusted (AGENTS.md invariant 9), so they must
// have the shape the server itself accepts.
var (
	accountRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	deviceRE  = regexp.MustCompile(`^[a-z0-9]{1,64}$`)
)

// transports holds one transport per CA file ("" for the system roots), so
// every client of the process reuses its connections: a transport per
// client leaks idle sockets in a long-lived process (the MCP server).
var (
	transportsMu sync.Mutex
	transports   = map[string]*http.Transport{}
)

func transportFor(caFile string) (*http.Transport, error) {
	transportsMu.Lock()
	defer transportsMu.Unlock()
	if tr, ok := transports[caFile]; ok {
		return tr, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("remote: cannot read the CA file")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("remote: the CA file holds no certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	transports[caFile] = tr
	return tr, nil
}

// Client talks to one server.
type Client struct {
	base   string
	origin string
	http   *http.Client
	token  string
}

// NewClient checks the URL (https, or http to a loopback host) and, when
// caFile is given, trusts that CA for TLS.
func NewClient(server, caFile string) (*Client, error) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil {
		return nil, ErrInsecureURL
	}
	switch u.Scheme {
	case "https":
	case "http":
		if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return nil, ErrInsecureURL
		}
	default:
		return nil, ErrInsecureURL
	}
	tr, err := transportFor(caFile)
	if err != nil {
		return nil, err
	}
	origin := u.Scheme + "://" + u.Host
	return &Client{base: origin, origin: origin, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}}, nil
}

func (c *Client) call(ctx context.Context, method, path string, in any, out any, hdr ...string) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return 0, ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, ErrUnreachable
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if res.StatusCode == http.StatusNotModified {
		return res.StatusCode, nil
	}
	var head struct {
		API   int `json:"api"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &head) != nil || head.API != 1 {
		return res.StatusCode, ErrIncompatible
	}
	// Only the code is read; the server's message is never kept.
	if res.StatusCode >= 400 && head.Error.Code == "device_revoked" {
		return res.StatusCode, ErrRevoked
	}
	switch res.StatusCode {
	case 200:
		if out != nil && json.Unmarshal(raw, out) != nil {
			return res.StatusCode, ErrIncompatible
		}
		return 200, nil
	case 401, 403:
		return res.StatusCode, ErrAuth
	case 409:
		if out != nil {
			_ = json.Unmarshal(raw, out)
		}
		return res.StatusCode, ErrConflict
	case 404:
		return res.StatusCode, ErrNotFound
	case 400:
		return res.StatusCode, ErrInvalid
	case 413:
		return res.StatusCode, ErrTooLarge
	case 429:
		return res.StatusCode, ErrRateLimited
	}
	return res.StatusCode, ErrServer
}

func enc(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func dec(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }

// Info checks the server speaks API 1 and returns its version string.
func (c *Client) Info(ctx context.Context) (string, error) {
	var out struct {
		Version string `json:"version"`
	}
	_, err := c.call(ctx, "GET", "/v1/info", nil, &out)
	return out.Version, err
}

// NewAccount is what registering the first device sends.
type NewAccount struct {
	Invite           string
	AccountID        string
	DeviceID         string
	Device           Device
	Recovery         Recovery
	RecoveryEnvelope []byte
	KeyEnvelope      []byte
	Vault            []byte
}

func recoveryAuth(r Recovery) string {
	raw := r.AuthSecret.Reveal()
	defer clear(raw)
	return enc(raw)
}

// CreateAccount registers an account with its first device.
func (c *Client) CreateAccount(ctx context.Context, a NewAccount) error {
	_, err := c.call(ctx, "POST", "/v1/accounts", map[string]any{
		"invite": a.Invite, "account_id": a.AccountID,
		"device":       map[string]string{"id": a.DeviceID, "sign_pub": enc(a.Device.SignPub), "box_pub": enc(a.Device.BoxPub)},
		"recovery":     map[string]string{"lookup_id": hex.EncodeToString(a.Recovery.LookupID), "auth": recoveryAuth(a.Recovery), "envelope": string(a.RecoveryEnvelope)},
		"key_envelope": string(a.KeyEnvelope), "vault": string(a.Vault),
	}, nil)
	return err
}

// Login authenticates the device and keeps the token for later calls.
func (c *Client) Login(ctx context.Context, deviceID string, d Device) error {
	var ch struct {
		Nonce string `json:"nonce"`
	}
	if _, err := c.call(ctx, "POST", "/v1/auth/challenge", map[string]string{"device_id": deviceID}, &ch); err != nil {
		return err
	}
	sig := ed25519.Sign(d.SignPriv, AuthMessage(c.origin, dec(ch.Nonce)))
	var tok struct {
		Token string `json:"token"`
	}
	if _, err := c.call(ctx, "POST", "/v1/auth/token", map[string]string{"device_id": deviceID, "nonce": ch.Nonce, "sig": enc(sig)}, &tok); err != nil {
		return err
	}
	c.token = tok.Token
	return nil
}

// VaultVersion is one stored version.
type VaultVersion struct {
	Version     int64
	Generation  int
	Blob        []byte
	NotModified bool
}

// GetVault returns the current version, or NotModified when it is have.
func (c *Client) GetVault(ctx context.Context, have int64) (VaultVersion, error) {
	var out struct {
		Version    int64  `json:"version"`
		Generation int    `json:"generation"`
		Blob       string `json:"blob"`
	}
	var hdr []string
	if have > 0 {
		hdr = []string{"If-None-Match", strconv.FormatInt(have, 10)}
	}
	code, err := c.call(ctx, "GET", "/v1/vault", nil, &out, hdr...)
	if err != nil {
		return VaultVersion{}, err
	}
	if code == http.StatusNotModified {
		return VaultVersion{Version: have, NotModified: true}, nil
	}
	return VaultVersion{Version: out.Version, Generation: out.Generation, Blob: []byte(out.Blob)}, nil
}

// GetVersion returns stored version n.
func (c *Client) GetVersion(ctx context.Context, n int64) (VaultVersion, error) {
	var out struct {
		Version    int64  `json:"version"`
		Generation int    `json:"generation"`
		Blob       string `json:"blob"`
	}
	_, err := c.call(ctx, "GET", "/v1/vault?version="+strconv.FormatInt(n, 10), nil, &out)
	return VaultVersion{Version: out.Version, Generation: out.Generation, Blob: []byte(out.Blob)}, err
}

// PutVault stores blob as base+1; ErrConflict when base is stale.
func (c *Client) PutVault(ctx context.Context, base int64, blob []byte) (int64, error) {
	var out struct {
		Version int64 `json:"version"`
	}
	_, err := c.call(ctx, "PUT", "/v1/vault", map[string]any{"base_version": base, "blob": string(blob)}, &out)
	return out.Version, err
}

// VersionInfo describes a stored version.
type VersionInfo struct {
	Version   int64  `json:"version"`
	Writer    string `json:"writer"`
	CreatedAt string `json:"created_at"`
}

// Versions lists the stored versions, newest first.
func (c *Client) Versions(ctx context.Context) ([]VersionInfo, error) {
	var out struct {
		Versions []VersionInfo `json:"versions"`
	}
	_, err := c.call(ctx, "GET", "/v1/vault/versions", nil, &out)
	return out.Versions, err
}

// Pairing is a pairing the new device created.
type Pairing struct{ Code, PollSecret, ExpiresAt string }

// CreatePairing announces a new device (no token needed).
func (c *Client) CreatePairing(ctx context.Context, deviceID string, d Device) (Pairing, error) {
	code := PairingCode(d.SignPub, d.BoxPub)
	var out struct {
		PairingID  string `json:"pairing_id"`
		PollSecret string `json:"poll_secret"`
		ExpiresAt  string `json:"expires_at"`
	}
	_, err := c.call(ctx, "POST", "/v1/pairings", map[string]string{"code": code, "device_id": deviceID, "sign_pub": enc(d.SignPub), "box_pub": enc(d.BoxPub)}, &out)
	// The code the user reads must be this device's own fingerprint: an id
	// the server picked could fingerprint keys of its own (REMOTE_SYNC § 4.2).
	if err == nil && out.PairingID != code {
		return Pairing{}, ErrForged
	}
	return Pairing{Code: out.PairingID, PollSecret: out.PollSecret, ExpiresAt: out.ExpiresAt}, err
}

// PairingKeys are the keys a pairing announces.
type PairingKeys struct {
	DeviceID        string
	SignPub, BoxPub []byte
}

// ReadPairing returns the keys of a pending pairing (approver side). The
// caller must check they fingerprint to the code the user typed.
func (c *Client) ReadPairing(ctx context.Context, code string) (PairingKeys, error) {
	var out struct {
		DeviceID string `json:"device_id"`
		SignPub  string `json:"sign_pub"`
		BoxPub   string `json:"box_pub"`
	}
	_, err := c.call(ctx, "GET", "/v1/pairings/"+url.PathEscape(code), nil, &out)
	if err == nil && !deviceRE.MatchString(out.DeviceID) {
		return PairingKeys{}, ErrInvalid
	}
	return PairingKeys{DeviceID: out.DeviceID, SignPub: dec(out.SignPub), BoxPub: dec(out.BoxPub)}, err
}

// ApprovePairing hands the new device its key envelope.
func (c *Client) ApprovePairing(ctx context.Context, code string, envelope []byte) error {
	_, err := c.call(ctx, "POST", "/v1/pairings/"+url.PathEscape(code)+"/approve", map[string]string{"envelope": string(envelope)}, nil)
	return err
}

// PollResult is what the new device's poll returns.
type PollResult struct {
	Status, AccountID, Issuer string
	IssuerSignPub, Envelope   []byte
}

// PollPairing checks a pairing (new device side).
func (c *Client) PollPairing(ctx context.Context, code, secret string) (PollResult, error) {
	var out struct {
		Status        string `json:"status"`
		AccountID     string `json:"account_id"`
		Envelope      string `json:"envelope"`
		Issuer        string `json:"issuer"`
		IssuerSignPub string `json:"issuer_sign_pub"`
	}
	_, err := c.call(ctx, "GET", "/v1/pairings/"+url.PathEscape(code)+"?poll="+url.QueryEscape(secret), nil, &out)
	if err == nil && out.Status == "approved" && (!accountRE.MatchString(out.AccountID) || !deviceRE.MatchString(out.Issuer)) {
		return PollResult{}, ErrInvalid
	}
	return PollResult{Status: out.Status, AccountID: out.AccountID, Issuer: out.Issuer, IssuerSignPub: dec(out.IssuerSignPub), Envelope: []byte(out.Envelope)}, err
}

// RecoveryLogin gets a recovery token and returns the account id.
func (c *Client) RecoveryLogin(ctx context.Context, r Recovery) (string, error) {
	var out struct {
		AccountID string `json:"account_id"`
		Token     string `json:"token"`
	}
	_, err := c.call(ctx, "POST", "/v1/recovery/token", map[string]string{"lookup_id": hex.EncodeToString(r.LookupID), "auth": recoveryAuth(r)}, &out)
	if err == nil && !accountRE.MatchString(out.AccountID) {
		return "", ErrInvalid
	}
	if err == nil {
		c.token = out.Token
	}
	return out.AccountID, err
}

// RecoveryEnvelope returns the recovery envelope (recovery token).
func (c *Client) RecoveryEnvelope(ctx context.Context) (int, []byte, error) {
	var out struct {
		Generation int    `json:"generation"`
		Envelope   string `json:"envelope"`
	}
	_, err := c.call(ctx, "GET", "/v1/recovery/envelope", nil, &out)
	return out.Generation, []byte(out.Envelope), err
}

// RegisterByRecovery adds this device to the account (recovery token).
func (c *Client) RegisterByRecovery(ctx context.Context, deviceID string, d Device, keyEnvelope []byte) error {
	_, err := c.call(ctx, "POST", "/v1/devices", map[string]any{
		"device": map[string]string{"id": deviceID, "sign_pub": enc(d.SignPub), "box_pub": enc(d.BoxPub)}, "key_envelope": string(keyEnvelope)}, nil)
	return err
}

// KeysSelf returns this device's latest key envelope.
func (c *Client) KeysSelf(ctx context.Context) (int, []byte, error) {
	var out struct {
		Generation int    `json:"generation"`
		Envelope   string `json:"envelope"`
	}
	_, err := c.call(ctx, "GET", "/v1/keys/self", nil, &out)
	return out.Generation, []byte(out.Envelope), err
}

// RekeyRequest is one atomic rekey (§ 4.5).
type RekeyRequest struct {
	Base             int64
	Generation       int
	Blob             []byte
	Envelopes        map[string][]byte
	Recovery         Recovery
	RecoveryEnvelope []byte
	Revoke           []string
}

// Rekey runs a rekey transaction.
func (c *Client) Rekey(ctx context.Context, r RekeyRequest) (int64, error) {
	envs := map[string]string{}
	for id, e := range r.Envelopes {
		envs[id] = string(e)
	}
	if r.Revoke == nil {
		r.Revoke = []string{}
	}
	var out struct {
		Version int64 `json:"version"`
	}
	_, err := c.call(ctx, "POST", "/v1/rekey", map[string]any{"base_version": r.Base, "generation": r.Generation, "blob": string(r.Blob),
		"envelopes": envs, "revoke": r.Revoke,
		"recovery": map[string]string{"lookup_id": hex.EncodeToString(r.Recovery.LookupID), "auth": recoveryAuth(r.Recovery), "envelope": string(r.RecoveryEnvelope)}}, &out)
	return out.Version, err
}

// RotateRecovery replaces the recovery key at the current generation; the
// old one stops working. ErrConflict when the account key changed.
func (c *Client) RotateRecovery(ctx context.Context, generation int, r Recovery, envelope []byte) error {
	_, err := c.call(ctx, "PUT", "/v1/recovery", map[string]any{"generation": generation,
		"lookup_id": hex.EncodeToString(r.LookupID), "auth": recoveryAuth(r), "envelope": string(envelope)}, nil)
	return err
}

// DeviceInfo is a server-side device record (not trusted for keys: the
// encrypted roster is).
type DeviceInfo struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	LastSeen  string `json:"last_seen"`
}

// Devices lists the account's devices.
func (c *Client) Devices(ctx context.Context) ([]DeviceInfo, error) {
	var out struct {
		Devices []DeviceInfo `json:"devices"`
	}
	_, err := c.call(ctx, "GET", "/v1/devices", nil, &out)
	for _, d := range out.Devices {
		if err == nil && !deviceRE.MatchString(d.ID) {
			return nil, ErrInvalid
		}
	}
	return out.Devices, err
}

// DeleteSelf removes this device from the account (logout).
func (c *Client) DeleteSelf(ctx context.Context) error {
	_, err := c.call(ctx, "DELETE", "/v1/devices/self", nil, nil)
	return err
}

// PutAnchor uploads a sealed audit anchor.
func (c *Client) PutAnchor(ctx context.Context, blob []byte) error {
	_, err := c.call(ctx, "PUT", "/v1/anchors", map[string]string{"blob": string(blob)}, nil)
	return err
}

// Anchors returns a device's sealed anchors, oldest first.
func (c *Client) Anchors(ctx context.Context, device string) ([][]byte, error) {
	var out struct {
		Anchors []string `json:"anchors"`
	}
	_, err := c.call(ctx, "GET", "/v1/anchors?device="+url.QueryEscape(device), nil, &out)
	res := make([][]byte, len(out.Anchors))
	for i, a := range out.Anchors {
		res[i] = []byte(a)
	}
	return res, err
}

// Errorf never includes server text; it exists so callers can add context
// with a fixed message while keeping errors.Is working.
func Errorf(base error, what string) error { return fmt.Errorf("%s: %w", what, base) }
