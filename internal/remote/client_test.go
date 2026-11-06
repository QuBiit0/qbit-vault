package remote_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/remote"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/server"
)

var ctx = context.Background()

const acct = "0123456789abcdef0123456789abcdef"

func k(b byte) secret.Secret { return secret.New("k", bytes.Repeat([]byte{b}, 32)) }

// harness runs a real server whose public URL is its own address.
func harness(t *testing.T) (*server.Server, string) {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	s, err := server.New(server.Config{Data: t.TempDir(), PublicURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = s.Handler()
	t.Cleanup(ts.Close)
	return s, ts.URL
}

func object(t *testing.T, mk secret.Secret, gen int, version int64, body string) []byte {
	t.Helper()
	b, err := remote.SealObject(remote.Subkeys(mk).Vault, remote.ObjectAAD{AccountID: acct, Generation: gen, Version: version, Writer: "d1"}, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func registered(t *testing.T) (*server.Server, string, *remote.Client, remote.Device) {
	t.Helper()
	s, url := harness(t)
	c, err := remote.NewClient(url, "")
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := s.Invite(time.Hour)
	d := remote.DeviceFromSecret(k(1))
	rk, _, _ := remote.NewRecoveryKey()
	rec := remote.RecoveryFromKey(rk)
	renv, _ := remote.SealRecovery(rec.Wrap, acct, 1, k(9))
	kenv, _ := remote.SealKeyEnvelope(d, d.BoxPub, remote.EnvelopeAAD{AccountID: acct, DeviceID: "d1", Generation: 1, Issuer: "d1"}, k(9))
	err = c.CreateAccount(ctx, remote.NewAccount{Invite: inv, AccountID: acct, DeviceID: "d1", Device: d,
		Recovery: rec, RecoveryEnvelope: renv, KeyEnvelope: kenv, Vault: object(t, k(9), 1, 1, `{"schema":2}`)})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := c.Login(ctx, "d1", d); err != nil {
		t.Fatalf("login: %v", err)
	}
	return s, url, c, d
}

func TestNewClientRefusesPlainHTTPOffLoopback(t *testing.T) {
	for _, u := range []string{"http://vault.example.com", "ftp://x", "vault.example.com", "https://"} {
		if _, err := remote.NewClient(u, ""); !errors.Is(err, remote.ErrInsecureURL) {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"https://vault.example.com", "http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:9"} {
		if _, err := remote.NewClient(u, ""); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if _, err := remote.NewClient("https://vault.example.com", "/no/such/ca.pem"); err == nil {
		t.Error("a missing CA file was accepted")
	}
}

func TestVaultRoundTripAndConflict(t *testing.T) {
	_, _, c, _ := registered(t)
	v, err := c.GetVault(ctx, 0)
	if err != nil || v.Version != 1 || v.Generation != 1 || v.NotModified {
		t.Fatalf("get: %+v %v", v, err)
	}
	if v, err := c.GetVault(ctx, 1); err != nil || !v.NotModified {
		t.Fatalf("not modified: %+v %v", v, err)
	}
	ver, err := c.PutVault(ctx, 1, object(t, k(9), 1, 2, `{"schema":2,"x":1}`))
	if err != nil || ver != 2 {
		t.Fatalf("put: %d %v", ver, err)
	}
	if _, err := c.PutVault(ctx, 1, object(t, k(9), 1, 2, `{}`)); !errors.Is(err, remote.ErrConflict) {
		t.Fatalf("stale put: %v", err)
	}
	got, _ := c.GetVault(ctx, 0)
	body, aad, err := remote.OpenObject(remote.Subkeys(k(9)).Vault, acct, got.Blob)
	if err != nil || aad.Version != 2 || string(body) != `{"schema":2,"x":1}` {
		t.Fatalf("open what the server returned: %v %q", err, body)
	}
	vs, err := c.Versions(ctx)
	if err != nil || len(vs) != 2 || vs[0].Version != 2 {
		t.Fatalf("versions: %+v %v", vs, err)
	}
}

func TestPairingThroughTheClient(t *testing.T) {
	_, url, c, d1 := registered(t)
	nd := remote.DeviceFromSecret(k(2))
	anon, _ := remote.NewClient(url, "")
	p, err := anon.CreatePairing(ctx, "d2", nd)
	if err != nil || p.Code != remote.PairingCode(nd.SignPub, nd.BoxPub) {
		t.Fatalf("create pairing: %+v %v", p, err)
	}
	keys, err := c.ReadPairing(ctx, p.Code)
	if err != nil || !bytes.Equal(keys.SignPub, nd.SignPub) || keys.DeviceID != "d2" {
		t.Fatalf("read pairing: %+v %v", keys, err)
	}
	env, _ := remote.SealKeyEnvelope(d1, nd.BoxPub, remote.EnvelopeAAD{AccountID: acct, DeviceID: "d2", Generation: 1, Issuer: "d1"}, k(9))
	if err := c.ApprovePairing(ctx, p.Code, env); err != nil {
		t.Fatalf("approve: %v", err)
	}
	r, err := anon.PollPairing(ctx, p.Code, p.PollSecret)
	if err != nil || r.Status != "approved" || r.AccountID != acct || r.Issuer != "d1" || !bytes.Equal(r.IssuerSignPub, d1.SignPub) {
		t.Fatalf("poll: %+v %v", r, err)
	}
	mk, aad, err := remote.OpenKeyEnvelope(nd, r.IssuerSignPub, r.Envelope)
	if err != nil || aad.DeviceID != "d2" || string(mk.Reveal()) != string(k(9).Reveal()) {
		t.Fatalf("open envelope: %v", err)
	}
	nc, _ := remote.NewClient(url, "")
	if err := nc.Login(ctx, "d2", nd); err != nil {
		t.Fatalf("new device login: %v", err)
	}
}

func TestErrorsAreTyped(t *testing.T) {
	_, url, _, _ := registered(t)
	c, _ := remote.NewClient(url, "")
	if err := c.Login(ctx, "nobody", remote.DeviceFromSecret(k(5))); !errors.Is(err, remote.ErrAuth) {
		t.Fatalf("unknown device: %v", err)
	}
	if _, err := c.GetVault(ctx, 0); !errors.Is(err, remote.ErrAuth) {
		t.Fatalf("no token: %v", err)
	}
	dead, _ := remote.NewClient("http://127.0.0.1:1", "")
	if _, err := dead.Info(ctx); !errors.Is(err, remote.ErrUnreachable) {
		t.Fatalf("unreachable: %v", err)
	}
	// Error messages never carry a token or a server body.
	if err := c.Login(ctx, "nobody", remote.DeviceFromSecret(k(5))); strings.Contains(err.Error(), "{") {
		t.Fatalf("error carries a body: %v", err)
	}
}

func TestRecoveryAndAnchorsThroughTheClient(t *testing.T) {
	_, url, c, _ := registered(t)
	// Recovery with a key whose lookup id the server does not know.
	anon, _ := remote.NewClient(url, "")
	rk, _, _ := remote.NewRecoveryKey()
	if _, err := anon.RecoveryLogin(ctx, remote.RecoveryFromKey(rk)); !errors.Is(err, remote.ErrAuth) {
		t.Fatalf("unknown recovery key: %v", err)
	}
	blob, _ := remote.SealAnchor(remote.Subkeys(k(9)).Anchor, acct, 1, remote.Anchor{DeviceID: "d1", Seq: 7, Line: "sha256:x"})
	if err := c.PutAnchor(ctx, blob); err != nil {
		t.Fatal(err)
	}
	as, err := c.Anchors(ctx, "d1")
	if err != nil || len(as) != 1 {
		t.Fatalf("anchors: %v %v", as, err)
	}
	a, err := remote.OpenAnchor(remote.Subkeys(k(9)).Anchor, acct, as[0])
	if err != nil || a.Seq != 7 {
		t.Fatalf("open anchor: %v %+v", err, a)
	}
	var probe map[string]any
	_ = json.Unmarshal(as[0], &probe)
}

// The server is untrusted (AGENTS.md invariant 9): ids it returns end up in
// the roster, the audit log and the terminal, so they must be plain ids.
func TestClientRefusesMalformedIDsFromTheServer(t *testing.T) {
	bad := "d2\x1b[2J\nforged"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/pairings/") && r.URL.Query().Get("poll") != "":
			_ = json.NewEncoder(w).Encode(map[string]any{"api": 1, "status": "approved", "account_id": bad, "issuer": "d1", "envelope": "{}", "issuer_sign_pub": ""})
		case strings.HasPrefix(r.URL.Path, "/v1/pairings/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"api": 1, "device_id": bad, "sign_pub": "", "box_pub": ""})
		case r.URL.Path == "/v1/recovery/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"api": 1, "account_id": bad, "token": "t"})
		case r.URL.Path == "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"api": 1, "devices": []map[string]string{{"id": bad}}})
		}
	}))
	defer srv.Close()
	c, _ := remote.NewClient(srv.URL, "")
	if _, err := c.ReadPairing(ctx, "CODE"); !errors.Is(err, remote.ErrInvalid) {
		t.Errorf("read pairing: %v", err)
	}
	if _, err := c.PollPairing(ctx, "CODE", "s"); !errors.Is(err, remote.ErrInvalid) {
		t.Errorf("poll: %v", err)
	}
	rk, _, _ := remote.NewRecoveryKey()
	if _, err := c.RecoveryLogin(ctx, remote.RecoveryFromKey(rk)); !errors.Is(err, remote.ErrInvalid) {
		t.Errorf("recovery login: %v", err)
	}
	if _, err := c.Devices(ctx); !errors.Is(err, remote.ErrInvalid) {
		t.Errorf("devices: %v", err)
	}
}

// The pairing code shown to the user must be the fingerprint of this
// device's keys, never an id the server picked: a server could otherwise
// show the fingerprint of keys of its own and receive the master key.
func TestCreatePairingRefusesAnIDThatIsNotItsFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"api": 1, "pairing_id": "AAAA-BBBB-CCCC-DDDD", "poll_secret": "s", "expires_at": "x"})
	}))
	defer srv.Close()
	c, _ := remote.NewClient(srv.URL, "")
	if _, err := c.CreatePairing(ctx, "d2", remote.DeviceFromSecret(k(2))); !errors.Is(err, remote.ErrForged) {
		t.Fatalf("substituted pairing id: %v", err)
	}
}

func TestNewClientRefusesCredentialsInTheURL(t *testing.T) {
	if _, err := remote.NewClient("https://user:TESTSECRET_pw@vault.example.com", ""); !errors.Is(err, remote.ErrInsecureURL) {
		t.Fatalf("userinfo accepted: %v", err)
	}
}

// A server that answers device_revoked is told apart from any other 401/403,
// and its text never reaches the error.
func TestClientDistinguishesDeviceRevoked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{"revoked 403", 403, "device_revoked", remote.ErrRevoked},
		{"revoked 401", 401, "device_revoked", remote.ErrRevoked},
		{"unauthorized", 401, "unauthorized", remote.ErrAuth},
		{"forbidden", 403, "forbidden", remote.ErrAuth},
		{"unknown code", 403, "something_else", remote.ErrAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"api":1,"error":{"code":"` + tc.code + `","message":"SERVER-TEXT-TESTSECRET_x"}}`))
			}))
			defer ts.Close()
			c, _ := remote.NewClient(ts.URL, "")
			_, err := c.GetVault(ctx, 0)
			if !errors.Is(err, tc.want) || (tc.want == remote.ErrRevoked && errors.Is(err, remote.ErrAuth)) || strings.Contains(err.Error(), "SERVER-TEXT") {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// C-S10: a redirect is an error, never followed: sealed bodies go only to the
// configured server.
func TestClientNeverFollowsRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound} {
		var hits int
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+r.URL.Path, status)
		}))
		c, err := remote.NewClient(first.URL, "")
		if err != nil {
			t.Fatal(err)
		}
		err = c.ApprovePairing(ctx, "ABCD-EFGH", []byte("TESTSECRET_sealed"))
		if !errors.Is(err, remote.ErrUnreachable) {
			t.Errorf("%d: err = %v, want ErrUnreachable", status, err)
		}
		if hits != 0 {
			t.Errorf("%d: the redirect target received %d requests", status, hits)
		}
		first.Close()
		other.Close()
	}
}
