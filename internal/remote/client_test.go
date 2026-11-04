package remote_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/remote"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/server"
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
