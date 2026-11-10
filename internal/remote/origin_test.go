package remote_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/remote"
	"github.com/qbitdevz/qbit-vault/internal/server"
)

func TestNormalizeOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://vault.example.com":             "https://vault.example.com",
		"https://Vault.Example.COM/":            "https://vault.example.com",
		"HTTPS://vault.example.com:443":         "https://vault.example.com",
		"https://vault.example.com:443/":        "https://vault.example.com",
		"https://vault.example.com:8443":        "https://vault.example.com:8443",
		"http://localhost:80":                   "http://localhost",
		"http://LocalHost:8080/":                "http://localhost:8080",
		"https://vault.example.com/some/path?x": "https://vault.example.com",
		"http://[::1]:9":                        "http://[::1]:9",
	} {
		got, err := remote.NormalizeOrigin(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "vault.example.com", "ftp://x", "https://", "https://u:p@x.example"} {
		if _, err := remote.NormalizeOrigin(bad); !errors.Is(err, remote.ErrInsecureURL) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// A server whose configured URL is written differently from the one the
// client uses (case, default port, trailing slash) still authenticates:
// both sides sign the normalized origin.
func TestLoginAcrossEquivalentSpellingsOfTheOrigin(t *testing.T) {
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	t.Cleanup(ts.Close)
	host := strings.TrimPrefix(ts.URL, "http://")
	s, err := server.New(server.Config{Data: t.TempDir(), PublicURL: "HTTP://" + strings.ToUpper(host) + "/"})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = s.Handler()
	c, err := remote.NewClient(ts.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := s.Invite(time.Hour)
	register(t, c, inv)
	if err := c.Login(ctx, "d1", remote.DeviceFromSecret(k(1))); err != nil {
		t.Fatalf("login: %v", err)
	}
	if v, err := c.Info(ctx); err != nil || v != "" && strings.Contains(v, "/") {
		t.Fatalf("info: %q %v", v, err)
	}
}

// A refused login against a server configured for another origin names both
// URLs, and still is an ErrAuth.
func TestLoginRefusedNamesTheConfiguredOrigin(t *testing.T) {
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	t.Cleanup(ts.Close)
	s, err := server.New(server.Config{Data: t.TempDir(), PublicURL: "https://vault.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = s.Handler()
	c, _ := remote.NewClient(ts.URL, "")
	inv, _ := s.Invite(time.Hour)
	register(t, c, inv)
	err = c.Login(ctx, "d1", remote.DeviceFromSecret(k(1)))
	if !errors.Is(err, remote.ErrAuth) {
		t.Fatalf("login: %v", err)
	}
	want := "the server is configured as https://vault.example.test; you used " + ts.URL +
		". Use the same URL (qbit-vault remote logout, then register or join with it)."
	if err.Error() != want {
		t.Fatalf("message %q, want %q", err.Error(), want)
	}
}

// The origin a server reports is text from an untrusted peer: anything that
// is not a plain origin is never echoed, and a login that fails for another
// reason keeps the plain refusal.
func TestLoginRefusalNeverEchoesServerText(t *testing.T) {
	for name, origin := range map[string]string{
		"control characters": "https://evil\x1b[31m.example",
		"with a path":        "https://evil.example/\nrun rm -rf",
		"same origin":        "",
	} {
		t.Run(name, func(t *testing.T) {
			var ts *httptest.Server
			ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/auth/challenge":
					_, _ = w.Write([]byte(`{"api":1,"nonce":"AAAA","expires_in":60}`))
				case "/v1/auth/token":
					w.WriteHeader(401)
					_, _ = w.Write([]byte(`{"api":1,"error":{"code":"unauthorized","message":"nope"}}`))
				case "/v1/info":
					o := origin
					if o == "" {
						o = ts.URL
					}
					_, _ = w.Write([]byte(`{"api":1,"version":"x","origin":` + jsonString(o) + `}`))
				}
			}))
			t.Cleanup(ts.Close)
			c, _ := remote.NewClient(ts.URL, "")
			err := c.Login(ctx, "d1", remote.DeviceFromSecret(k(1)))
			if !errors.Is(err, remote.ErrAuth) || err.Error() != remote.ErrAuth.Error() {
				t.Fatalf("got %q (%v), want the plain refusal", err, errors.Is(err, remote.ErrAuth))
			}
		})
	}
}

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }

// register creates the account of registered() on c with device d1.
func register(t *testing.T, c *remote.Client, invite string) {
	t.Helper()
	d := remote.DeviceFromSecret(k(1))
	rk, _, _ := remote.NewRecoveryKey()
	rec := remote.RecoveryFromKey(rk)
	renv, _ := remote.SealRecovery(rec.Wrap, acct, 1, k(9))
	kenv, _ := remote.SealKeyEnvelope(d, d.BoxPub, remote.EnvelopeAAD{AccountID: acct, DeviceID: "d1", Generation: 1, Issuer: "d1"}, k(9))
	err := c.CreateAccount(ctx, remote.NewAccount{Invite: invite, AccountID: acct, DeviceID: "d1", Device: d,
		Recovery: rec, RecoveryEnvelope: renv, KeyEnvelope: kenv, Vault: object(t, k(9), 1, 1, `{"schema":2}`)})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
}
