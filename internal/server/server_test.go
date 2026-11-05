package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const origin = "https://vault.example.test"

type client struct {
	t    *testing.T
	base string
	tok  string
}

func newServer(t *testing.T) (*Server, *client) {
	t.Helper()
	s, err := New(Config{Data: t.TempDir(), PublicURL: origin, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, &client{t: t, base: ts.URL}
}

func (c *client) do(method, path string, body any, hdr ...string) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if c.tok != "" {
		req.Header.Set("Authorization", "Bearer "+c.tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	raw, _ := io.ReadAll(res.Body)
	_ = json.Unmarshal(raw, &m)
	return res.StatusCode, m
}

type dev struct {
	id   string
	priv ed25519.PrivateKey
	pub  []byte
}

func newDev(id string) dev {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return dev{id: id, priv: priv, pub: pub}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// object is a remote vault object as the client seals it: only the
// cleartext AAD matters to the server.
func object(acct string, gen int, version int64) string {
	b, _ := json.Marshal(map[string]any{"format": "qbit-vault-remote/1", "aad": map[string]any{"account_id": acct, "generation": gen, "version": version, "writer": "d1", "created_at": "x"}, "nonce": "AA==", "ct": "Y2lwaGVydGV4dA=="})
	return string(b)
}

const acct = "0123456789abcdef0123456789abcdef"

func register(t *testing.T, s *Server, c *client, d dev) {
	t.Helper()
	inv, err := s.Invite(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	code, m := c.do("POST", "/v1/accounts", map[string]any{
		"invite": inv, "account_id": acct,
		"device":       map[string]any{"id": d.id, "sign_pub": b64(d.pub), "box_pub": b64(make([]byte, 32))},
		"recovery":     map[string]any{"lookup_id": "aa", "auth": b64([]byte("TESTSECRET_auth_secret_32_bytes!")), "envelope": "{}"},
		"key_envelope": "{}",
		"vault":        object(acct, 1, 1),
	})
	if code != 200 || m["account_id"] != acct || m["version"] != float64(1) {
		t.Fatalf("register: %d %v", code, m)
	}
}

func login(t *testing.T, c *client, d dev) {
	t.Helper()
	code, m := c.do("POST", "/v1/auth/challenge", map[string]any{"device_id": d.id})
	if code != 200 {
		t.Fatalf("challenge: %d %v", code, m)
	}
	nonce, _ := base64.StdEncoding.DecodeString(m["nonce"].(string))
	sig := ed25519.Sign(d.priv, AuthMessage(origin, nonce))
	code, m = c.do("POST", "/v1/auth/token", map[string]any{"device_id": d.id, "nonce": m["nonce"], "sig": b64(sig)})
	if code != 200 || m["token"] == nil || m["expires_in"] != float64(900) {
		t.Fatalf("token: %d %v", code, m)
	}
	c.tok = m["token"].(string)
}

func TestInfoAndHealth(t *testing.T) {
	_, c := newServer(t)
	if code, m := c.do("GET", "/v1/info", nil); code != 200 || m["api"] != float64(1) || m["limits"] == nil {
		t.Fatalf("info: %d %v", code, m)
	}
	if code, _ := c.do("GET", "/healthz", nil); code != 200 {
		t.Fatalf("healthz: %d", code)
	}
}

func TestRegisterNeedsAValidSingleUseInvite(t *testing.T) {
	s, c := newServer(t)
	d := newDev("d1")
	body := map[string]any{"invite": "nope", "account_id": acct, "device": map[string]any{"id": d.id, "sign_pub": b64(d.pub), "box_pub": b64(make([]byte, 32))},
		"recovery": map[string]any{"lookup_id": "aa", "auth": b64([]byte("x")), "envelope": "{}"}, "key_envelope": "{}", "vault": object(acct, 1, 1)}
	if code, m := c.do("POST", "/v1/accounts", body); code != 401 || errCode(m) != "unauthorized" {
		t.Fatalf("bad invite: %d %v", code, m)
	}
	register(t, s, c, d)
	inv, _ := s.Invite(time.Hour)
	body["invite"] = inv
	if code, m := c.do("POST", "/v1/accounts", body); code != 409 || errCode(m) != "conflict" {
		t.Fatalf("duplicate account: %d %v", code, m)
	}
	// The invite was not spent by the refused call... but an expired one is refused.
	old, _ := s.Invite(-time.Minute)
	body["invite"], body["account_id"] = old, strings.Repeat("f", 32)
	if code, _ := c.do("POST", "/v1/accounts", body); code != 401 {
		t.Fatalf("expired invite: %d", code)
	}
}

func errCode(m map[string]any) string {
	if e, ok := m["error"].(map[string]any); ok {
		return e["code"].(string)
	}
	return ""
}

func TestAuthRefusesBadSignatureAndRelayedOrigin(t *testing.T) {
	s, c := newServer(t)
	d := newDev("d1")
	register(t, s, c, d)
	_, m := c.do("POST", "/v1/auth/challenge", map[string]any{"device_id": d.id})
	nonce, _ := base64.StdEncoding.DecodeString(m["nonce"].(string))
	other := newDev("x")
	cases := map[string][]byte{
		"wrong key":    ed25519.Sign(other.priv, AuthMessage(origin, nonce)),
		"other origin": ed25519.Sign(d.priv, AuthMessage("https://evil.example", nonce)),
		"garbage":      []byte("x"),
	}
	for name, sig := range cases {
		if code, m := c.do("POST", "/v1/auth/token", map[string]any{"device_id": d.id, "nonce": b64(nonce), "sig": b64(sig)}); code != 401 {
			t.Errorf("%s: %d %v", name, code, m)
		}
	}
	// A nonce is single use.
	sig := ed25519.Sign(d.priv, AuthMessage(origin, nonce))
	if code, _ := c.do("POST", "/v1/auth/token", map[string]any{"device_id": d.id, "nonce": b64(nonce), "sig": b64(sig)}); code != 401 {
		t.Fatalf("a nonce burnt by failures still worked: %d", code)
	}
	if code, _ := c.do("POST", "/v1/auth/challenge", map[string]any{"device_id": "unknown"}); code != 401 {
		t.Fatalf("unknown device: %d", code)
	}
	if code, m := c.do("GET", "/v1/vault", nil); code != 401 || errCode(m) != "unauthorized" {
		t.Fatalf("no token: %d %v", code, m)
	}
}

func TestVaultCompareAndSwapAndVersions(t *testing.T) {
	s, c := newServer(t)
	d := newDev("d1")
	register(t, s, c, d)
	login(t, c, d)
	code, m := c.do("GET", "/v1/vault", nil)
	if code != 200 || m["version"] != float64(1) || m["blob"] != object(acct, 1, 1) {
		t.Fatalf("get: %d %v", code, m)
	}
	if code, _ := c.do("GET", "/v1/vault", nil, "If-None-Match", "1"); code != 304 {
		t.Fatalf("not modified: %d", code)
	}
	if code, m := c.do("PUT", "/v1/vault", map[string]any{"base_version": 1, "blob": object(acct, 1, 2)}); code != 200 || m["version"] != float64(2) {
		t.Fatalf("put: %d %v", code, m)
	}
	if code, m := c.do("PUT", "/v1/vault", map[string]any{"base_version": 1, "blob": object(acct, 1, 2)}); code != 409 || m["version"] != float64(2) {
		t.Fatalf("stale base: %d %v", code, m)
	}
	for name, blob := range map[string]string{
		"version skip":  object(acct, 1, 5),
		"other account": object(strings.Repeat("e", 32), 1, 3),
		"not json":      "nope",
	} {
		if code, m := c.do("PUT", "/v1/vault", map[string]any{"base_version": 2, "blob": blob}); code != 400 || errCode(m) != "invalid" {
			t.Errorf("%s: %d %v", name, code, m)
		}
	}
	for v := int64(3); v <= 13; v++ {
		if code, _ := c.do("PUT", "/v1/vault", map[string]any{"base_version": v - 1, "blob": object(acct, 1, v)}); code != 200 {
			t.Fatalf("put %d: %d", v, code)
		}
	}
	code, m = c.do("GET", "/v1/vault/versions", nil)
	vs := m["versions"].([]any)
	if code != 200 || len(vs) != 10 || vs[0].(map[string]any)["version"] != float64(13) || vs[9].(map[string]any)["version"] != float64(4) {
		t.Fatalf("versions: %d %v", code, m)
	}
	if code, m := c.do("GET", "/v1/vault?version=4", nil); code != 200 || m["blob"] != object(acct, 1, 4) {
		t.Fatalf("old version: %d %v", code, m)
	}
	if code, _ := c.do("GET", "/v1/vault?version=2", nil); code != 404 {
		t.Fatalf("pruned version: %d", code)
	}
	big := strings.Repeat("a", MaxBlob+1)
	if code, m := c.do("PUT", "/v1/vault", map[string]any{"base_version": 13, "blob": big}); code != 413 || errCode(m) != "too_large" {
		t.Fatalf("too large: %d %v", code, m)
	}
}

func TestDevicesAndLogout(t *testing.T) {
	s, c := newServer(t)
	d := newDev("d1")
	register(t, s, c, d)
	login(t, c, d)
	code, m := c.do("GET", "/v1/devices", nil)
	if code != 200 || len(m["devices"].([]any)) != 1 {
		t.Fatalf("devices: %d %v", code, m)
	}
	if code, _ := c.do("DELETE", "/v1/devices/self", nil); code != 200 {
		t.Fatalf("logout: %d", code)
	}
	if code, m := c.do("GET", "/v1/vault", nil); code != 401 {
		t.Fatalf("token after logout: %d %v", code, m)
	}
	if code, _ := c.do("POST", "/v1/auth/challenge", map[string]any{"device_id": d.id}); code != 401 {
		t.Fatalf("deleted device can still log in: %d", code)
	}
}

func TestNothingSecretInStorageOrLogs(t *testing.T) {
	var logs bytes.Buffer
	dir := t.TempDir()
	s, err := New(Config{Data: dir, PublicURL: origin, Now: time.Now, Log: &logs})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	c := &client{t: t, base: ts.URL}
	d := newDev("d1")
	register(t, s, c, d)
	login(t, c, d)
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte("TESTSECRET_")) || bytes.Contains(b, []byte(c.tok)) {
				t.Errorf("%s stores the auth secret or a token", filepath.Base(p))
			}
			if runtime := fi.Mode().Perm(); runtime&0o077 != 0 && os.PathSeparator == '/' {
				t.Errorf("%s mode %v", filepath.Base(p), runtime)
			}
		}
		return nil
	})
	if strings.Contains(logs.String(), c.tok) || strings.Contains(logs.String(), "TESTSECRET_") || !strings.Contains(logs.String(), "/v1/auth/token") {
		t.Fatalf("logs=%q", logs.String())
	}
}

func TestRateLimitOnAuth(t *testing.T) {
	s, c := newServer(t)
	d := newDev("d1")
	register(t, s, c, d)
	limited := false
	for i := 0; i < 40; i++ {
		if code, _ := c.do("POST", "/v1/auth/challenge", map[string]any{"device_id": d.id}); code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("auth is not rate limited")
	}
}
