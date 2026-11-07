package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"
)

// Sync friction and small fixes (odd/tasks/launch-polish.md S10).

func TestInfoReportsTheNormalizedOrigin(t *testing.T) {
	s, err := New(Config{Data: t.TempDir(), PublicURL: "HTTPS://Vault.Example.Test:443/"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	c := &client{t: t, base: ts.URL}
	if code, m := c.do("GET", "/v1/info", nil); code != 200 || m["origin"] != origin || m["api"] != float64(1) {
		t.Fatalf("info: %d %v", code, m)
	}
	// Auth binds the normalized spelling, whichever way the operator wrote it.
	d := newDev("d1")
	register(t, s, c, d)
	login(t, c, d)
}

func TestTokenValidatesTheDeviceIDBeforeAnyLookup(t *testing.T) {
	s, c := newServer(t)
	d := newDev("d1")
	register(t, s, c, d)
	code, m := c.do("POST", "/v1/auth/challenge", map[string]any{"device_id": d.id})
	if code != 200 {
		t.Fatalf("challenge: %d %v", code, m)
	}
	nonce := m["nonce"].(string)
	raw, _ := base64.StdEncoding.DecodeString(nonce)
	sig := b64(signAuth(d, raw))
	for _, bad := range []string{"", "../accounts/x", "D1", "d 1", "a\x00b"} {
		code, m := c.do("POST", "/v1/auth/token", map[string]any{"device_id": bad, "nonce": nonce, "sig": sig})
		if code != 401 || errCode(m) != "unauthorized" || m["error"].(map[string]any)["message"] != "unknown device" {
			t.Fatalf("%q: %d %v", bad, code, m)
		}
	}
	// A refused device id does not burn the challenge of the real device.
	if code, m := c.do("POST", "/v1/auth/token", map[string]any{"device_id": d.id, "nonce": nonce, "sig": sig}); code != 200 || m["token"] == nil {
		t.Fatalf("token after refused ids: %d %v", code, m)
	}
}

func TestPairingWithAPendingCodeIsRefused(t *testing.T) {
	clk := newClock()
	s, c, _ := newServerCfg(t, clk.Now, 0)
	old := newDev("d1")
	register(t, s, c, old)
	nd := newDev("d2")
	box := make([]byte, 32)
	box[0] = 7
	anon := &client{t: t, base: c.base}
	code, first := anon.do("POST", "/v1/pairings", pairBody(nd, box))
	if code != 200 {
		t.Fatalf("first pairing: %d %v", code, first)
	}
	secret := first["poll_secret"].(string)
	code, m := anon.do("POST", "/v1/pairings", pairBody(nd, box))
	if code != 409 || errCode(m) != "conflict" || m["poll_secret"] != nil {
		t.Fatalf("second pairing with the same code: %d %v", code, m)
	}
	// The first one is untouched: its poll secret still works.
	pcode := first["pairing_id"].(string)
	if code, m := anon.do("GET", "/v1/pairings/"+pcode+"?poll="+secret, nil); code != 200 || m["status"] != "pending" {
		t.Fatalf("first pairing after the refused one: %d %v", code, m)
	}
	// Once it expired the code can be announced again.
	clk.Advance(pairingTTL + time.Second)
	if code, m := anon.do("POST", "/v1/pairings", pairBody(nd, box)); code != 200 || m["poll_secret"] == nil || m["poll_secret"] == secret {
		t.Fatalf("pairing after expiry: %d %v", code, m)
	}
}

func TestRefusedRekeyLeavesNoVersion(t *testing.T) {
	s, c := newServer(t)
	d1 := newDev("d1")
	register(t, s, c, d1)
	inv, _ := s.Invite(time.Hour)
	other := "fedcba9876543210fedcba9876543210"
	d2 := newDev("d2")
	c2 := &client{t: t, base: c.base}
	if code, m := c2.do("POST", "/v1/accounts", map[string]any{"invite": inv, "account_id": other,
		"device":       map[string]any{"id": d2.id, "sign_pub": b64(d2.pub), "box_pub": b64(make([]byte, 32))},
		"recovery":     map[string]any{"lookup_id": "cc", "auth": b64([]byte("other-auth")), "envelope": "{}"},
		"key_envelope": "{}", "vault": object(other, 1, 1)}); code != 200 {
		t.Fatalf("second account: %d %v", code, m)
	}
	login(t, c2, d2)
	// The recovery lookup id belongs to the first account: refused.
	if code, m := c2.do("POST", "/v1/rekey", map[string]any{"base_version": 1, "generation": 2, "blob": object(other, 2, 2),
		"envelopes": map[string]string{"d2": "e"}, "revoke": []string{},
		"recovery": map[string]any{"lookup_id": "aa", "auth": b64([]byte("x")), "envelope": "{}"}}); code != 409 {
		t.Fatalf("rekey took another account's lookup id: %d %v", code, m)
	}
	vs, err := s.st.versions(other)
	if err != nil || len(vs) != 1 || vs[0] != 1 {
		t.Fatalf("versions after a refused rekey: %v %v", vs, err)
	}
	// The account still works at its old version and generation.
	if code, m := c2.do("GET", "/v1/vault", nil); code != 200 || m["version"] != float64(1) || m["generation"] != float64(1) {
		t.Fatalf("vault after a refused rekey: %d %v", code, m)
	}
}

func signAuth(d dev, nonce []byte) []byte { return ed25519.Sign(d.priv, AuthMessage(origin, nonce)) }
