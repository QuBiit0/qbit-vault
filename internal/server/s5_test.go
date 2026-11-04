package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/remote"
)

func pairBody(d dev, box []byte) map[string]any {
	return map[string]any{"code": remote.PairingCode(d.pub, box), "device_id": d.id, "sign_pub": b64(d.pub), "box_pub": b64(box)}
}

func TestPairingFlow(t *testing.T) {
	s, c := newServer(t)
	old := newDev("d1")
	register(t, s, c, old)
	login(t, c, old)

	nd := newDev("d2")
	box := make([]byte, 32)
	box[0] = 7
	anon := &client{t: t, base: c.base}
	bad := pairBody(nd, box)
	bad["code"] = "AAAA-AAAA-AAAA-AAAA"
	if code, m := anon.do("POST", "/v1/pairings", bad); code != 400 || errCode(m) != "invalid" {
		t.Fatalf("code that does not fingerprint the keys: %d %v", code, m)
	}
	code, m := anon.do("POST", "/v1/pairings", pairBody(nd, box))
	if code != 200 || m["poll_secret"] == nil {
		t.Fatalf("create pairing: %d %v", code, m)
	}
	pcode, secret := m["pairing_id"].(string), m["poll_secret"].(string)
	if code, m := anon.do("GET", "/v1/pairings/"+pcode+"?poll="+secret, nil); code != 200 || m["status"] != "pending" {
		t.Fatalf("poll pending: %d %v", code, m)
	}
	if code, _ := anon.do("GET", "/v1/pairings/"+pcode+"?poll=wrong", nil); code != 401 {
		t.Fatalf("poll with a wrong secret: %d", code)
	}
	if code, _ := anon.do("GET", "/v1/pairings/"+pcode, nil); code != 401 {
		t.Fatalf("reading a pairing needs a device token: %d", code)
	}
	code, m = c.do("GET", "/v1/pairings/"+pcode, nil)
	if code != 200 || m["sign_pub"] != b64(nd.pub) || m["device_id"] != "d2" {
		t.Fatalf("approver reads: %d %v", code, m)
	}
	if code, m := c.do("POST", "/v1/pairings/"+pcode+"/approve", map[string]any{"envelope": `{"env":"for d2"}`}); code != 200 {
		t.Fatalf("approve: %d %v", code, m)
	}
	code, m = anon.do("GET", "/v1/pairings/"+pcode+"?poll="+secret, nil)
	if code != 200 || m["status"] != "approved" || m["account_id"] != acct || m["envelope"] != `{"env":"for d2"}` || m["issuer"] != "d1" || m["issuer_sign_pub"] != b64(old.pub) {
		t.Fatalf("poll approved: %d %v", code, m)
	}
	if code, _ := anon.do("GET", "/v1/pairings/"+pcode+"?poll="+secret, nil); code != 404 {
		t.Fatalf("a pairing answers once: %d", code)
	}
	// The new device can now log in.
	nc := &client{t: t, base: c.base}
	login(t, nc, nd)
	if code, m := nc.do("GET", "/v1/keys/self", nil); code != 200 || m["envelope"] != `{"env":"for d2"}` || m["generation"] != float64(1) {
		t.Fatalf("keys/self: %d %v", code, m)
	}
}

func TestRecoveryFlow(t *testing.T) {
	s, c := newServer(t)
	register(t, s, c, newDev("d1"))
	anon := &client{t: t, base: c.base}
	if code, _ := anon.do("POST", "/v1/recovery/token", map[string]any{"lookup_id": "aa", "auth": b64([]byte("wrong"))}); code != 401 {
		t.Fatalf("wrong auth: %d", code)
	}
	code, m := anon.do("POST", "/v1/recovery/token", map[string]any{"lookup_id": "aa", "auth": b64([]byte("TESTSECRET_auth_secret_32_bytes!"))})
	if code != 200 || m["account_id"] != acct {
		t.Fatalf("recovery token: %d %v", code, m)
	}
	rc := &client{t: t, base: c.base, tok: m["token"].(string)}
	if code, _ := rc.do("GET", "/v1/vault", nil); code != 401 {
		t.Fatalf("a recovery token read the vault: %d", code)
	}
	if code, m := rc.do("GET", "/v1/recovery/envelope", nil); code != 200 || m["envelope"] != "{}" || m["generation"] != float64(1) {
		t.Fatalf("recovery envelope: %d %v", code, m)
	}
	nd := newDev("d3")
	if code, m := rc.do("POST", "/v1/devices", map[string]any{"device": map[string]any{"id": nd.id, "sign_pub": b64(nd.pub), "box_pub": b64(make([]byte, 32))}, "key_envelope": "{}"}); code != 200 {
		t.Fatalf("register by recovery: %d %v", code, m)
	}
	if code, _ := rc.do("POST", "/v1/devices", map[string]any{"device": map[string]any{"id": "d4", "sign_pub": b64(nd.pub), "box_pub": b64(make([]byte, 32))}, "key_envelope": "{}"}); code != 401 {
		t.Fatalf("a recovery token registered two devices: %d", code)
	}
	login(t, &client{t: t, base: c.base}, nd)
	limited := false
	for i := 0; i < 10; i++ {
		if code, _ := anon.do("POST", "/v1/recovery/token", map[string]any{"lookup_id": "aa", "auth": b64([]byte("guess"))}); code == 429 {
			limited = true
		}
	}
	if !limited {
		t.Fatal("recovery is not rate limited")
	}
}

func TestRekeyRevokesAtomically(t *testing.T) {
	s, c := newServer(t)
	d1, d2 := newDev("d1"), newDev("d2")
	register(t, s, c, d1)
	login(t, c, d1)
	// Add d2 by recovery to have two devices.
	anon := &client{t: t, base: c.base}
	_, m := anon.do("POST", "/v1/recovery/token", map[string]any{"lookup_id": "aa", "auth": b64([]byte("TESTSECRET_auth_secret_32_bytes!"))})
	rc := &client{t: t, base: c.base, tok: m["token"].(string)}
	rc.do("POST", "/v1/devices", map[string]any{"device": map[string]any{"id": d2.id, "sign_pub": b64(d2.pub), "box_pub": b64(make([]byte, 32))}, "key_envelope": "{}"})
	c2 := &client{t: t, base: c.base}
	login(t, c2, d2)

	rekey := func(base int64, gen int, envs map[string]string, revoke []string) (int, map[string]any) {
		return c.do("POST", "/v1/rekey", map[string]any{"base_version": base, "generation": gen, "blob": object(acct, gen, base+1),
			"envelopes": envs, "recovery": map[string]any{"lookup_id": "bb", "auth": b64([]byte("new-auth")), "envelope": `{"r":2}`}, "revoke": revoke})
	}
	if code, _ := rekey(0, 2, map[string]string{"d1": "e1"}, []string{"d2"}); code != 409 {
		t.Fatalf("stale base: %d", code)
	}
	if code, m := rekey(1, 3, map[string]string{"d1": "e1"}, []string{"d2"}); code != 400 {
		t.Fatalf("generation skip: %d %v", code, m)
	}
	if code, m := rekey(1, 2, map[string]string{}, []string{"d2"}); code != 400 {
		t.Fatalf("missing envelope for a remaining device: %d %v", code, m)
	}
	if code, m := rekey(1, 2, map[string]string{"d1": "e1"}, []string{"d1"}); code != 400 {
		t.Fatalf("revoking oneself: %d %v", code, m)
	}
	if code, m := rekey(1, 2, map[string]string{"d1": "e1-gen2"}, []string{"d2"}); code != 200 || m["version"] != float64(2) {
		t.Fatalf("rekey: %d %v", code, m)
	}
	if code, m := c2.do("GET", "/v1/vault", nil); code != 401 {
		t.Fatalf("a revoked device kept its token: %d %v", code, m)
	}
	if code, _ := c2.do("POST", "/v1/auth/challenge", map[string]any{"device_id": "d2"}); code != 401 {
		t.Fatalf("a revoked device can log in: %d", code)
	}
	if code, m := c.do("GET", "/v1/keys/self", nil); code != 200 || m["envelope"] != "e1-gen2" || m["generation"] != float64(2) {
		t.Fatalf("keys/self after rekey: %d %v", code, m)
	}
	if code, _ := anon.do("POST", "/v1/recovery/token", map[string]any{"lookup_id": "aa", "auth": b64([]byte("TESTSECRET_auth_secret_32_bytes!"))}); code != 401 {
		t.Fatalf("the old recovery key still works: %d", code)
	}
	if code, _ := anon.do("POST", "/v1/recovery/token", map[string]any{"lookup_id": "bb", "auth": b64([]byte("new-auth"))}); code != 200 {
		t.Fatalf("the new recovery key does not work: %d", code)
	}
	if code, m := c.do("PUT", "/v1/vault", map[string]any{"base_version": 2, "blob": object(acct, 1, 3)}); code != 400 {
		t.Fatalf("a version under the old generation was accepted: %d %v", code, m)
	}
}

func TestAnchors(t *testing.T) {
	s, c := newServer(t)
	d := newDev("d1")
	register(t, s, c, d)
	login(t, c, d)
	for i := 0; i < 105; i++ {
		if code, _ := c.do("PUT", "/v1/anchors", map[string]any{"blob": fmt.Sprintf(`{"n":%d}`, i)}); code != 200 {
			t.Fatalf("put anchor %d: %d", i, code)
		}
	}
	code, m := c.do("GET", "/v1/anchors?device=d1", nil)
	as := m["anchors"].([]any)
	if code != 200 || len(as) != 100 || as[len(as)-1] != `{"n":104}` || as[0] != `{"n":5}` {
		t.Fatalf("anchors: %d len=%d", code, len(as))
	}
	if code, _ := c.do("GET", "/v1/anchors?device=stranger", nil); code != 404 {
		t.Fatalf("another account's device: %d", code)
	}
	if code, _ := c.do("PUT", "/v1/anchors", map[string]any{"blob": strings.Repeat("a", 5000)}); code != 413 {
		t.Fatalf("oversized anchor: %d", code)
	}
}
