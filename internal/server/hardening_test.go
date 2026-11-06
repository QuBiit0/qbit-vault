package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Server hardening (odd/tasks/launch-polish.md S4): trusted proxy hops, body
// caps, bootstrap invite strength, atomic invites, sweeps.

// fakeClock is the server's injectable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)} }

// newServerCfg is newServer with a clock, a trusted-proxy count and its data dir.
func newServerCfg(t *testing.T, now func() time.Time, trust int) (*Server, *client, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(Config{Data: dir, PublicURL: origin, Now: now, TrustProxy: trust})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, &client{t: t, base: ts.URL}, dir
}

func entries(t *testing.T, dir ...string) []string {
	t.Helper()
	es, err := os.ReadDir(filepath.Join(dir...))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// ---- S4.1 trusted proxy hops ----

func TestClientIPIsTheNthAddressFromTheRight(t *testing.T) {
	cases := []struct {
		name    string
		trust   int
		xff     func(i int) string // the X-Forwarded-For of request i
		limited bool               // all requests share one bucket (the 6th is 429)
	}{
		{"N=1 a forged leftmost entry cannot dodge the limit", 1, func(i int) string { return fmt.Sprintf("10.0.0.%d, 9.9.9.9", i) }, true},
		{"N=2 the client is the second from the right", 2, func(i int) string { return fmt.Sprintf("9.9.9.9, 10.0.0.%d", i) }, true},
		{"N=2 a varying client gets its own bucket", 2, func(i int) string { return fmt.Sprintf("10.0.0.%d, 9.9.9.9", i) }, false},
		{"N=1 a varying last hop gets its own bucket", 1, func(i int) string { return fmt.Sprintf("9.9.9.9, 10.0.0.%d", i) }, false},
		{"N=2 fewer entries than N falls back to the peer", 2, func(i int) string { return fmt.Sprintf("10.0.0.%d", i) }, true},
		{"N=1 a malformed entry falls back to the peer", 1, func(i int) string { return fmt.Sprintf("not-an-ip-%d", i) }, true},
		{"N=1 an empty last entry falls back to the peer", 1, func(i int) string { return fmt.Sprintf("10.0.0.%d,", i) }, true},
		{"unset: the header is ignored", 0, func(i int) string { return fmt.Sprintf("10.0.0.%d", i) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, c, dir := newServerCfg(t, time.Now, tc.trust)
			var last int
			for i := 1; i <= 6; i++ {
				// An invalid body: the limiter runs first, nothing is ever stored.
				code, m := c.do("POST", "/v1/pairings", map[string]any{"code": "x"}, "X-Forwarded-For", tc.xff(i))
				last = code
				if i < 6 && (code != 400 || errCode(m) != "invalid") {
					t.Fatalf("request %d: %d %v", i, code, m)
				}
			}
			if tc.limited && last != 429 {
				t.Fatalf("the 6th request was %d, want 429", last)
			}
			if !tc.limited && last != 400 {
				t.Fatalf("the 6th request was %d, want 400 (its own bucket)", last)
			}
			if got := entries(t, dir, "pairings"); len(got) != 0 {
				t.Fatalf("refused requests stored %v", got)
			}
		})
	}
}

func TestClientIPJoinsRepeatedForwardedForLines(t *testing.T) {
	_, c, _ := newServerCfg(t, time.Now, 2)
	for i := 1; i <= 6; i++ {
		req, _ := http.NewRequest("POST", c.base+"/v1/pairings", strings.NewReader(`{"code":"x"}`))
		req.Header.Add("X-Forwarded-For", "9.9.9.9")
		req.Header.Add("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if i == 6 && res.StatusCode != 429 {
			t.Fatalf("two header lines are one list: the 6th request was %d, want 429", res.StatusCode)
		}
	}
}

func TestTrustProxyIsANumberOfProxies(t *testing.T) {
	for in, want := range map[string]int{"": 0, "0": 0, "1": 1, "2": 2, "10": 10} {
		if n, ok := parseTrustProxy(in); !ok || n != want {
			t.Errorf("%q: n=%d ok=%v, want %d", in, n, ok, want)
		}
	}
	for _, in := range []string{"true", "yes", "-1", "+1", "1.5", " 1", "1 ", "01x", "99999999999999999999"} {
		if _, ok := parseTrustProxy(in); ok {
			t.Errorf("%q was accepted", in)
		}
		dir := t.TempDir()
		var out, errb bytes.Buffer
		e := env(map[string]string{"QBV_SERVER_DATA": dir, "QBV_SERVER_PUBLIC_URL": origin, "QBV_SERVER_TRUST_PROXY": in})
		if code := Main(context.Background(), []string{"serve"}, e, &out, &errb); code != 2 ||
			errb.String() != "error: QBV_SERVER_TRUST_PROXY must be a number of proxies (0, 1, 2...)\n" || out.Len() != 0 {
			t.Errorf("%q: code=%d out=%q err=%q", in, code, out.String(), errb.String())
		}
		if got := entries(t, dir); len(got) != 0 {
			t.Errorf("%q: a refused start stored %v", in, got)
		}
	}
}

// ---- S4.2 body caps ----

func TestSmallRoutesCapTheBodyAt64KiB(t *testing.T) {
	s, c, dir := newServerCfg(t, time.Now, 0)
	d := newDev("d1")
	register(t, s, c, d)
	login(t, c, d)
	big := strings.Repeat("a", 65<<10)

	// Unauthenticated routes: refused before anything is decoded or stored.
	for _, route := range [][2]string{{"POST", "/v1/auth/challenge"}, {"POST", "/v1/auth/token"}, {"POST", "/v1/pairings"}, {"POST", "/v1/recovery/token"}} {
		anon := &client{t: t, base: c.base}
		code, m := anon.do(route[0], route[1], map[string]any{"device_id": big})
		if code != 413 || errCode(m) != "too_large" || m["api"] != float64(1) {
			t.Errorf("%s %s: %d %v", route[0], route[1], code, m)
		}
	}
	if got := entries(t, dir, "pairings"); len(got) != 0 {
		t.Fatalf("a refused pairing stored %v", got)
	}
	// Authenticated small route: nothing stored either.
	if code, m := c.do("PUT", "/v1/anchors", map[string]any{"blob": big}); code != 413 || errCode(m) != "too_large" {
		t.Fatalf("anchor: %d %v", code, m)
	}
	if code, m := c.do("GET", "/v1/anchors?device=d1", nil); code != 200 || len(m["anchors"].([]any)) != 0 {
		t.Fatalf("an anchor was stored: %d %v", code, m)
	}
	// Just under the cap still reaches the handler.
	anon := &client{t: t, base: c.base}
	if code, m := anon.do("POST", "/v1/auth/challenge", map[string]any{"device_id": strings.Repeat("a", 60<<10)}); code != 401 || errCode(m) != "unauthorized" {
		t.Fatalf("60 KiB: %d %v", code, m)
	}
}

func TestVaultPutKeepsItsLargeBodyCap(t *testing.T) {
	s, c, dir := newServerCfg(t, time.Now, 0)
	d := newDev("d1")
	register(t, s, c, d)
	login(t, c, d)
	// A 2 MiB sealed vault: far over the small-route cap, well within MaxBlob.
	blob := strings.Replace(object(acct, 1, 2), "Y2lwaGVydGV4dA==", strings.Repeat("A", 2<<20), 1)
	if code, m := c.do("PUT", "/v1/vault", map[string]any{"base_version": 1, "blob": blob}); code != 200 || m["version"] != float64(2) {
		t.Fatalf("large put: %d %v", code, m)
	}
	if got := entries(t, dir, "accounts", acct, "vault"); len(got) != 2 {
		t.Fatalf("versions on disk: %v", got)
	}
	// Past the 9 MiB route cap: 413 and nothing stored.
	huge := strings.Repeat("a", 9<<20)
	if code, m := c.do("PUT", "/v1/vault", map[string]any{"base_version": 2, "blob": huge}); code != 413 || errCode(m) != "too_large" {
		t.Fatalf("huge put: %d %v", code, m)
	}
	if got := entries(t, dir, "accounts", acct, "vault"); len(got) != 2 {
		t.Fatalf("a refused put stored a version: %v", got)
	}
}

func TestAccountCreationKeepsItsLargeBodyCap(t *testing.T) {
	s, c, dir := newServerCfg(t, time.Now, 0)
	d := newDev("d1")
	inv, _ := s.Invite(time.Hour)
	vault := strings.Replace(object(acct, 1, 1), "Y2lwaGVydGV4dA==", strings.Repeat("A", 1<<20), 1)
	code, m := c.do("POST", "/v1/accounts", map[string]any{
		"invite": inv, "account_id": acct,
		"device":   map[string]any{"id": d.id, "sign_pub": b64(d.pub), "box_pub": b64(make([]byte, 32))},
		"recovery": map[string]any{"lookup_id": "aa", "auth": b64([]byte("TESTSECRET_auth")), "envelope": "{}"}, "key_envelope": "{}", "vault": vault})
	if code != 200 || m["account_id"] != acct {
		t.Fatalf("1 MiB vault on register: %d %v", code, m)
	}
	if got := entries(t, dir, "accounts"); len(got) != 1 {
		t.Fatalf("accounts: %v", got)
	}
}

// ---- S4.3 bootstrap invite ----

func TestBootstrapInviteRefusesALowVarietyCode(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{Data: dir, PublicURL: origin})
	if err != nil {
		t.Fatal(err)
	}
	weak := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaa",          // 26 chars, 1 distinct
		"abababababababababababababab",        // 2 distinct
		"abcdefghijkabcdefghijkabcdefghijk",   // 11 distinct
		strings.Repeat("TESTSECRET_", 3)[:24], // 8 distinct
	}
	for _, code := range weak {
		if made, err := s.BootstrapInvite(code, time.Hour); made || err != ErrWeakInvite {
			t.Errorf("%q: made=%v err=%v", code, made, err)
		}
	}
	if got := entries(t, dir, "invites"); len(got) != 0 {
		t.Fatalf("a weak code stored %v", got)
	}
	// 12 distinct characters in 24 is the floor.
	if made, err := s.BootstrapInvite("abcdefghijklabcdefghijkl", time.Hour); !made || err != nil {
		t.Fatalf("12 distinct: made=%v err=%v", made, err)
	}

	var out, errb bytes.Buffer
	dir2 := t.TempDir()
	e := env(map[string]string{"QBV_SERVER_DATA": dir2, "QBV_SERVER_PUBLIC_URL": origin, "QBV_SERVER_BOOTSTRAP_INVITE": "aaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if code := Main(context.Background(), []string{"serve"}, e, &out, &errb); code != 2 ||
		errb.String() != "error: QBV_SERVER_BOOTSTRAP_INVITE must be at least 24 characters with at least 12 different ones\n" || out.Len() != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	if got := entries(t, dir2, "invites"); len(got) != 0 {
		t.Fatalf("a refused start stored %v", got)
	}
}

func TestBootstrapInviteNeverRefreshesItsExpiry(t *testing.T) {
	clk := newClock()
	dir := t.TempDir()
	open := func() *Server {
		s, err := New(Config{Data: dir, PublicURL: origin, Now: clk.Now})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if made, err := open().BootstrapInvite(bootCode, 24*time.Hour); !made || err != nil {
		t.Fatalf("first start: made=%v err=%v", made, err)
	}
	path := filepath.Join(dir, "invites", hash(bootCode))
	first, _ := os.ReadFile(path)

	clk.Advance(10 * time.Hour) // a restart with the same code set
	if made, err := open().BootstrapInvite(bootCode, 24*time.Hour); !made || err != nil {
		t.Fatalf("restart: made=%v err=%v", made, err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(first, again) {
		t.Fatalf("the restart refreshed the expiry: %s -> %s", first, again)
	}

	clk.Advance(15 * time.Hour) // 25 h after the first start: expired for good
	if _, err := open().BootstrapInvite(bootCode, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	// Same data directory, through the HTTP handler.
	srv, err := New(Config{Data: dir, PublicURL: origin, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	c := &client{t: t, base: ts.URL}
	d := newDev("d1")
	code, m := c.do("POST", "/v1/accounts", map[string]any{
		"invite": bootCode, "account_id": acct,
		"device":   map[string]any{"id": d.id, "sign_pub": b64(d.pub), "box_pub": b64(make([]byte, 32))},
		"recovery": map[string]any{"lookup_id": "aa", "auth": b64([]byte("TESTSECRET_auth")), "envelope": "{}"}, "key_envelope": "{}", "vault": object(acct, 1, 1)})
	if code != 401 || errCode(m) != "unauthorized" {
		t.Fatalf("an expired bootstrap code created an account: %d %v", code, m)
	}
	if got := entries(t, dir, "accounts"); len(got) != 0 {
		t.Fatalf("accounts: %v", got)
	}
}

func TestAccountCreationIsRateLimitedPerClientIP(t *testing.T) {
	s, c, dir := newServerCfg(t, time.Now, 1)
	body := map[string]any{"invite": "TESTSECRET_wrong", "account_id": acct}
	for i := 1; i <= 10; i++ {
		if code, m := c.do("POST", "/v1/accounts", body, "X-Forwarded-For", "9.9.9.9"); code != 401 || errCode(m) != "unauthorized" {
			t.Fatalf("attempt %d: %d %v", i, code, m)
		}
	}
	inv, _ := s.Invite(time.Hour)
	d := newDev("d1")
	good := map[string]any{"invite": inv, "account_id": acct,
		"device":   map[string]any{"id": d.id, "sign_pub": b64(d.pub), "box_pub": b64(make([]byte, 32))},
		"recovery": map[string]any{"lookup_id": "aa", "auth": b64([]byte("TESTSECRET_auth")), "envelope": "{}"}, "key_envelope": "{}", "vault": object(acct, 1, 1)}
	if code, m := c.do("POST", "/v1/accounts", good, "X-Forwarded-For", "9.9.9.9"); code != 429 || errCode(m) != "rate_limited" || m["api"] != float64(1) {
		t.Fatalf("11th attempt: %d %v", code, m)
	}
	if got := entries(t, dir, "accounts"); len(got) != 0 {
		t.Fatalf("a limited request created %v", got)
	}
	if got := entries(t, dir, "invites"); len(got) != 1 {
		t.Fatalf("a limited request spent the invite: %v", got)
	}
	// Another client IP has its own budget.
	if code, m := c.do("POST", "/v1/accounts", good, "X-Forwarded-For", "8.8.8.8"); code != 200 {
		t.Fatalf("other IP: %d %v", code, m)
	}
}

// ---- S4.4 atomic invite ----

func TestConcurrentAccountCreationsWithOneInviteMakeOneAccount(t *testing.T) {
	s, c, dir := newServerCfg(t, time.Now, 0)
	inv, _ := s.Invite(time.Hour)
	const n = 8
	codes := make([]int, n)
	errs := make([]string, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := newDev(fmt.Sprintf("d%d", i))
			id := strings.Repeat(fmt.Sprintf("%x", i+1), 32)
			cc := &client{t: t, base: c.base}
			<-start
			code, m := cc.do("POST", "/v1/accounts", map[string]any{
				"invite": inv, "account_id": id,
				"device":       map[string]any{"id": d.id, "sign_pub": b64(d.pub), "box_pub": b64(make([]byte, 32))},
				"recovery":     map[string]any{"lookup_id": fmt.Sprintf("lookup%d", i), "auth": b64([]byte("TESTSECRET_auth")), "envelope": "{}"},
				"key_envelope": "{}", "vault": object(id, 1, 1)})
			codes[i], errs[i] = code, errCode(m)
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for i := range codes {
		switch {
		case codes[i] == 200:
			ok++
		case codes[i] != 401 || errs[i] != "unauthorized":
			t.Errorf("loser %d: %d %s", i, codes[i], errs[i])
		}
	}
	if ok != 1 {
		t.Fatalf("%d accounts created from one invite (codes %v)", ok, codes)
	}
	if got := entries(t, dir, "accounts"); len(got) != 1 {
		t.Fatalf("accounts on disk: %v", got)
	}
	if got := entries(t, dir, "invites"); len(got) != 0 {
		t.Fatalf("the spent invite is still there: %v", got)
	}
}

func TestARefusedAccountCreationKeepsTheInvite(t *testing.T) {
	s, c, dir := newServerCfg(t, time.Now, 0)
	d := newDev("d1")
	register(t, s, c, d) // the account exists
	inv, _ := s.Invite(time.Hour)
	body := map[string]any{"invite": inv, "account_id": acct,
		"device":   map[string]any{"id": "other", "sign_pub": b64(newDev("o").pub), "box_pub": b64(make([]byte, 32))},
		"recovery": map[string]any{"lookup_id": "bb", "auth": b64([]byte("TESTSECRET_auth")), "envelope": "{}"}, "key_envelope": "{}", "vault": object(acct, 1, 1)}
	if code, m := c.do("POST", "/v1/accounts", body); code != 409 || errCode(m) != "conflict" {
		t.Fatalf("duplicate account: %d %v", code, m)
	}
	body["account_id"] = "not-an-account-id"
	if code, m := c.do("POST", "/v1/accounts", body); code != 400 || errCode(m) != "invalid" {
		t.Fatalf("malformed: %d %v", code, m)
	}
	if got := entries(t, dir, "invites"); len(got) != 1 || got[0] != hash(inv) {
		t.Fatalf("refused requests changed the invites: %v", got)
	}
	if got := entries(t, dir, "accounts"); len(got) != 1 {
		t.Fatalf("accounts: %v", got)
	}
}

// ---- S4.5 sweeps and caps ----

func TestExpiredNoncesTokensAndPairingsAreSwept(t *testing.T) {
	clk := newClock()
	s, c, dir := newServerCfg(t, clk.Now, 0)
	d := newDev("d1")
	register(t, s, c, d)
	login(t, c, d) // one token (15 min)
	if code, _ := c.do("POST", "/v1/auth/challenge", map[string]any{"device_id": d.id}); code != 200 {
		t.Fatal("challenge")
	} // one nonce (60 s)
	nd := newDev("d2")
	box := make([]byte, 32)
	box[0] = 7
	if code, m := c.do("POST", "/v1/pairings", pairBody(nd, box)); code != 200 { // one pairing (10 min)
		t.Fatalf("pairing: %d %v", code, m)
	}
	// An abandoned pairing file nobody polls again.
	count := func() (n, t_, p int) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.nonces), len(s.tokens), len(entries(t, dir, "pairings"))
	}
	if n, tk, p := count(); n != 1 || tk != 1 || p != 1 {
		t.Fatalf("before: nonces=%d tokens=%d pairings=%d", n, tk, p)
	}

	clk.Advance(11 * time.Minute) // nonce and pairing expired, token live
	if code, _ := c.do("GET", "/healthz", nil); code != 200 {
		t.Fatal("healthz")
	}
	if n, tk, p := count(); n != 0 || tk != 1 || p != 0 {
		t.Fatalf("after 11 min: nonces=%d tokens=%d pairings=%d, want 0 1 0", n, tk, p)
	}
	if code, _ := c.do("GET", "/v1/vault", nil); code != 200 {
		t.Fatalf("a live token was swept: %d", code)
	}

	clk.Advance(5 * time.Minute) // the token is expired too
	c.do("GET", "/healthz", nil)
	if n, tk, p := count(); n != 0 || tk != 0 || p != 0 {
		t.Fatalf("after 16 min: nonces=%d tokens=%d pairings=%d, want 0 0 0", n, tk, p)
	}
}

// plant writes a pairing file without the fsync of the server's own writes.
func plant(t *testing.T, s *Server, code, expires string) {
	t.Helper()
	p := s.pairingPath(code)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"status":"pending","expires_at":"`+expires+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPendingPairingsAreCapped(t *testing.T) {
	s, c, dir := newServerCfg(t, time.Now, 0)
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	for i := 0; i < maxPairings; i++ {
		plant(t, s, fmt.Sprintf("code-%d", i), exp)
	}
	nd := newDev("d2")
	box := make([]byte, 32)
	box[0] = 7
	if code, m := c.do("POST", "/v1/pairings", pairBody(nd, box)); code != 429 || errCode(m) != "rate_limited" || m["api"] != float64(1) {
		t.Fatalf("pairing past the cap: %d %v", code, m)
	}
	if got := entries(t, dir, "pairings"); len(got) != maxPairings {
		t.Fatalf("a refused pairing stored a file: %d", len(got))
	}
	// Expired pairings do not count: after they lapse a new one is accepted.
	s2, c2, dir2 := newServerCfg(t, time.Now, 0)
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	for i := 0; i < maxPairings; i++ {
		plant(t, s2, fmt.Sprintf("old-%d", i), old)
	}
	if code, m := c2.do("POST", "/v1/pairings", pairBody(nd, box)); code != 200 {
		t.Fatalf("pairing over expired ones: %d %v", code, m)
	}
	if got := entries(t, dir2, "pairings"); len(got) != 1 {
		t.Fatalf("expired pairings were not removed: %d files", len(got))
	}
}

func TestLimiterEvictionKeepsLiveCounters(t *testing.T) {
	l := newLimiter(2, time.Minute)
	l.max = 4
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	l.allow("old-1", now.Add(-2*time.Minute)) // windows already over
	l.allow("old-2", now.Add(-2*time.Minute))
	for i := 0; i < 3; i++ {
		l.allow("attacker", now)
	}
	if l.allow("attacker", now) {
		t.Fatal("over the limit should be refused")
	}
	l.allow("fresh", now.Add(30*time.Second))   // the table is now full
	l.allow("fresh-2", now.Add(31*time.Second)) // evicts the two expired entries, nothing else
	if l.allow("attacker", now.Add(32*time.Second)) {
		t.Fatal("filling the table reset a live counter")
	}
	if !l.allow("fresh-3", now.Add(33*time.Second)) {
		t.Fatal("a new key was refused although expired entries were evictable")
	}
	// A flood of live keys cannot grow the table past its bound.
	for i := 0; i < 50; i++ {
		l.allow(fmt.Sprintf("flood-%d", i), now.Add(40*time.Second))
	}
	l.mu.Lock()
	n := len(l.seen)
	l.mu.Unlock()
	if n > l.max {
		t.Fatalf("limiter holds %d keys, bound is %d", n, l.max)
	}
}

// A table full of live keys never refuses everyone: a new key evicts one
// entry at random and is admitted, so a flood of device ids cannot lock out
// legitimate users (the bound on memory still holds).
func TestLimiterFullOfLiveKeysStillAdmitsANewKey(t *testing.T) {
	l := newLimiter(2, time.Minute)
	l.max = 3
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		l.allow(fmt.Sprintf("flood-%d", i), now)
	}
	if !l.allow("legit", now.Add(time.Second)) {
		t.Fatal("a new key was refused because the table is full of live keys")
	}
	l.mu.Lock()
	n := len(l.seen)
	l.mu.Unlock()
	if n > l.max {
		t.Fatalf("limiter holds %d keys, bound is %d", n, l.max)
	}
}
