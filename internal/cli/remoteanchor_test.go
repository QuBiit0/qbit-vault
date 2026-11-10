package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
)

// Audit anchors (REMOTE_SYNC § 8). A round uploads at most one
// sealed anchor every 10 minutes; `audit --verify` checks the log against
// the server's copies.

// anchorClock pins the clock the 10 minute rule reads.
type anchorClock struct{ now atomic.Int64 }

func newAnchorClock(t *testing.T) *anchorClock {
	t.Helper()
	c := &anchorClock{}
	c.now.Store(time.Now().Add(-time.Hour).UnixNano())
	old := anchorNow
	anchorNow = func() time.Time { return time.Unix(0, c.now.Load()).UTC() }
	t.Cleanup(func() { anchorNow = old })
	return c
}

func (c *anchorClock) advance(d time.Duration) { c.now.Add(int64(d)) }

// anchorPuts counts the anchor uploads that reach the server.
func (ss *syncServer) anchorPuts() *atomic.Int64 {
	var n atomic.Int64
	ss.proxy(func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method == "PUT" && r.URL.Path == "/v1/anchors" {
			n.Add(1)
		}
		return false
	})
	return &n
}

func (w *world) anchorStatus() string {
	w.t.Helper()
	var st struct{ Anchor string }
	_, out, _ := w.run("", "--json", "remote", "status")
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		w.t.Fatalf("status = %q", out)
	}
	return st.Anchor
}

// forgeLog replaces the audit log and head with a different, valid chain of
// n records, as a local attacker who rewrites both files would.
func (w *world) forgeLog(n int) {
	w.t.Helper()
	for _, f := range []string{w.auditFile(), w.home + string(os.PathSeparator) + "audit.head"} {
		if err := os.Remove(f); err != nil {
			w.t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		if err := audit.Append(w.home, audit.Record{Event: audit.EventWarning, Session: "forged", Detail: "forged line", By: "user"}); err != nil {
			w.t.Fatal(err)
		}
	}
	if res, err := audit.Verify(w.home); err != nil || !res.Valid {
		w.t.Fatalf("the forged log must verify on its own: %+v %v", res, err)
	}
}

func headSeq(t *testing.T, w *world) int {
	t.Helper()
	seq, _, ok := audit.ReadHead(w.home)
	if !ok {
		t.Fatal("no audit head")
	}
	return int(seq)
}

func TestAnchorIsUploadedAtMostEveryTenMinutes(t *testing.T) {
	clk := newAnchorClock(t)
	ss, _, a, _ := syncPair(t)
	puts := ss.anchorPuts()
	clk.advance(11 * time.Minute) // the rounds of the pairing uploaded one already
	a.mustRun("TESTSECRET_k1", "set", "K1", "--global", "--stdin")
	if puts.Load() != 1 {
		t.Fatalf("first round: %d anchor uploads, want 1", puts.Load())
	}
	want := time.Unix(0, clk.now.Load()).UTC().Format(time.RFC3339)
	if got := a.anchorStatus(); got != want {
		t.Fatalf("status anchor = %q, want %q", got, want)
	}
	clk.advance(9 * time.Minute)
	a.mustRun("TESTSECRET_k2", "set", "K2", "--global", "--stdin")
	a.mustRun("", "remote", "sync")
	if puts.Load() != 1 {
		t.Fatalf("within 10 minutes: %d uploads, want 1", puts.Load())
	}
	clk.advance(2 * time.Minute)
	a.mustRun("TESTSECRET_k3", "set", "K3", "--global", "--stdin")
	if puts.Load() != 2 {
		t.Fatalf("after 11 minutes: %d uploads, want 2", puts.Load())
	}
	// The server holds ciphertext: no fixture, no audit line hash.
	held := ss.held(t)
	noFixtures(t, "server data", held)
	if strings.Contains(held, "sha256:") {
		t.Fatal("an audit hash reached the server in the clear")
	}
	noFixtures(t, "audit", a.auditText())
}

func TestAnchorStatusSaysNoneBeforeTheFirstUpload(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	w.register(ss)
	if got := w.anchorStatus(); got != "none uploaded" {
		t.Fatalf("status anchor = %q", got)
	}
}

func TestAuditVerifyChecksTheServerAnchors(t *testing.T) {
	clk := newAnchorClock(t)
	ss, tp, a, _ := syncPair(t)
	var hide atomic.Bool
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		if !hide.Load() || r.Method != "GET" || r.URL.Path != "/v1/anchors" {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"api":1,"anchors":[]}`)
		return true
	})
	clk.advance(11 * time.Minute)
	a.mustRun("TESTSECRET_v1", "set", "V1", "--global", "--stdin")
	a.mustRun("TESTSECRET_v2", "set", "V2", "--global", "--stdin")
	seq := headSeq(t, a)

	t.Run("matching anchors pass", func(t *testing.T) {
		code, out, errs := a.run("", "audit", "--verify")
		if code != exitcode.OK || errs != "" || !strings.Contains(out, "audit log ok") || !strings.Contains(out, "remote anchor ok (seq ") {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		code, out, _ = a.run("", "--json", "audit", "--verify")
		var got struct {
			Valid  bool
			Anchor string
		}
		if err := json.Unmarshal([]byte(out), &got); code != exitcode.OK || err != nil || !got.Valid || got.Anchor != "ok" {
			t.Fatalf("json code=%d out=%q", code, out)
		}
		noFixtures(t, "verify", out)
	})

	t.Run("offline and the off switch skip it", func(t *testing.T) {
		before := tp.n.Load()
		code, out, _ := a.run("", "audit", "--verify", "--offline")
		if code != exitcode.OK || strings.Contains(out, "remote anchor") || tp.n.Load() != before {
			t.Fatalf("--offline: code=%d out=%q requests=%d", code, out, tp.n.Load()-before)
		}
		code, out, _ = a.runEnv(map[string]string{envNoRemote: "1"}, "", "audit", "--verify")
		if code != exitcode.OK || strings.Contains(out, "remote anchor") || tp.n.Load() != before {
			t.Fatalf("NO_REMOTE: code=%d out=%q requests=%d", code, out, tp.n.Load()-before)
		}
	})

	t.Run("an unreachable server does not fail the verification", func(t *testing.T) {
		tp.down.Store(true)
		defer tp.down.Store(false)
		code, out, errs := a.run("", "audit", "--verify")
		if code != exitcode.OK || !strings.Contains(out, "audit log ok") || !strings.Contains(out, "remote anchor: unavailable") {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		_, jout, _ := a.run("", "--json", "audit", "--verify")
		if !strings.Contains(jout, `"anchor":"unavailable"`) {
			t.Fatalf("json = %q", jout)
		}
	})

	// Anchors this device uploaded and the server no longer returns must not
	// read like a fresh account: that is how a server would hide a rewrite.
	t.Run("anchors gone from the server are reported", func(t *testing.T) {
		hide.Store(true)
		defer hide.Store(false)
		code, out, _ := a.run("", "audit", "--verify")
		if code != exitcode.OK || !strings.Contains(out, "remote anchor: missing (this device uploaded anchors; the server returned none this key opens)") {
			t.Fatalf("code=%d out=%q", code, out)
		}
		if _, jout, _ := a.run("", "--json", "audit", "--verify"); !strings.Contains(jout, `"anchor":"missing"`) {
			t.Fatalf("json = %q", jout)
		}
	})

	t.Run("a rewritten log is an anchor mismatch", func(t *testing.T) {
		a.forgeLog(seq + 3)
		code, out, _ := a.run("", "audit", "--verify")
		if code != exitcode.Failure || !strings.Contains(out, "anchor_mismatch") {
			t.Fatalf("code=%d out=%q", code, out)
		}
		_, jout, _ := a.run("", "--json", "audit", "--verify")
		var got struct {
			Valid   bool
			Problem struct {
				Line   int
				Reason string
			}
		}
		if err := json.Unmarshal([]byte(jout), &got); err != nil || got.Valid || got.Problem.Reason != "anchor_mismatch" || got.Problem.Line < 1 || got.Problem.Line > seq {
			t.Fatalf("json = %q", jout)
		}
		// --offline cannot see it: the forged chain is valid on its own.
		if code, out, _ := a.run("", "audit", "--verify", "--offline"); code != exitcode.OK || !strings.Contains(out, "audit log ok") {
			t.Fatalf("offline: code=%d out=%q", code, out)
		}
	})

	t.Run("a log shorter than the anchors is truncated", func(t *testing.T) {
		a.forgeLog(1)
		code, out, _ := a.run("", "audit", "--verify")
		if code != exitcode.Failure || !strings.Contains(out, "truncated") {
			t.Fatalf("code=%d out=%q", code, out)
		}
	})
}

func TestAuditVerifyWithoutSyncOrAnchorsIsUnchanged(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_p", "set", "P1", "--global", "--stdin")
	out := w.mustRun("", "audit", "--verify")
	if strings.Contains(out, "remote") {
		t.Fatalf("out = %q", out)
	}
	if js := w.mustRun("", "--json", "audit", "--verify"); strings.Contains(js, "anchor") {
		t.Fatalf("json = %q", js)
	}
	// Sync enabled but nothing uploaded yet says so and passes.
	_, _, a, _ := syncPair(t)
	code, out, _ := a.runEnv(map[string]string{envNoRemote: "1"}, "", "audit", "--verify")
	if code != exitcode.OK || strings.Contains(out, "remote anchor") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}
