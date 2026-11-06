package grants

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

const (
	sessA = "pi:TESTSECRET_session_a1"
	sessB = "pi:TESTSECRET_session_b2"
)

func rootOf(parts ...string) string {
	return filepath.Join(append([]string{string(filepath.Separator) + "work"}, parts...)...)
}

func projLayer(parts ...string) string { return ProjectLayer(rootOf(parts...)) }

const testRec = "rec-1"

// chk is Check for the record every fixture grant was made for.
func chk(s *Store, name, layer, session, cwd string, now time.Time) (Decision, bool) {
	return Check(s, name, layer, testRec, false, session, cwd, now)
}

func mustAdd(t *testing.T, s *Store, req Request, at time.Time) Grant {
	t.Helper()
	if req.RecordID == "" {
		req.RecordID = testRec
	}
	g, err := Add(s, req, at)
	if err != nil {
		t.Fatalf("Add(%+v): %v", req, err)
	}
	return g
}

func sessionReq(name, layer, session string) Request {
	return Request{Name: name, Layer: layer, Session: session, Scope: ScopeSession}
}

func allowed(s *Store, name, layer, session, cwd string, at time.Time) bool {
	d, _ := chk(s, name, layer, session, cwd, at)
	return d.Allowed
}

func TestParseScope(t *testing.T) {
	for in, want := range map[string]Scope{"once": ScopeOnce, "session": ScopeSession, "project": ScopeProject} {
		if got, ok := ParseScope(in); !ok || got != want {
			t.Fatalf("ParseScope(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "forever", "SESSION", "global"} {
		if _, ok := ParseScope(in); ok {
			t.Fatalf("ParseScope(%q) accepted", in)
		}
	}
}

func TestLayerHelpers(t *testing.T) {
	if r, ok := ProjectRootOf(ProjectLayer("/a/b")); !ok || r != "/a/b" {
		t.Fatalf("ProjectRootOf = %q, %v", r, ok)
	}
	if _, ok := ProjectRootOf(GlobalLayer); ok {
		t.Fatal("global has no root")
	}
	if _, ok := ProjectRootOf("project:"); ok {
		t.Fatal("empty root accepted")
	}
}

func TestAddScopeRules(t *testing.T) {
	proj := projLayer("shop")
	tests := []struct {
		name    string
		req     Request
		wantErr error
	}{
		{"once", Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}, nil},
		{"session", sessionReq("A_KEY", GlobalLayer, sessA), nil},
		{"project", Request{Name: "A_KEY", Layer: proj, Scope: ScopeProject}, nil},
		{"sensitive once", Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce, Sensitive: true}, nil},
		{"sensitive session", Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeSession, Sensitive: true}, ErrScopeNotAllowed},
		{"sensitive project", Request{Name: "A_KEY", Layer: proj, Scope: ScopeProject, Sensitive: true}, ErrScopeNotAllowed},
		{"project scope on a global record", Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject}, ErrScopeNotAllowed},
		{"once without session", Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeOnce}, ErrInvalidRequest},
		{"session without session", Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeSession}, ErrInvalidRequest},
		{"unknown scope", Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: "forever"}, ErrInvalidRequest},
		{"empty name", Request{Layer: GlobalLayer, Session: sessA, Scope: ScopeSession}, ErrInvalidRequest},
		{"bad layer", Request{Name: "A_KEY", Layer: "elsewhere", Session: sessA, Scope: ScopeSession}, ErrInvalidRequest},
		{"empty project root", Request{Name: "A_KEY", Layer: "project:", Scope: ScopeProject}, ErrInvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Store{}
			tt.req.RecordID = testRec
			_, err := Add(s, tt.req, t0)
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil) != (err == nil) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil && len(s.Grants) != 0 {
				t.Fatal("a refused request changed the store")
			}
			if err := Validate(tt.req); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddFieldsPerScope(t *testing.T) {
	s := &Store{}
	proj := projLayer("shop")
	once := mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}, t0)
	if once.ExpiresAt == nil || !once.ExpiresAt.Equal(t0.Add(10*time.Minute)) || once.Session != sessA || once.ProjectRoot != "" || once.Consumed {
		t.Fatalf("once = %+v", once)
	}
	sess := mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	if sess.ExpiresAt == nil || !sess.ExpiresAt.Equal(t0.Add(12*time.Hour)) {
		t.Fatalf("session default ttl: %+v", sess)
	}
	p := mustAdd(t, s, Request{Name: "A_KEY", Layer: proj, Session: sessA, Scope: ScopeProject, PromptTokenHash: "sha256:abc"}, t0)
	if p.ExpiresAt != nil || p.Session != "" || p.ProjectRoot != rootOf("shop") || p.PromptTokenHash != "sha256:abc" {
		t.Fatalf("project = %+v", p)
	}
	if !strings.HasPrefix(p.ID, "g_") || p.ID == sess.ID || !p.CreatedAt.Equal(t0) {
		t.Fatalf("id/created: %+v", p)
	}
}

func TestSessionTTLBounds(t *testing.T) {
	tests := []struct {
		ttl     time.Duration
		wantErr bool
		want    time.Duration
	}{
		{0, false, 12 * time.Hour},
		{time.Minute, false, time.Minute},
		{45 * time.Minute, false, 45 * time.Minute},
		{24 * time.Hour, false, 24 * time.Hour},
		{time.Minute - time.Nanosecond, true, 0},
		{24*time.Hour + time.Nanosecond, true, 0},
		{-time.Minute, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.ttl.String(), func(t *testing.T) {
			s := &Store{}
			req := sessionReq("A_KEY", GlobalLayer, sessA)
			req.RecordID = testRec
			req.TTL = tt.ttl
			g, err := Add(s, req, t0)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidTTL) || len(s.Grants) != 0 {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || !g.ExpiresAt.Equal(t0.Add(tt.want)) {
				t.Fatalf("expires = %v, err = %v", g.ExpiresAt, err)
			}
		})
	}
	for _, sc := range []Scope{ScopeOnce} {
		req := Request{Name: "A_KEY", Layer: projLayer("shop"), Session: sessA, Scope: sc, TTL: time.Hour}
		req.RecordID = testRec
		if _, err := Add(&Store{}, req, t0); !errors.Is(err, ErrInvalidTTL) {
			t.Fatalf("%s with a ttl: err = %v", sc, err)
		}
	}
}

func TestAddReplacesIdenticalGrant(t *testing.T) {
	s := &Store{}
	first := mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	second := mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0.Add(time.Minute))
	if len(s.Grants) != 1 || s.Grants[0].ID != second.ID || second.ID == first.ID {
		t.Fatalf("grants = %+v", s.Grants)
	}
	if !s.Grants[0].ExpiresAt.Equal(t0.Add(12*time.Hour + time.Minute)) {
		t.Fatal("the new grant must carry the new expiry")
	}
	// Different session, scope or layer are different grants.
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessB), t0)
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}, t0)
	mustAdd(t, s, sessionReq("A_KEY", projLayer("shop"), sessA), t0)
	if len(s.Grants) != 4 {
		t.Fatalf("want 4 grants, got %d", len(s.Grants))
	}
}

func TestAddPurgesExpired(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, sessionReq("OLD_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, sessionReq("NEW_KEY", GlobalLayer, sessA), t0.Add(13*time.Hour))
	if len(s.Grants) != 1 || s.Grants[0].Name != "NEW_KEY" {
		t.Fatalf("grants = %+v", s.Grants)
	}
}

func TestCheckSessionGrant(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	if !allowed(s, "A_KEY", GlobalLayer, sessA, "/anywhere", t0.Add(12*time.Hour-time.Minute)) {
		t.Fatal("active session grant refused")
	}
	// A session grant is not consumed.
	if !allowed(s, "A_KEY", GlobalLayer, sessA, "/anywhere", t0.Add(12*time.Hour-time.Minute)) {
		t.Fatal("session grant was consumed")
	}
	d, _ := chk(s, "A_KEY", GlobalLayer, sessA, "/x", t0.Add(12*time.Hour))
	if d.Allowed || !errors.Is(d.Err, ErrGrantRequired) {
		t.Fatalf("expired grant: %+v", d)
	}
	if len(s.Grants) != 0 {
		t.Fatal("expired grant was not purged")
	}
}

func TestCheckExpiredIsPurgedAndMutated(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	if _, mutated := chk(s, "A_KEY", GlobalLayer, sessA, "", t0.Add(time.Minute)); mutated {
		t.Fatal("a pure allow must not report a mutation")
	}
	if _, mutated := chk(s, "A_KEY", GlobalLayer, sessA, "", t0.Add(13*time.Hour)); !mutated {
		t.Fatal("purging must report a mutation")
	}
}

func TestCheckOnceIsConsumedExactlyOnce(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}, t0)
	d, mutated := chk(s, "A_KEY", GlobalLayer, sessA, "", t0.Add(time.Minute))
	if !d.Allowed || d.Err != nil || !mutated || d.Scope != ScopeOnce {
		t.Fatalf("first use: %+v mutated=%v", d, mutated)
	}
	d, _ = chk(s, "A_KEY", GlobalLayer, sessA, "", t0.Add(2*time.Minute))
	if d.Allowed || !errors.Is(d.Err, ErrGrantRequired) {
		t.Fatalf("second use allowed: %+v", d)
	}
	if got := Active(s, t0.Add(2*time.Minute)); len(got) != 0 {
		t.Fatalf("consumed grant still listed: %+v", got)
	}
}

func TestCheckOnceExpiresUnused(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}, t0)
	if allowed(s, "A_KEY", GlobalLayer, sessA, "", t0.Add(10*time.Minute)) {
		t.Fatal("unused once grant outlived 10 minutes")
	}
}

func TestCheckPrefersNonConsumingGrant(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}, t0)
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	d, _ := chk(s, "A_KEY", GlobalLayer, sessA, "", t0)
	if !d.Allowed || d.Scope != ScopeSession {
		t.Fatalf("decision = %+v", d)
	}
	if len(Active(s, t0)) != 2 {
		t.Fatal("the once grant must not have been spent")
	}
}

func TestSessionIsolation(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, Request{Name: "B_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}, t0)
	// R-GRANT-05: a subagent is another session and never matches its parent.
	for _, other := range []string{sessB, "", sessA + "-sub", "pi:"} {
		if allowed(s, "A_KEY", GlobalLayer, other, "", t0) {
			t.Fatalf("session %q matched a grant of %q", other, sessA)
		}
		if allowed(s, "B_KEY", GlobalLayer, other, "", t0) {
			t.Fatalf("session %q consumed a once grant of %q", other, sessA)
		}
	}
	if !allowed(s, "B_KEY", GlobalLayer, sessA, "", t0) {
		t.Fatal("the once grant must still be there for its own session")
	}
}

func TestProjectGrantScopedToItsRoot(t *testing.T) {
	s := &Store{}
	root := rootOf("shop")
	mustAdd(t, s, Request{Name: "A_KEY", Layer: ProjectLayer(root), Scope: ScopeProject}, t0)
	for name, cwd := range map[string]string{
		"root":            root,
		"nested":          filepath.Join(root, "pkg", "api"),
		"another session": root,
	} {
		if !allowed(s, "A_KEY", ProjectLayer(root), sessB, cwd, t0.Add(1000*time.Hour)) {
			t.Fatalf("%s: project grant refused (no expiry, any session)", name)
		}
	}
	for name, cwd := range map[string]string{
		"sibling":             rootOf("shop-api"),
		"sibling same prefix": root + "-old",
		"parent":              rootOf(),
		"elsewhere":           filepath.Join(string(filepath.Separator)+"other", "shop"),
		"empty cwd":           "",
	} {
		if allowed(s, "A_KEY", ProjectLayer(root), sessA, cwd, t0) {
			t.Fatalf("%s: project grant matched outside its root", name)
		}
	}
	// The grant is for this record only.
	if allowed(s, "A_KEY", ProjectLayer(rootOf("other")), sessA, rootOf("other"), t0) {
		t.Fatal("grant matched another project layer")
	}
}

func TestGlobalAndProjectLayersNeverCross(t *testing.T) {
	root := rootOf("shop")
	s := &Store{}
	mustAdd(t, s, sessionReq("DB_URL", GlobalLayer, sessA), t0)
	if allowed(s, "DB_URL", ProjectLayer(root), sessA, root, t0) {
		t.Fatal("a global grant satisfied a project record (R-GRANT-01)")
	}
	s = &Store{}
	mustAdd(t, s, sessionReq("DB_URL", ProjectLayer(root), sessA), t0)
	mustAdd(t, s, Request{Name: "DB_URL", Layer: ProjectLayer(root), Scope: ScopeProject}, t0)
	if allowed(s, "DB_URL", GlobalLayer, sessA, root, t0) {
		t.Fatal("a project grant satisfied the global record (R-GRANT-01)")
	}
	if allowed(s, "OTHER_KEY", ProjectLayer(root), sessA, root, t0) {
		t.Fatal("a grant matched another name")
	}
}

func TestRevoke(t *testing.T) {
	root := rootOf("shop")
	build := func() *Store {
		s := &Store{}
		mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
		mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessB), t0)
		mustAdd(t, s, sessionReq("A_KEY", ProjectLayer(root), sessA), t0)
		mustAdd(t, s, Request{Name: "A_KEY", Layer: ProjectLayer(root), Scope: ScopeProject}, t0)
		mustAdd(t, s, sessionReq("B_KEY", GlobalLayer, sessA), t0)
		return s
	}
	t.Run("name and layer", func(t *testing.T) {
		s := build()
		if n := RevokeName(s, "A_KEY", GlobalLayer); n != 2 {
			t.Fatalf("revoked %d", n)
		}
		if allowed(s, "A_KEY", GlobalLayer, sessA, "", t0) || !allowed(s, "A_KEY", ProjectLayer(root), sessA, root, t0) || !allowed(s, "B_KEY", GlobalLayer, sessA, "", t0) {
			t.Fatal("revoke touched the wrong grants")
		}
	})
	t.Run("name in every layer", func(t *testing.T) {
		s := build()
		if n := RevokeName(s, "A_KEY", ""); n != 4 {
			t.Fatalf("revoked %d", n)
		}
		if len(s.Grants) != 1 || s.Grants[0].Name != "B_KEY" {
			t.Fatalf("grants = %+v", s.Grants)
		}
	})
	t.Run("session", func(t *testing.T) {
		s := build()
		if n := RevokeSession(s, sessA); n != 3 {
			t.Fatalf("revoked %d", n)
		}
		if allowed(s, "A_KEY", GlobalLayer, sessA, "", t0) {
			t.Fatal("session grant survived")
		}
		if !allowed(s, "A_KEY", GlobalLayer, sessB, "", t0) {
			t.Fatal("another session's grant was revoked")
		}
		if !allowed(s, "A_KEY", ProjectLayer(root), sessA, root, t0) {
			t.Fatal("a project grant is not bound to the session")
		}
		if n := RevokeSession(s, ""); n != 0 {
			t.Fatalf("empty session revoked %d", n)
		}
	})
	t.Run("all", func(t *testing.T) {
		s := build()
		IssueToken(s, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 0, t0)
		if n := RevokeAll(s); n != 5 {
			t.Fatalf("revoked %d", n)
		}
		if len(s.Grants) != 0 || len(s.Tokens) != 0 {
			t.Fatalf("store = %+v", s)
		}
	})
	t.Run("nothing to revoke", func(t *testing.T) {
		s := build()
		if n := RevokeName(s, "NOPE_KEY", ""); n != 0 || len(s.Grants) != 5 {
			t.Fatalf("revoked %d", n)
		}
	})
}

func TestDropRecordAndDropLayer(t *testing.T) {
	oldRoot := rootOf("old")
	s := &Store{}
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, sessionReq("A_KEY", ProjectLayer(oldRoot), sessA), t0)
	mustAdd(t, s, Request{Name: "B_KEY", Layer: ProjectLayer(oldRoot), Scope: ScopeProject}, t0)
	mustAdd(t, s, Request{Name: "C_KEY", Layer: ProjectLayer(rootOf("other")), Scope: ScopeProject}, t0)

	// relink narrows: the old layer's grants go and nothing is carried over.
	if n := DropLayer(s, ProjectLayer(oldRoot)); n != 2 {
		t.Fatalf("dropped %d", n)
	}
	if allowed(s, "B_KEY", ProjectLayer(oldRoot), "", oldRoot, t0) {
		t.Fatal("old layer still allowed")
	}
	if !allowed(s, "C_KEY", ProjectLayer(rootOf("other")), "", rootOf("other"), t0) || !allowed(s, "A_KEY", GlobalLayer, sessA, "", t0) {
		t.Fatal("DropLayer touched unrelated grants")
	}
	if n := DropLayer(s, ProjectLayer(oldRoot)); n != 0 {
		t.Fatalf("second drop removed %d", n)
	}
	if n := DropLayer(s, GlobalLayer); n != 1 {
		t.Fatalf("global layer drop removed %d", n)
	}

	s = &Store{}
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, sessionReq("A_KEY", ProjectLayer(oldRoot), sessA), t0)
	if n := DropRecord(s, "A_KEY", ProjectLayer(oldRoot)); n != 1 {
		t.Fatalf("dropped %d", n)
	}
	if !allowed(s, "A_KEY", GlobalLayer, sessA, "", t0) {
		t.Fatal("DropRecord removed the other layer's grant")
	}
	if n := DropRecord(s, "A_KEY", ProjectLayer(oldRoot)); n != 0 {
		t.Fatalf("dropped %d twice", n)
	}
}

func TestDropNonOnceKeepsOnlyOnce(t *testing.T) {
	root := rootOf("shop")
	s := &Store{}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}, t0)
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessB), t0)
	mustAdd(t, s, Request{Name: "A_KEY", Layer: ProjectLayer(root), Scope: ScopeProject}, t0)
	mustAdd(t, s, sessionReq("B_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeSession, RecordID: "other"}, t0)
	if n := DropNonOnce(s, "A_KEY", GlobalLayer, testRec); n != 2 {
		t.Fatalf("dropped %d", n)
	}
	got := Active(s, t0)
	if len(got) != 4 {
		t.Fatalf("left %d: %+v", len(got), got)
	}
	if n := DropNonOnce(s, "A_KEY", GlobalLayer, testRec); n != 0 {
		t.Fatalf("again dropped %d", n)
	}
}

// Defensive: even if a broad grant exists for a record that is sensitive,
// only a once grant may allow it.
func TestSensitiveRecordOnlyMatchesOnce(t *testing.T) {
	root := rootOf("shop")
	s := &Store{}
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, Request{Name: "A_KEY", Layer: ProjectLayer(root), Scope: ScopeProject}, t0)
	if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, true, sessA, "", t0); d.Allowed || !errors.Is(d.Err, ErrGrantRequired) {
		t.Fatalf("session grant allowed a sensitive record: %+v", d)
	}
	if d, _ := Check(s, "A_KEY", ProjectLayer(root), testRec, true, sessA, root, t0); d.Allowed {
		t.Fatalf("project grant allowed a sensitive record: %+v", d)
	}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}, t0)
	if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, true, sessA, "", t0); !d.Allowed || d.Scope != ScopeOnce {
		t.Fatalf("once grant refused for a sensitive record: %+v", d)
	}
	if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, true, sessA, "", t0); d.Allowed {
		t.Fatal("the once grant was not consumed")
	}
	// A non-sensitive record is unaffected.
	if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, false, sessA, "", t0); !d.Allowed {
		t.Fatalf("session grant refused for a plain record: %+v", d)
	}
}

func TestNeedsProjectIsAScopeRefusal(t *testing.T) {
	_, err := Add(&Store{}, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject, RecordID: testRec}, t0)
	if !errors.Is(err, ErrNeedsProject) || !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasSuffix(err.Error(), "project scope needs a repository: run it inside one") {
		t.Fatalf("message = %q", err.Error())
	}
	_, err = Add(&Store{}, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeSession, Sensitive: true, RecordID: testRec}, t0)
	if errors.Is(err, ErrNeedsProject) || !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("sensitive err = %v", err)
	}
}

func TestActiveIsSortedAndPurged(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, sessionReq("B_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessB), t0)
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, Request{Name: "A_KEY", Layer: projLayer("shop"), Scope: ScopeProject}, t0)
	got := Active(s, t0.Add(time.Minute))
	var names []string
	for _, g := range got {
		names = append(names, g.Name+"|"+g.Layer+"|"+g.Session)
	}
	want := []string{"A_KEY|global|" + sessA, "A_KEY|global|" + sessB, "A_KEY|" + projLayer("shop") + "|", "B_KEY|global|" + sessA}
	if strings.Join(names, ";") != strings.Join(want, ";") {
		t.Fatalf("order:\n got %v\nwant %v", names, want)
	}
	if got := Active(s, t0.Add(13*time.Hour)); len(got) != 1 || got[0].Scope != ScopeProject {
		t.Fatalf("after expiry: %+v", got)
	}
	if got := ForRecord(s, "A_KEY", projLayer("shop"), testRec, t0); len(got) != 1 {
		t.Fatalf("ForRecord = %+v", got)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
	mustAdd(t, s, Request{Name: "A_KEY", Layer: projLayer("shop"), Scope: ScopeProject}, t0)
	IssueToken(s, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 0, t0)
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := Encode(got)
	if string(b) != string(b2) {
		t.Fatalf("round trip differs:\n%s\n%s", b, b2)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m["grants"] == nil || m["tokens"] == nil {
		t.Fatalf("body shape: %s", b)
	}
	// Project grants carry no session and no expiry in the stored form.
	if !strings.Contains(string(b), `"session":""`) || !strings.Contains(string(b), `"expires_at":null`) {
		t.Fatalf("project grant encoding: %s", b)
	}
}

func TestDecodeEmptyAndBad(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte(`{}`)} {
		s, err := Decode(in)
		if err != nil || len(s.Grants) != 0 || len(s.Tokens) != 0 {
			t.Fatalf("Decode(%q) = %+v, %v", in, s, err)
		}
	}
	if _, err := Decode([]byte(`{"grants":`)); err == nil {
		t.Fatal("garbage accepted")
	}
	b, err := Encode(&Store{})
	if err != nil || string(b) != `{"grants":[],"tokens":[],"cooldowns":[]}` {
		t.Fatalf("empty encode = %s, %v", b, err)
	}
}

// A grant is for one record instance: a re-created secret with the same name
// and layer has a new record id and the stale grant is inert.
func TestGrantNeverAuthorizesAnotherRecord(t *testing.T) {
	root := rootOf("shop")
	for _, req := range []Request{
		{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeSession},
		{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce},
		{Name: "A_KEY", Layer: ProjectLayer(root), Scope: ScopeProject},
	} {
		t.Run(string(req.Scope), func(t *testing.T) {
			s := &Store{}
			req.RecordID = "record-A"
			g := mustAdd(t, s, req, t0)
			if g.RecordID != "record-A" {
				t.Fatalf("record id not stored: %+v", g)
			}
			d, _ := Check(s, "A_KEY", req.Layer, "record-B", false, sessA, root, t0)
			if d.Allowed || !errors.Is(d.Err, ErrGrantRequired) {
				t.Fatalf("grant for record A allowed record B: %+v", d)
			}
			if d, _ = Check(s, "A_KEY", req.Layer, "", false, sessA, root, t0); d.Allowed {
				t.Fatal("an empty record id matched")
			}
			if len(ForRecord(s, "A_KEY", req.Layer, "record-B", t0)) != 0 || len(ForRecord(s, "A_KEY", req.Layer, "record-A", t0)) != 1 {
				t.Fatal("ForRecord ignores the record id")
			}
			// The once grant of A was not spent by the failed check for B.
			if d, _ = Check(s, "A_KEY", req.Layer, "record-A", false, sessA, root, t0); !d.Allowed {
				t.Fatalf("record A lost its grant: %+v", d)
			}
		})
	}
	if _, err := Add(&Store{}, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeSession}, t0); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("grant without a record id: %v", err)
	}
	// Two records with one name and layer hold separate grants.
	s := &Store{}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeSession, RecordID: "record-A"}, t0)
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeSession, RecordID: "record-B"}, t0)
	if len(s.Grants) != 2 {
		t.Fatalf("grants = %d, want one per record", len(s.Grants))
	}
}

// D3 (dogfood 1): a once grant taken for an exec that never started goes back.
func TestRestoreReturnsAConsumedOnceGrant(t *testing.T) {
	once := Request{Name: "A_KEY", Layer: GlobalLayer, Session: sessA, Scope: ScopeOnce}
	take := func(s *Store, at time.Time) Decision {
		d, _ := chk(s, "A_KEY", GlobalLayer, sessA, "", at)
		return d
	}

	t.Run("the claim carries the grant and a second check is refused", func(t *testing.T) {
		s := &Store{}
		g := mustAdd(t, s, once, t0)
		d := take(s, t0)
		if !d.Allowed || d.Once == nil || d.Once.ID != g.ID || d.Once.Consumed {
			t.Fatalf("claim: %+v", d)
		}
		if take(s, t0).Allowed {
			t.Fatal("a claimed once grant allowed a second check")
		}
	})
	t.Run("restore makes it usable again, once", func(t *testing.T) {
		s := &Store{}
		mustAdd(t, s, once, t0)
		d := take(s, t0)
		if !Restore(s, *d.Once, t0) {
			t.Fatal("Restore reported nothing to do")
		}
		if !take(s, t0).Allowed || take(s, t0).Allowed {
			t.Fatal("after Restore the grant must allow exactly one more check")
		}
	})
	t.Run("restore brings back a grant a purge already dropped", func(t *testing.T) {
		s := &Store{}
		mustAdd(t, s, once, t0)
		d := take(s, t0)
		Purge(s, t0) // another operation tidied the consumed grant away
		if len(s.Grants) != 0 {
			t.Fatalf("purge kept %d grants", len(s.Grants))
		}
		if !Restore(s, *d.Once, t0) || !take(s, t0).Allowed {
			t.Fatal("the dropped grant did not come back")
		}
	})
	t.Run("an expired grant stays gone", func(t *testing.T) {
		s := &Store{}
		mustAdd(t, s, once, t0)
		d := take(s, t0)
		if Restore(s, *d.Once, t0.Add(OnceTTL+time.Second)) {
			t.Fatal("restored an expired grant")
		}
		if take(s, t0.Add(OnceTTL+time.Second)).Allowed {
			t.Fatal("an expired grant allowed a check")
		}
	})
	t.Run("a newer identical grant is not duplicated", func(t *testing.T) {
		s := &Store{}
		mustAdd(t, s, once, t0)
		d := take(s, t0)
		mustAdd(t, s, once, t0.Add(time.Minute)) // the user granted again meanwhile
		Restore(s, *d.Once, t0.Add(time.Minute))
		if n := len(Active(s, t0.Add(time.Minute))); n != 1 {
			t.Fatalf("%d live grants, want 1", n)
		}
	})
	t.Run("only once grants are restored", func(t *testing.T) {
		s := &Store{}
		g := mustAdd(t, s, sessionReq("A_KEY", GlobalLayer, sessA), t0)
		if d := take(s, t0); !d.Allowed || d.Once != nil {
			t.Fatalf("a session grant must not be offered for restore: %+v", d)
		}
		if Restore(s, g, t0) {
			t.Fatal("restored a session grant")
		}
	})
}

// The default session lifetime is 12h, inside the 1m to 24h bounds.
func TestDefaultSessionTTLIs12Hours(t *testing.T) {
	if DefaultSessionTTL != 12*time.Hour {
		t.Fatalf("DefaultSessionTTL = %v", DefaultSessionTTL)
	}
	if MinTTL != time.Minute || MaxTTL != 24*time.Hour {
		t.Fatalf("bounds = %v..%v", MinTTL, MaxTTL)
	}
}

// A project grant on a global secret is bound to the repository it was
// approved in: it survives new agent sessions there, never reaches another
// repository (a nested one included), and two repositories keep their own.
func TestProjectGrantOnAGlobalSecretIsBoundToItsRepository(t *testing.T) {
	const shop, blog = "/work/shop", "/work/blog"
	s := &Store{}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject, RecordID: testRec, ProjectRoot: shop}, t0)
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject, RecordID: testRec, ProjectRoot: blog}, t0)
	if len(s.Grants) != 2 {
		t.Fatalf("grants of two repositories replaced each other: %+v", s.Grants)
	}
	for _, sess := range []string{sessA, "mcp:another-session", ""} {
		if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, false, sess, shop, t0.Add(48*time.Hour)); !d.Allowed || d.Scope != ScopeProject {
			t.Fatalf("session %q in the repository: %+v", sess, d)
		}
	}
	for _, cwd := range []string{"/work/shop/vendor/lib", "/work/other", "/work/shop-old", ""} {
		if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, false, sessA, cwd, t0); d.Allowed {
			t.Fatalf("cwd %q was allowed by a grant bound to another repository: %+v", cwd, d)
		}
	}
	if d, _ := Check(s, "A_KEY", GlobalLayer, "other-record", false, sessA, shop, t0); d.Allowed {
		t.Fatal("a replaced value kept the grant")
	}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject, RecordID: testRec, ProjectRoot: shop}, t0)
	if len(s.Grants) != 2 {
		t.Fatalf("re-granting the same repository added a duplicate: %d grants", len(s.Grants))
	}
	if _, err := Add(&Store{}, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject, RecordID: testRec, ProjectRoot: shop, Sensitive: true}, t0); !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("sensitive: err = %v", err)
	}
}

// A project grant can expire: "12 hours in this project" survives new agent
// sessions in the repository like any project grant, then ends.
func TestProjectGrantWithATTLExpires(t *testing.T) {
	const shop = "/work/shop"
	s := &Store{}
	g := mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject, RecordID: testRec, ProjectRoot: shop, TTL: 12 * time.Hour}, t0)
	if g.ExpiresAt == nil || !g.ExpiresAt.Equal(t0.Add(12*time.Hour)) || g.Session != "" {
		t.Fatalf("grant = %+v", g)
	}
	if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, false, "mcp:new-session", shop, t0.Add(11*time.Hour)); !d.Allowed {
		t.Fatalf("within 12h: %+v", d)
	}
	if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, false, "mcp:new-session", shop, t0.Add(12*time.Hour)); d.Allowed {
		t.Fatal("still allowed after 12h")
	}
	if _, err := Add(&Store{}, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject, RecordID: testRec, ProjectRoot: shop, TTL: 48 * time.Hour}, t0); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("ttl over the max: err = %v", err)
	}
}
