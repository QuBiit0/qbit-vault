package grants

import (
	"reflect"
	"testing"
	"time"
)

// Lookup (what secret_list shows) and Check (what exec enforces) share one
// predicate: for every store and caller, Lookup finds a grant exactly when
// Check allows, and Lookup never changes the store (issue #42).
func TestLookupAgreesWithCheck(t *testing.T) {
	shop, blog := rootOf("shop"), rootOf("blog")
	build := func() *Store {
		s := &Store{}
		mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject, ProjectRoot: shop}, t0)
		mustAdd(t, s, Request{Name: "S_KEY", Layer: GlobalLayer, Scope: ScopeSession, Session: sessA}, t0)
		mustAdd(t, s, Request{Name: "O_KEY", Layer: GlobalLayer, Scope: ScopeOnce, Session: sessA}, t0)
		mustAdd(t, s, Request{Name: "P_KEY", Layer: projLayer("shop"), Scope: ScopeProject}, t0)
		return s
	}
	names := []struct{ name, layer string }{{"A_KEY", GlobalLayer}, {"S_KEY", GlobalLayer}, {"O_KEY", GlobalLayer}, {"P_KEY", projLayer("shop")}, {"NONE", GlobalLayer}}
	cwds := []string{shop, rootOf("shop", "pkg"), blog, rootOf("shop-old"), ""}
	for _, n := range names {
		for _, sess := range []string{sessA, sessB, ""} {
			for _, cwd := range cwds {
				for _, id := range []string{testRec, "other", ""} {
					s := build()
					before := append([]Grant(nil), s.Grants...)
					got, _ := Lookup(s, n.name, n.layer, id, false, sess, cwd, t0)
					if !reflect.DeepEqual(before, s.Grants) {
						t.Fatalf("Lookup changed the store for %s/%s/%q", n.name, sess, cwd)
					}
					d, _ := Check(build(), n.name, n.layer, id, false, sess, cwd, t0)
					if (got != nil) != d.Allowed {
						t.Fatalf("%s sess=%q cwd=%q id=%q: Lookup=%v Check allowed=%v", n.name, sess, cwd, id, got, d.Allowed)
					}
					if got != nil && got.Scope != d.Scope && d.Scope != ScopeOnce {
						// Check takes the first non-spent grant in store order; one
						// grant per name here, so the scopes agree.
						t.Fatalf("%s: Lookup scope %s, Check scope %s", n.name, got.Scope, d.Scope)
					}
				}
			}
		}
	}
}

func TestLookupGlobalRecordProjectGrantNeedsTheExactRepository(t *testing.T) {
	shop := rootOf("shop")
	s := &Store{}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeProject, ProjectRoot: shop}, t0)
	if g, why := Lookup(s, "A_KEY", GlobalLayer, testRec, false, sessA, shop, t0); g == nil || why != WhyNone {
		t.Fatalf("exact repository: %v %q", g, why)
	}
	for _, cwd := range []string{rootOf("blog"), rootOf("shop", "vendor", "lib"), rootOf("shop-old"), ""} {
		g, why := Lookup(s, "A_KEY", GlobalLayer, testRec, false, sessA, cwd, t0)
		if g != nil || why != WhyOtherDirectory {
			t.Fatalf("cwd %q: %v %q", cwd, g, why)
		}
		d, _ := Check(s, "A_KEY", GlobalLayer, testRec, false, sessA, cwd, t0)
		if d.Allowed || d.Why != WhyOtherDirectory {
			t.Fatalf("Check cwd %q: %+v", cwd, d)
		}
	}
}

func TestLookupNamesAnEarlierRecordAndIgnoresOtherSessions(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeSession, Session: sessA, RecordID: "old"}, t0)
	if g, why := Lookup(s, "A_KEY", GlobalLayer, testRec, false, sessA, "", t0); g != nil || why != WhyOtherRecord {
		t.Fatalf("stale: %v %q", g, why)
	}
	if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, false, sessA, "", t0); d.Why != WhyOtherRecord {
		t.Fatalf("Check stale: %+v", d)
	}
	// Another session's grant of this very record says nothing.
	s2 := &Store{}
	mustAdd(t, s2, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeSession, Session: sessB}, t0)
	if g, why := Lookup(s2, "A_KEY", GlobalLayer, testRec, false, sessA, "", t0); g != nil || why != WhyNone {
		t.Fatalf("other session: %v %q", g, why)
	}
	// An expired stale grant is not worth a note.
	if g, why := Lookup(s, "A_KEY", GlobalLayer, testRec, false, sessA, "", t0.Add(13*time.Hour)); g != nil || why != WhyNone {
		t.Fatalf("expired: %v %q", g, why)
	}
}

func TestLookupDoesNotSpendAOnceGrant(t *testing.T) {
	s := &Store{}
	mustAdd(t, s, Request{Name: "A_KEY", Layer: GlobalLayer, Scope: ScopeOnce, Session: sessA}, t0)
	for i := 0; i < 3; i++ {
		if g, _ := Lookup(s, "A_KEY", GlobalLayer, testRec, false, sessA, "", t0); g == nil || g.Scope != ScopeOnce || g.Consumed {
			t.Fatalf("lookup %d: %v", i, g)
		}
	}
	if d, _ := Check(s, "A_KEY", GlobalLayer, testRec, false, sessA, "", t0); !d.Allowed || d.Once == nil {
		t.Fatalf("Check after lookups: %+v", d)
	}
	if g, _ := Lookup(s, "A_KEY", GlobalLayer, testRec, false, sessA, "", t0); g != nil {
		t.Fatalf("a spent once grant is still found: %v", g)
	}
}
