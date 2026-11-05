package merge

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func hlc(ms int64, dev string) string { return fmt.Sprintf("%013d.0@%s", now.UnixMilli()+ms, dev) }

func rec(value, h string) Record {
	return Record{"value": json.RawMessage(`"` + value + `"`), "hlc": json.RawMessage(`"` + h + `"`)}
}

func body() *Body {
	return &Body{Schema: 2, Global: map[string]Record{}, Projects: map[string]*Project{}, Devices: map[string]Device{}}
}

func val(t *testing.T, b *Body, name string) string {
	t.Helper()
	r, ok := b.Global[name]
	if !ok {
		return "<absent>"
	}
	var v string
	_ = json.Unmarshal(r["value"], &v)
	return v
}

func TestRecordCases(t *testing.T) {
	type side = func(*Body)
	set := func(name, v, h string) side { return func(b *Body) { b.Global[name] = rec(v, h) } }
	del := func(name, h string) side {
		return func(b *Body) {
			delete(b.Global, name)
			b.Tombstones = append(b.Tombstones, Tombstone{Key: "global/" + name, HLC: h, DeletedBy: "x"})
		}
	}
	none := func(*Body) {}
	b1 := hlc(1, "a")
	cases := []struct {
		name               string
		base, local, rem   side
		want               string
		conflicts          int
		wantConflictDelete bool
	}{
		{"unchanged", set("A", "v1", b1), set("A", "v1", b1), set("A", "v1", b1), "v1", 0, false},
		{"remote edit", set("A", "v1", b1), set("A", "v1", b1), set("A", "v2", hlc(5, "b")), "v2", 0, false},
		{"local edit", set("A", "v1", b1), set("A", "v3", hlc(5, "a")), set("A", "v1", b1), "v3", 0, false},
		{"both, remote newer", set("A", "v1", b1), set("A", "loc", hlc(5, "a")), set("A", "rem", hlc(9, "b")), "rem", 1, false},
		{"both, local newer", set("A", "v1", b1), set("A", "loc", hlc(9, "a")), set("A", "rem", hlc(5, "b")), "loc", 1, false},
		{"same change", set("A", "v1", b1), set("A", "v2", hlc(5, "a")), set("A", "v2", hlc(5, "a")), "v2", 0, false},
		{"added remotely", none, none, set("A", "new", hlc(3, "b")), "new", 0, false},
		{"added on both", none, set("A", "loc", hlc(3, "a")), set("A", "rem", hlc(4, "b")), "rem", 1, false},
		{"deleted remotely", set("A", "v1", b1), set("A", "v1", b1), del("A", hlc(5, "b")), "<absent>", 0, false},
		{"deleted locally", set("A", "v1", b1), del("A", hlc(5, "a")), set("A", "v1", b1), "<absent>", 0, false},
		{"edit beats older delete", set("A", "v1", b1), set("A", "loc", hlc(9, "a")), del("A", hlc(5, "b")), "loc", 1, true},
		{"newer delete beats edit", set("A", "v1", b1), set("A", "loc", hlc(5, "a")), del("A", hlc(9, "b")), "<absent>", 1, false},
		{"stale device, no tombstone", set("A", "v1", b1), set("A", "v1", b1), none, "<absent>", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base, local, rem := body(), body(), body()
			c.base(base)
			c.base(local)
			c.base(rem)
			// Each side starts from the base, then applies its own change.
			local.Global, rem.Global = map[string]Record{}, map[string]Record{}
			local.Tombstones, rem.Tombstones = nil, nil
			c.local(local)
			c.rem(rem)
			m := Merge(base, local, rem, "a", now)
			if got := val(t, m, "A"); got != c.want {
				t.Fatalf("A=%s want %s", got, c.want)
			}
			if len(m.Conflicts) != c.conflicts {
				t.Fatalf("conflicts=%+v", m.Conflicts)
			}
			if c.conflicts == 1 && m.Conflicts[0].Deleted != c.wantConflictDelete {
				t.Fatalf("conflict deleted=%v", m.Conflicts[0].Deleted)
			}
			if c.conflicts == 1 && (m.Conflicts[0].Key != "global/A" || m.Conflicts[0].ID == "") {
				t.Fatalf("conflict=%+v", m.Conflicts[0])
			}
			_, live := m.Global["A"]
			hasTomb := false
			for _, tb := range m.Tombstones {
				hasTomb = hasTomb || tb.Key == "global/A"
			}
			if live && hasTomb {
				t.Fatal("a live record kept its tombstone")
			}
		})
	}
}

func TestRootsComeFromTheirOwnDevice(t *testing.T) {
	mk := func(roots map[string]string, label, h string) *Body {
		b := body()
		b.Projects["p1"] = &Project{Label: label, HLC: h, Roots: roots, Secrets: map[string]Record{}}
		return b
	}
	base := mk(map[string]string{"a": "/a/old", "b": "/b/x"}, "shop", hlc(1, "a"))
	local := mk(map[string]string{"a": "/a/new", "b": "/b/stale"}, "shop", hlc(1, "a"))
	rem := mk(map[string]string{"a": "/a/stale", "b": "/b/new", "c": "/c/x"}, "shop-api", hlc(5, "b"))
	m := Merge(base, local, rem, "a", now)
	p := m.Projects["p1"]
	if p.Roots["a"] != "/a/new" || p.Roots["b"] != "/b/new" || p.Roots["c"] != "/c/x" || p.Label != "shop-api" {
		t.Fatalf("project=%+v", p)
	}
}

func TestRosterUnionAndStickyRevocation(t *testing.T) {
	r1, r2 := "2026-10-01T00:00:00Z", "2026-10-05T00:00:00Z"
	local, rem := body(), body()
	local.Devices["d1"] = Device{Label: "laptop", RevokedAt: &r2, LastSync: &LastSync{Version: 4}}
	rem.Devices["d1"] = Device{Label: "laptop", RevokedAt: nil, LastSync: &LastSync{Version: 7}}
	rem.Devices["d2"] = Device{Label: "desktop"}
	local.Devices["d3"] = Device{Label: "old", RevokedAt: &r2}
	rem.Devices["d3"] = Device{Label: "old", RevokedAt: &r1}
	m := Merge(body(), local, rem, "x", now)
	if d := m.Devices["d1"]; d.RevokedAt == nil || *d.RevokedAt != r2 || d.LastSync.Version != 7 {
		t.Fatalf("d1=%+v", d)
	}
	if d := m.Devices["d3"]; *d.RevokedAt != r1 {
		t.Fatalf("d3 revoked_at=%v, want the earliest", *d.RevokedAt)
	}
	if _, ok := m.Devices["d2"]; !ok {
		t.Fatal("roster lost a device")
	}
}

func TestConflictsAndTombstonesArePruned(t *testing.T) {
	local, rem := body(), body()
	old := now.Add(-31 * 24 * time.Hour).Format(time.RFC3339)
	fresh := now.Add(-time.Hour).Format(time.RFC3339)
	local.Conflicts = []Conflict{{ID: "c-old", Key: "global/X", LostAt: old}, {ID: "c-new", Key: "global/Y", LostAt: fresh}}
	rem.Conflicts = []Conflict{{ID: "c-new", Key: "global/Y", LostAt: fresh}, {ID: "c-rem", Key: "global/Z", LostAt: fresh}}
	rem.Tombstones = []Tombstone{{Key: "global/T", HLC: fmt.Sprintf("%013d.0@b", now.Add(-181*24*time.Hour).UnixMilli())}}
	m := Merge(body(), local, rem, "a", now)
	var ids []string
	for _, c := range m.Conflicts {
		ids = append(ids, c.ID)
	}
	sort.Strings(ids)
	if strings.Join(ids, ",") != "c-new,c-rem" {
		t.Fatalf("conflicts=%v", ids)
	}
	if len(m.Tombstones) != 0 {
		t.Fatalf("tombstones=%v", m.Tombstones)
	}
}

func TestMergeIsDeterministic(t *testing.T) {
	base, local, rem := body(), body(), body()
	base.Global["A"] = rec("v1", hlc(1, "a"))
	local.Global["A"] = rec("loc", hlc(5, "a"))
	rem.Global["A"] = rec("rem", hlc(9, "b"))
	a, _ := json.Marshal(Merge(base, local, rem, "a", now))
	b, _ := json.Marshal(Merge(base, local, rem, "a", now))
	if string(a) != string(b) {
		t.Fatal("merge is not deterministic")
	}
}

// FuzzMerge: random edit sequences on two sides from one base never lose a
// change. Every live record that differs from the base on either side is in
// the result or kept as a conflict, and the result is deterministic.
func FuzzMerge(f *testing.F) {
	for _, s := range []int64{1, 2, 3, 42} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, seed int64) {
		rnd := rand.New(rand.NewSource(seed))
		base := body()
		names := []string{"A", "B", "C", "D"}
		for _, n := range names {
			if rnd.Intn(2) == 0 {
				base.Global[n] = rec(n+"0", hlc(int64(rnd.Intn(5)), "z"))
			}
		}
		side := func(dev string) *Body {
			b := body()
			for k, v := range base.Global {
				b.Global[k] = v
			}
			for _, n := range names {
				switch rnd.Intn(3) {
				case 1:
					b.Global[n] = rec(n+dev+fmt.Sprint(rnd.Intn(9)), hlc(int64(10+rnd.Intn(20)), dev))
				case 2:
					if _, ok := b.Global[n]; ok {
						delete(b.Global, n)
						b.Tombstones = append(b.Tombstones, Tombstone{Key: "global/" + n, HLC: hlc(int64(10+rnd.Intn(20)), dev)})
					}
				}
			}
			return b
		}
		local, rem := side("a"), side("b")
		m := Merge(base, local, rem, "a", now)
		kept := map[string]bool{}
		for _, r := range m.Global {
			kept[string(r["value"])] = true
		}
		for _, c := range m.Conflicts {
			if c.Record != nil {
				kept[string(c.Record["value"])] = true
			}
		}
		for _, s := range []*Body{local, rem} {
			for n, r := range s.Global {
				if br, ok := base.Global[n]; ok && string(br["hlc"]) == string(r["hlc"]) {
					continue // unchanged on this side: a deletion elsewhere may win
				}
				if !kept[string(r["value"])] {
					t.Fatalf("seed %d: change %s=%s lost", seed, n, r["value"])
				}
			}
		}
		a, _ := json.Marshal(m)
		b, _ := json.Marshal(Merge(base, local, rem, "a", now))
		if string(a) != string(b) {
			t.Fatal("not deterministic")
		}
	})
}

// Kept conflicts merge three ways like records: one resolved (removed) on
// one side since the base stays resolved; one new on either side is kept.
func TestResolvedConflictsStayResolved(t *testing.T) {
	at := now.Format(time.RFC3339)
	old := Conflict{ID: "c-old", Key: "global/A", LostAt: at}
	gone := Conflict{ID: "c-gone", Key: "global/B", LostAt: at}
	fresh := Conflict{ID: "c-new", Key: "global/C", LostAt: at}
	base, l, r := body(), body(), body()
	base.Conflicts = []Conflict{old, gone}
	l.Conflicts = []Conflict{old}              // gone was resolved here
	r.Conflicts = []Conflict{old, gone, fresh} // fresh appeared there
	m := Merge(base, l, r, "d1", now)
	ids := map[string]bool{}
	for _, c := range m.Conflicts {
		ids[c.ID] = true
	}
	if !ids["c-old"] || ids["c-gone"] || !ids["c-new"] || len(ids) != 2 {
		t.Fatalf("conflicts=%v", ids)
	}
	// With no base (first sync) both sides are kept.
	if m := Merge(nil, l, r, "d1", now); len(m.Conflicts) != 3 {
		t.Fatalf("no base: %d", len(m.Conflicts))
	}
}
