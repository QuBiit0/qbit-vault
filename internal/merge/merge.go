// Package merge is the three-way, per-record merge of two schema-2 vault
// bodies against the version both last agreed on (docs/REMOTE_SYNC.md §
// 7.3-7.4). It is pure: no disk, no network, no clock but the one given.
// When both sides changed a record the newer change wins and the other is
// kept as a conflict, so no change is ever lost silently.
package merge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	tombstoneTTL = 180 * 24 * time.Hour
	conflictTTL  = 30 * 24 * time.Hour
	maxConflicts = 100
)

// Record is one secret record as stored; only its "hlc" is interpreted.
type Record map[string]json.RawMessage

// HLC returns the record's clock.
func (r Record) HLC() string {
	var h string
	_ = json.Unmarshal(r["hlc"], &h)
	return h
}

// Project is a project layer of schema 2.
type Project struct {
	Label   string            `json:"label"`
	Origin  string            `json:"origin,omitempty"`
	Roots   map[string]string `json:"roots,omitempty"`
	HLC     string            `json:"hlc,omitempty"`
	Secrets map[string]Record `json:"secrets"`
}

// Tombstone records a deletion.
type Tombstone struct {
	Key       string `json:"key"`
	HLC       string `json:"hlc"`
	DeletedBy string `json:"deleted_by"`
}

// Conflict is the losing side of a double change: a record, or a deletion.
type Conflict struct {
	ID           string `json:"id"`
	Key          string `json:"key"`
	Record       Record `json:"record,omitempty"`
	Deleted      bool   `json:"deleted,omitempty"`
	LostAt       string `json:"lost_at"`
	WinnerDevice string `json:"winner_device,omitempty"`
}

// LastSync is the last version a device synced.
type LastSync struct {
	Version int64  `json:"version"`
	At      string `json:"at"`
}

// Device is a roster entry.
type Device struct {
	Label     string    `json:"label"`
	SignPub   string    `json:"sign_pub,omitempty"`
	BoxPub    string    `json:"box_pub,omitempty"`
	AddedAt   string    `json:"added_at,omitempty"`
	AddedBy   string    `json:"added_by,omitempty"`
	RevokedAt *string   `json:"revoked_at"`
	LastSync  *LastSync `json:"last_sync,omitempty"`
}

// Body is a schema-2 vault body.
type Body struct {
	Schema     int                 `json:"schema"`
	Global     map[string]Record   `json:"global"`
	Projects   map[string]*Project `json:"projects"`
	Tombstones []Tombstone         `json:"tombstones"`
	Conflicts  []Conflict          `json:"conflicts"`
	Devices    map[string]Device   `json:"devices"`
}

// entry is what a body holds under one record key.
type entry struct {
	rec  Record // nil for a tombstone
	tomb *Tombstone
}

func (e *entry) hlc() string {
	switch {
	case e == nil:
		return ""
	case e.tomb != nil:
		return e.tomb.HLC
	}
	return e.rec.HLC()
}

// same reports one change: both absent, or the same clock.
func same(a, b *entry) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return (a.tomb != nil) == (b.tomb != nil) && a.hlc() == b.hlc()
}

// flatten indexes b's records and tombstones by merge key.
func flatten(b *Body) map[string]*entry {
	m := map[string]*entry{}
	if b == nil {
		return m
	}
	for i := range b.Tombstones {
		t := b.Tombstones[i]
		m[t.Key] = &entry{tomb: &t}
	}
	for n, r := range b.Global {
		m["global/"+n] = &entry{rec: r}
	}
	for id, p := range b.Projects {
		for n, r := range p.Secrets {
			m["project/"+id+"/"+n] = &entry{rec: r}
		}
	}
	return m
}

// Merge returns the merge of local and remote against base, for device (the
// one running it: its project roots are taken from local).
func Merge(base, local, remote *Body, device string, now time.Time) *Body {
	b, l, r := flatten(base), flatten(local), flatten(remote)
	out := &Body{Schema: 2, Global: map[string]Record{}, Projects: map[string]*Project{}, Devices: map[string]Device{}}

	out.Projects = mergeProjects(base, local, remote, device)
	var conflicts []Conflict
	for _, k := range keys(l, r) {
		lb, ll, lr := b[k], l[k], r[k]
		var win *entry
		switch {
		case same(ll, lr):
			win = ll
		case same(ll, lb):
			win = lr
		case same(lr, lb):
			win = ll
		default:
			win, lose := ll, lr
			if compare(lr.hlc(), ll.hlc()) > 0 {
				win, lose = lr, ll
			}
			conflicts = append(conflicts, conflictOf(k, lose, win, now))
			place(out, k, win)
			continue
		}
		place(out, k, win)
	}

	conflicts = append(conflicts, existing(base, local, remote)...)
	out.Conflicts = prune(conflicts, now)
	out.Tombstones = liveTombstones(out, now)
	out.Devices = mergeRoster(local, remote)
	return out
}

// place puts the winning entry of key into out.
func place(out *Body, key string, e *entry) {
	if e == nil {
		return
	}
	if e.tomb != nil {
		out.Tombstones = append(out.Tombstones, *e.tomb)
		return
	}
	if name, ok := strings.CutPrefix(key, "global/"); ok {
		out.Global[name] = e.rec
		return
	}
	rest := strings.TrimPrefix(key, "project/")
	id, name, _ := strings.Cut(rest, "/")
	p := out.Projects[id]
	if p == nil {
		p = &Project{Roots: map[string]string{}, Secrets: map[string]Record{}}
		out.Projects[id] = p
	}
	p.Secrets[name] = e.rec
}

func conflictOf(key string, lose, win *entry, now time.Time) Conflict {
	c := Conflict{Key: key, LostAt: now.UTC().Format(time.RFC3339)}
	if _, dev, ok := strings.Cut(win.hlc(), "@"); ok {
		c.WinnerDevice = dev
	}
	if lose.tomb != nil {
		c.Deleted = true
	} else {
		c.Record = lose.rec
	}
	sum := sha256.Sum256([]byte(key + "|" + lose.hlc()))
	c.ID = "c_" + hex.EncodeToString(sum[:8])
	return c
}

// mergeProjects merges layer metadata (newer hlc wins) and roots (each
// device's own entry from the side that device writes: local for this
// device, remote for every other one).
func mergeProjects(base, local, remote *Body, device string) map[string]*Project {
	out := map[string]*Project{}
	ids := map[string]bool{}
	for _, b := range []*Body{local, remote} {
		if b != nil {
			for id := range b.Projects {
				ids[id] = true
			}
		}
	}
	get := func(b *Body, id string) *Project {
		if b == nil {
			return nil
		}
		return b.Projects[id]
	}
	for id := range ids {
		lp, rp := get(local, id), get(remote, id)
		p := &Project{Roots: map[string]string{}, Secrets: map[string]Record{}}
		meta := lp
		if meta == nil || (rp != nil && compare(rp.HLC, lp.HLC) > 0) {
			meta = rp
		}
		p.Label, p.Origin, p.HLC = meta.Label, meta.Origin, meta.HLC
		if rp != nil {
			for d, root := range rp.Roots {
				if d != device {
					p.Roots[d] = root
				}
			}
		}
		if lp != nil {
			if root, ok := lp.Roots[device]; ok {
				p.Roots[device] = root
			}
		} else if rp != nil {
			if root, ok := rp.Roots[device]; ok {
				p.Roots[device] = root
			}
		}
		out[id] = p
	}
	_ = base
	return out
}

// existing merges the kept conflicts three ways: a conflict the base held
// and one side no longer has was resolved there and stays resolved; any
// other conflict of either side is kept.
func existing(base, local, remote *Body) []Conflict {
	ids := func(b *Body) map[string]bool {
		m := map[string]bool{}
		if b != nil {
			for _, c := range b.Conflicts {
				m[c.ID] = true
			}
		}
		return m
	}
	inBase, inLocal, inRemote := ids(base), ids(local), ids(remote)
	var out []Conflict
	for _, b := range []*Body{local, remote} {
		if b == nil {
			continue
		}
		for _, c := range b.Conflicts {
			if inBase[c.ID] && (!inLocal[c.ID] || !inRemote[c.ID]) {
				continue
			}
			out = append(out, c)
		}
	}
	return out
}

// prune dedupes conflicts by id, drops those older than 30 days and keeps
// the newest 100.
func prune(cs []Conflict, now time.Time) []Conflict {
	seen := map[string]bool{}
	var out []Conflict
	for _, c := range cs {
		at, err := time.Parse(time.RFC3339, c.LostAt)
		if seen[c.ID] || (err == nil && at.Before(now.Add(-conflictTTL))) {
			continue
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LostAt != out[j].LostAt {
			return out[i].LostAt > out[j].LostAt
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > maxConflicts {
		out = out[:maxConflicts]
	}
	if out == nil {
		out = []Conflict{}
	}
	return out
}

// liveTombstones keeps the winning tombstones that are younger than the TTL
// and whose key holds no live record, in key order.
func liveTombstones(out *Body, now time.Time) []Tombstone {
	live := flatten(&Body{Global: out.Global, Projects: out.Projects})
	var ts []Tombstone
	seen := map[string]bool{}
	for _, t := range out.Tombstones {
		if seen[t.Key] || live[t.Key] != nil || clockTime(t.HLC).Before(now.Add(-tombstoneTTL)) {
			continue
		}
		seen[t.Key] = true
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Key < ts[j].Key })
	if ts == nil {
		ts = []Tombstone{}
	}
	return ts
}

// mergeRoster is the union of both rosters: revoked_at is sticky (the
// earliest one wins) and last_sync takes the higher version.
func mergeRoster(local, remote *Body) map[string]Device {
	out := map[string]Device{}
	for _, b := range []*Body{local, remote} {
		if b == nil {
			continue
		}
		for id, d := range b.Devices {
			cur, ok := out[id]
			if !ok {
				out[id] = d
				continue
			}
			if d.RevokedAt != nil && (cur.RevokedAt == nil || *d.RevokedAt < *cur.RevokedAt) {
				cur.RevokedAt = d.RevokedAt
			}
			if d.LastSync != nil && (cur.LastSync == nil || d.LastSync.Version > cur.LastSync.Version) {
				cur.LastSync = d.LastSync
			}
			for _, f := range []struct {
				dst *string
				src string
			}{{&cur.Label, d.Label}, {&cur.SignPub, d.SignPub}, {&cur.BoxPub, d.BoxPub}, {&cur.AddedAt, d.AddedAt}, {&cur.AddedBy, d.AddedBy}} {
				if *f.dst == "" {
					*f.dst = f.src
				}
			}
			out[id] = cur
		}
	}
	return out
}

// keys is the sorted union of the keys of maps.
func keys(ms ...map[string]*entry) []string {
	set := map[string]bool{}
	for _, m := range ms {
		for k := range m {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// compare orders hybrid clocks "<ms>.<counter>@<device>".
func compare(a, b string) int {
	am, ac, ad := parse(a)
	bm, bc, bd := parse(b)
	switch {
	case am != bm:
		return sign(am - bm)
	case ac != bc:
		return sign(ac - bc)
	}
	return strings.Compare(ad, bd)
}

func sign(x int64) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	}
	return 0
}

func parse(h string) (ms, ctr int64, dev string) {
	t, dev, _ := strings.Cut(h, "@")
	a, c, _ := strings.Cut(t, ".")
	ms, _ = strconv.ParseInt(a, 10, 64)
	ctr, _ = strconv.ParseInt(c, 10, 64)
	return ms, ctr, dev
}

func clockTime(h string) time.Time {
	ms, _, _ := parse(h)
	return time.UnixMilli(ms)
}
