package vault

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Body schema 2 (docs/STORAGE.md § Plaintext body): project layers keyed by
// a random id with one root per device, a hybrid logical clock on every
// record, tombstones for deletions and the sync roster. In memory the body
// keeps project layers keyed by this device's root, so resolution, grants
// and relink are unchanged; projects without a root here are kept aside as
// unlinked. Every save compares the body with the one loaded: a changed or
// new record gets a fresh hlc and a vanished one leaves a tombstone, so no
// command stamps anything itself (odd/tasks/remote-sync.md L2).

const (
	schemaVersion = 2
	tombstoneTTL  = 180 * 24 * time.Hour
)

// hlcNow is the wall clock of the hybrid clock; tests pin it.
var hlcNow = time.Now

type wireProject struct {
	Label   string                `json:"label"`
	Origin  string                `json:"origin,omitempty"`
	Roots   map[string]string     `json:"roots,omitempty"`
	HLC     string                `json:"hlc,omitempty"`
	Secrets map[string]wireRecord `json:"secrets"`
}

type tombstone struct {
	Key       string `json:"key"`
	HLC       string `json:"hlc"`
	DeletedBy string `json:"deleted_by"`
}

type wireBody struct {
	Schema     int                        `json:"schema"`
	Global     map[string]wireRecord      `json:"global"`
	Projects   map[string]json.RawMessage `json:"projects"`
	Tombstones []tombstone                `json:"tombstones"`
	Conflicts  []json.RawMessage          `json:"conflicts"`
	Devices    map[string]json.RawMessage `json:"devices"`
}

// decodeBody reads a schema 1 or 2 body for device. A schema 1 body is
// migrated in memory: every project layer gets an id, a root for this
// device and its origin; the next save writes schema 2.
func decodeBody(pt []byte, device string) (*body, error) {
	var w wireBody
	if err := json.Unmarshal(pt, &w); err != nil {
		return nil, corrupt("unreadable body")
	}
	if w.Schema > schemaVersion {
		return nil, corrupt("vault was written by a newer qbit-vault; upgrade")
	}
	b := newBody()
	b.device = device
	if w.Global != nil {
		b.Global = w.Global
	}
	b.tombstones, b.conflicts, b.devices = w.Tombstones, w.Conflicts, w.Devices
	for key, raw := range w.Projects {
		var p wireProject
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, corrupt("unreadable project")
		}
		if p.Secrets == nil {
			p.Secrets = map[string]wireRecord{}
		}
		pb := &projectBody{Label: p.Label, Secrets: p.Secrets, ID: key, Origin: p.Origin, Roots: p.Roots, HLC: p.HLC}
		if w.Schema < 2 {
			pb.ID, pb.Roots, pb.Origin = newProjectID(), map[string]string{device: key}, originOf(key)
		}
		if pb.Roots == nil {
			pb.Roots = map[string]string{}
		}
		root := pb.Roots[device]
		if _, taken := b.Projects[root]; root == "" || taken {
			b.unlinked = append(b.unlinked, pb)
			continue
		}
		b.Projects[root] = pb
	}
	b.clock = newClock(device, b)
	return b, nil
}

// encodeBody writes b as schema 2, stamping what changed since before (the
// index of the body as loaded) and purging old tombstones.
func encodeBody(b *body, before map[string]string) ([]byte, error) {
	now := hlcNow()
	after := b.index()
	live := map[string]bool{}
	stamp := func(key string, hlc *string) {
		live[key] = true
		if old, ok := before[key]; !ok || old != after[key] || *hlc == "" {
			*hlc = b.clock.next(now)
		}
	}
	w := wireBody{Schema: schemaVersion, Global: b.Global, Projects: map[string]json.RawMessage{},
		Conflicts: b.conflicts, Devices: b.devices}
	for n, r := range b.Global {
		stamp("global/"+n, &r.HLC)
		b.Global[n] = r
	}
	put := func(p *projectBody) error {
		stamp("project/"+p.ID, &p.HLC)
		for n, r := range p.Secrets {
			stamp("project/"+p.ID+"/"+n, &r.HLC)
			p.Secrets[n] = r
		}
		raw, err := json.Marshal(wireProject{Label: p.Label, Origin: p.Origin, Roots: p.Roots, HLC: p.HLC, Secrets: p.Secrets})
		w.Projects[p.ID] = raw
		return err
	}
	for root, p := range b.Projects {
		if p.Roots == nil {
			p.Roots = map[string]string{}
		}
		p.Roots[b.device] = root
		if err := put(p); err != nil {
			return nil, err
		}
	}
	for _, p := range b.unlinked {
		if err := put(p); err != nil {
			return nil, err
		}
	}
	// Tombstones: a key that was there and is gone; none for live keys; none
	// older than the TTL.
	var ts []tombstone
	for _, t := range b.tombstones {
		if live[t.Key] || hlcTime(t.HLC).Before(now.Add(-tombstoneTTL)) {
			continue
		}
		ts = append(ts, t)
	}
	for key := range before {
		if !live[key] && isRecordKey(key) {
			ts = append(ts, tombstone{Key: key, HLC: b.clock.next(now), DeletedBy: b.device})
		}
	}
	if ts == nil {
		ts = []tombstone{}
	}
	if w.Conflicts == nil {
		w.Conflicts = []json.RawMessage{}
	}
	if w.Devices == nil {
		w.Devices = map[string]json.RawMessage{}
	}
	w.Tombstones = ts
	return json.Marshal(w)
}

// index fingerprints every record and project of b by merge key. The
// fingerprint is a hash, so the index holds no value.
func (b *body) index() map[string]string {
	m := map[string]string{}
	fp := func(v any) string {
		raw, _ := json.Marshal(v)
		sum := sha256.Sum256(raw)
		clear(raw)
		return hex.EncodeToString(sum[:])
	}
	rec := func(r wireRecord) string { r.HLC = ""; return fp(r) }
	for n, r := range b.Global {
		m["global/"+n] = rec(r)
	}
	for _, p := range b.allProjects() {
		m["project/"+p.ID] = fp([]string{p.Label, p.Origin})
		for n, r := range p.Secrets {
			m["project/"+p.ID+"/"+n] = rec(r)
		}
	}
	return m
}

// isRecordKey tells a record key (global/N, project/<id>/N) from a project
// key (project/<id>): only records leave tombstones.
func isRecordKey(key string) bool {
	return strings.HasPrefix(key, "global/") || strings.Count(key, "/") == 2
}

func (b *body) allProjects() []*projectBody {
	out := make([]*projectBody, 0, len(b.Projects)+len(b.unlinked))
	for _, p := range b.Projects {
		out = append(out, p)
	}
	return append(out, b.unlinked...)
}

func newProjectID() string {
	var r [16]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic("vault: random source failed")
	}
	return hex.EncodeToString(r[:])
}

// ---- hybrid logical clock: "<unix_ms>.<counter>@<device>" ----

type hlcClock struct {
	device string
	ms     int64
	ctr    int
}

func newClock(device string, b *body) *hlcClock {
	c := &hlcClock{device: device}
	see := func(h string) {
		ms, ctr, ok := parseHLC(h)
		if ok && (ms > c.ms || (ms == c.ms && ctr > c.ctr)) {
			c.ms, c.ctr = ms, ctr
		}
	}
	for _, r := range b.Global {
		see(r.HLC)
	}
	for _, p := range b.allProjects() {
		see(p.HLC)
		for _, r := range p.Secrets {
			see(r.HLC)
		}
	}
	for _, t := range b.tombstones {
		see(t.HLC)
	}
	return c
}

// next is a clock value above every one seen and not below the wall clock.
func (c *hlcClock) next(now time.Time) string {
	if ms := now.UnixMilli(); ms > c.ms {
		c.ms, c.ctr = ms, 0
	} else {
		c.ctr++
	}
	return fmt.Sprintf("%013d.%d@%s", c.ms, c.ctr, c.device)
}

func parseHLC(h string) (ms int64, ctr int, ok bool) {
	t, _, found := strings.Cut(h, "@")
	if !found {
		return 0, 0, false
	}
	a, c, found := strings.Cut(t, ".")
	if !found {
		return 0, 0, false
	}
	ms, err1 := strconv.ParseInt(a, 10, 64)
	n, err2 := strconv.Atoi(c)
	return ms, n, err1 == nil && err2 == nil
}

// compareHLC orders two clock values by milliseconds, counter, then device.
func compareHLC(a, b string) int {
	am, ac, _ := parseHLC(a)
	bm, bc, _ := parseHLC(b)
	switch {
	case am != bm:
		return cmp(am, bm)
	case ac != bc:
		return cmp(int64(ac), int64(bc))
	}
	_, ad, _ := strings.Cut(a, "@")
	_, bd, _ := strings.Cut(b, "@")
	return strings.Compare(ad, bd)
}

func cmp(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func hlcTime(h string) time.Time {
	ms, _, ok := parseHLC(h)
	if !ok {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// ---- origin of a repository (REMOTE_SYNC.md § 7.5) ----

// originOf reads the origin remote of the repository at root and returns it
// normalized, or "" when there is none. It never runs git.
func originOf(root string) string {
	cfg := filepath.Join(root, ".git", "config")
	if fi, err := os.Lstat(filepath.Join(root, ".git")); err == nil && !fi.IsDir() {
		// A linked worktree: .git is "gitdir: <dir>"; the config lives in the
		// common directory.
		raw, err := os.ReadFile(filepath.Join(root, ".git"))
		if err != nil {
			return ""
		}
		dir := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "gitdir:"))
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(root, dir)
		}
		common := filepath.Join(dir, "..", "..")
		if c, err := os.ReadFile(filepath.Join(dir, "commondir")); err == nil {
			common = strings.TrimSpace(string(c))
			if !filepath.IsAbs(common) {
				common = filepath.Join(dir, common)
			}
		}
		cfg = filepath.Join(common, "config")
	}
	data, err := os.ReadFile(cfg)
	if err != nil {
		return ""
	}
	in := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			in = strings.EqualFold(strings.Join(strings.Fields(line), " "), `[remote "origin"]`)
			continue
		}
		if k, v, ok := strings.Cut(line, "="); in && ok && strings.EqualFold(strings.TrimSpace(k), "url") {
			return normalizeOrigin(strings.TrimSpace(v))
		}
	}
	return ""
}

// normalizeOrigin is host/path of a remote URL: scheme, credentials, port
// and a .git suffix dropped, host lower-cased. Local paths have no origin.
func normalizeOrigin(u string) string {
	u = strings.TrimSpace(u)
	var host, path string
	switch {
	case strings.Contains(u, "://"):
		rest := u[strings.Index(u, "://")+3:]
		host, path, _ = strings.Cut(rest, "/")
	case strings.Contains(u, ":") && !strings.HasPrefix(u, "/") && !strings.HasPrefix(u, ".") && !(len(u) > 1 && u[1] == ':'):
		host, path, _ = strings.Cut(u, ":") // scp-like user@host:path
	default:
		return ""
	}
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if host == "" || path == "" {
		return ""
	}
	return strings.ToLower(host) + "/" + path
}
