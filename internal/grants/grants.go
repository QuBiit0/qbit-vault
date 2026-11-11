// Package grants is the grant model: what the user allowed, for which record,
// to whom and for how long (docs/STORAGE.md § Grants, PRD § 5.3). It is pure
// logic over a decoded Store and an injected clock; persistence is the
// vault's (grants.enc) and every caller decides when to write.
package grants

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Scope is how far a grant reaches.
type Scope string

const (
	ScopeOnce    Scope = "once"
	ScopeSession Scope = "session"
	ScopeProject Scope = "project"
)

// ParseScope accepts exactly the three scope names.
func ParseScope(s string) (Scope, bool) {
	switch sc := Scope(s); sc {
	case ScopeOnce, ScopeSession, ScopeProject:
		return sc, true
	}
	return "", false
}

const (
	// GlobalLayer is the layer text of the global record.
	GlobalLayer   = "global"
	projectPrefix = "project:"

	// DefaultSessionTTL is the session scope lifetime without --ttl.
	DefaultSessionTTL = 12 * time.Hour
	// MinTTL and MaxTTL bound a session grant's lifetime.
	MinTTL = time.Minute
	MaxTTL = 24 * time.Hour
	// OnceTTL is how long an unused once grant stays valid.
	OnceTTL = 10 * time.Minute
)

// Typed failures. The CLI maps them to contract refusals.
var (
	ErrScopeNotAllowed = errors.New("scope_not_allowed")
	ErrGrantRequired   = errors.New("grant_required")
	ErrBadToken        = errors.New("bad_prompt_token")
	ErrInvalidRequest  = errors.New("invalid_grant_request")
	ErrInvalidTTL      = errors.New("invalid_ttl")
	// ErrNeedsProject is a scope_not_allowed refusal with its own message:
	// project scope on a global record has no project to bind to.
	ErrNeedsProject = fmt.Errorf("%w: project scope needs a repository: run it inside one", ErrScopeNotAllowed)
)

// ProjectLayer is the layer text of the project record rooted at root.
func ProjectLayer(root string) string { return projectPrefix + root }

// ProjectRootOf returns the root of a project layer text.
func ProjectRootOf(layer string) (string, bool) {
	root, ok := strings.CutPrefix(layer, projectPrefix)
	return root, ok && root != ""
}

// Grant is one permission. Session is empty and ExpiresAt nil for project
// scope; ProjectRoot is set only for project scope.
type Grant struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Layer           string     `json:"layer"`
	RecordID        string     `json:"record_id"`
	Session         string     `json:"session"`
	Scope           Scope      `json:"scope"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at"`
	Consumed        bool       `json:"consumed"`
	ProjectRoot     string     `json:"project_root,omitempty"`
	PromptTokenHash string     `json:"prompt_token_hash,omitempty"`
}

// Store is the decrypted body of grants.enc.
type Store struct {
	Grants    []Grant    `json:"grants"`
	Tokens    []Token    `json:"tokens"`
	Cooldowns []Cooldown `json:"cooldowns"`
}

// Decode parses a grants body; nil or empty is an empty store.
func Decode(body []byte) (*Store, error) {
	s := &Store{}
	if len(body) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(body, s); err != nil {
		return nil, errors.New("grants: unreadable grants body")
	}
	return s, nil
}

// Encode renders the store as a grants body.
func Encode(s *Store) ([]byte, error) {
	out := Store{Grants: s.Grants, Tokens: s.Tokens, Cooldowns: s.Cooldowns}
	if out.Cooldowns == nil {
		out.Cooldowns = []Cooldown{}
	}
	if out.Grants == nil {
		out.Grants = []Grant{}
	}
	if out.Tokens == nil {
		out.Tokens = []Token{}
	}
	return json.Marshal(out)
}

// Request is what the user confirmed.
type Request struct {
	Name            string
	Layer           string
	RecordID        string // id of the resolved record the user granted
	Session         string
	Scope           Scope
	TTL             time.Duration // session scope only; 0 means DefaultSessionTTL
	Sensitive       bool          // the record's flag; sensitive records accept once only
	PromptTokenHash string
	// ProjectRoot is the repository a project grant of a global record is
	// bound to (the canonical root of the cwd it was approved in). A project
	// record's grant takes its root from Layer and ignores this.
	ProjectRoot string
}

// Validate applies the scope rules (R-GRANT-02) without touching a store.
func Validate(req Request) error {
	if req.Name == "" {
		return ErrInvalidRequest
	}
	_, isProject := ProjectRootOf(req.Layer)
	if req.Layer != GlobalLayer && !isProject {
		return ErrInvalidRequest
	}
	switch req.Scope {
	case ScopeOnce, ScopeSession, ScopeProject:
	default:
		return ErrInvalidRequest
	}
	if req.Sensitive && req.Scope != ScopeOnce {
		return ErrScopeNotAllowed
	}
	if req.Scope == ScopeProject && !isProject && req.ProjectRoot == "" {
		return ErrNeedsProject
	}
	if req.Scope != ScopeProject && req.Session == "" {
		return ErrInvalidRequest
	}
	if req.TTL != 0 && req.Scope != ScopeSession {
		return ErrInvalidTTL
	}
	if req.Scope == ScopeSession && req.TTL != 0 && (req.TTL < MinTTL || req.TTL > MaxTTL) {
		return ErrInvalidTTL
	}
	return nil
}

// Add records a grant after validating it, replacing any identical (name,
// layer, session, scope) grant and purging what has expired.
func Add(s *Store, req Request, now time.Time) (Grant, error) {
	if err := Validate(req); err != nil {
		return Grant{}, err
	}
	if req.RecordID == "" {
		return Grant{}, ErrInvalidRequest
	}
	now = now.UTC()
	purge(s, now)
	g := Grant{
		ID: newID(), Name: req.Name, Layer: req.Layer, RecordID: req.RecordID, Scope: req.Scope,
		CreatedAt: now, PromptTokenHash: req.PromptTokenHash,
	}
	switch req.Scope {
	case ScopeOnce:
		g.Session = req.Session
		g.ExpiresAt = at(now.Add(OnceTTL))
	case ScopeSession:
		ttl := req.TTL
		if ttl == 0 {
			ttl = DefaultSessionTTL
		}
		g.Session = req.Session
		g.ExpiresAt = at(now.Add(ttl))
	case ScopeProject:
		var isProject bool
		if g.ProjectRoot, isProject = ProjectRootOf(req.Layer); !isProject {
			g.ProjectRoot = req.ProjectRoot
		}
	}
	kept := s.Grants[:0]
	for _, old := range s.Grants {
		if old.Name == g.Name && old.Layer == g.Layer && old.RecordID == g.RecordID && old.Session == g.Session && old.Scope == g.Scope && old.ProjectRoot == g.ProjectRoot {
			continue
		}
		kept = append(kept, old)
	}
	s.Grants = append(kept, g)
	return g, nil
}

func at(t time.Time) *time.Time { return &t }

func newID() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("grants: random source failed")
	}
	return "g_" + hex.EncodeToString(b[:])
}

func expired(exp *time.Time, now time.Time) bool { return exp != nil && !now.Before(*exp) }

// purge drops expired and consumed grants and expired tokens.
func purge(s *Store, now time.Time) bool {
	changed := false
	kept := s.Grants[:0]
	for _, g := range s.Grants {
		if g.Consumed || expired(g.ExpiresAt, now) {
			changed = true
			continue
		}
		kept = append(kept, g)
	}
	s.Grants = kept
	keptTokens := s.Tokens[:0]
	for _, t := range s.Tokens {
		if !now.Before(t.ExpiresAt) {
			changed = true
			continue
		}
		keptTokens = append(keptTokens, t)
	}
	s.Tokens = keptTokens
	keptCool := s.Cooldowns[:0]
	for _, c := range s.Cooldowns {
		if !now.Before(c.Until) {
			changed = true
			continue
		}
		keptCool = append(keptCool, c)
	}
	s.Cooldowns = keptCool
	return changed
}

// Purge removes expired and consumed grants and expired tokens and reports
// whether anything went.
func Purge(s *Store, now time.Time) bool { return purge(s, now.UTC()) }

// Why says why a record that has a live grant is still refused.
type Why string

const (
	// WhyNone: no grant of this record is in the way (there is none, or it
	// belongs to another session).
	WhyNone Why = ""
	// WhyOtherDirectory: a project grant exists, for another repository.
	WhyOtherDirectory Why = "other_directory"
	// WhyOtherRecord: a live grant has this name and layer but belongs to an
	// earlier record (the value was replaced or re-created). It is inert.
	WhyOtherRecord Why = "other_record"
)

// Decision is the outcome of Check.
type Decision struct {
	Allowed bool
	Scope   Scope  // the scope that allowed it
	GrantID string // the grant that allowed it
	Err     error  // nil when allowed, else ErrGrantRequired
	// Why explains a refusal when a grant exists but does not apply here.
	Why Why
	// Once is a copy of the once grant this check consumed, as it was before;
	// nil for any other scope. Restore puts it back.
	Once *Grant
}

// covers is the one predicate that decides whether a grant lets a record be
// used: Check (exec) and Lookup (list) both call it. g is already known to
// belong to the record (name, layer, record id). cwd is the canonical working
// directory, or its repository root when there is one.
func covers(g Grant, layer string, sensitive bool, session, cwd string) bool {
	switch g.Scope {
	case ScopeOnce:
		return !g.Consumed && session != "" && g.Session == session
	case ScopeSession:
		return !sensitive && session != "" && g.Session == session
	case ScopeProject:
		if sensitive {
			return false // only a once grant may allow it
		}
		// A project record's grant covers its repository and below; a global
		// record's grant only the exact repository it was approved in (cwd is
		// the repository root when there is one), so a nested repository does
		// not inherit it.
		_, projectRecord := ProjectRootOf(layer)
		return g.ProjectRoot != "" && (projectRecord && inside(g.ProjectRoot, cwd) || !projectRecord && g.ProjectRoot == cwd)
	}
	return false
}

// explain says why no live grant applies although one is there, over a store
// that is already purged (or filtered by live). A session or once grant of
// another session says nothing: it would not apply even for this record.
func explain(s *Store, name, layer, recordID string, sensitive bool, session string, live func(Grant) bool) Why {
	if recordID == "" || sensitive {
		return WhyNone
	}
	why := WhyNone
	for _, g := range s.Grants {
		if g.Name != name || g.Layer != layer || !live(g) {
			continue
		}
		if g.Scope != ScopeProject && (session == "" || g.Session != session) {
			continue
		}
		switch {
		case g.RecordID != recordID:
			if why == WhyNone {
				why = WhyOtherRecord
			}
		case g.Scope == ScopeProject:
			return WhyOtherDirectory
		}
	}
	return why
}

// Check evaluates docs/STORAGE.md § Grants for one resolved record: layer is
// the record's layer text, sensitive the record's flag (a sensitive record
// only matches once grants, even if broader ones exist), recordID its id (a grant for another record, even
// with the same name and layer, never matches; an empty id matches nothing)
// and cwd the canonical working directory (or its
// repository root). A once grant is consumed exactly once. mutated tells the
// caller to persist the store (a purge or a consumption happened).
func Check(s *Store, name, layer, recordID string, sensitive bool, session, cwd string, now time.Time) (d Decision, mutated bool) {
	now = now.UTC()
	mutated = purge(s, now)
	// Grants that are not spent by use first, so a once grant outlives a
	// session grant that already covers the call.
	if recordID == "" {
		return Decision{Err: ErrGrantRequired}, mutated
	}
	for _, g := range s.Grants {
		if g.Name == name && g.Layer == layer && g.RecordID == recordID && g.Scope != ScopeOnce && covers(g, layer, sensitive, session, cwd) {
			return Decision{Allowed: true, Scope: g.Scope, GrantID: g.ID}, mutated
		}
	}
	for i, g := range s.Grants {
		if g.Name == name && g.Layer == layer && g.RecordID == recordID && g.Scope == ScopeOnce && covers(g, layer, sensitive, session, cwd) {
			s.Grants[i].Consumed = true
			taken := g
			return Decision{Allowed: true, Scope: g.Scope, GrantID: g.ID, Once: &taken}, true
		}
	}
	why := explain(s, name, layer, recordID, sensitive, session, func(Grant) bool { return true })
	return Decision{Err: ErrGrantRequired, Why: why}, mutated
}

// Lookup is Check without side effects: the grant Check would allow the
// record with (project, else session, else an unused once grant; never
// consumed, never purged), or nil and, when a grant exists but does not apply
// here, why. The store is not modified.
func Lookup(s *Store, name, layer, recordID string, sensitive bool, session, cwd string, now time.Time) (best *Grant, why Why) {
	now = now.UTC()
	if recordID == "" {
		return nil, WhyNone
	}
	rank := map[Scope]int{ScopeProject: 3, ScopeSession: 2, ScopeOnce: 1}
	for i := range s.Grants {
		g := s.Grants[i]
		if g.Name != name || g.Layer != layer || g.RecordID != recordID || expired(g.ExpiresAt, now) {
			continue
		}
		if covers(g, layer, sensitive, session, cwd) && (best == nil || rank[g.Scope] > rank[best.Scope]) {
			best = &g
		}
	}
	if best != nil {
		return best, WhyNone
	}
	return nil, explain(s, name, layer, recordID, sensitive, session, func(g Grant) bool { return !expired(g.ExpiresAt, now) })
}

// Restore undoes the consumption of a once grant that Check returned in
// Decision.Once, for a caller that took it and then could not use it (the
// command never started). The grant is put back as it was if it is still
// live: it is un-consumed when present, re-added when a purge dropped it, and
// left out when it expired or the user granted the same thing again in the
// meantime. It reports whether the store changed.
func Restore(s *Store, g Grant, now time.Time) bool {
	now = now.UTC()
	if g.Scope != ScopeOnce || g.ID == "" || expired(g.ExpiresAt, now) {
		return false
	}
	g.Consumed = false
	for i, old := range s.Grants {
		if old.ID == g.ID {
			changed := old.Consumed
			s.Grants[i].Consumed = false
			return changed
		}
	}
	for _, old := range s.Grants {
		if !old.Consumed && !expired(old.ExpiresAt, now) && old.Name == g.Name && old.Layer == g.Layer &&
			old.RecordID == g.RecordID && old.Session == g.Session && old.Scope == g.Scope {
			return false
		}
	}
	s.Grants = append(s.Grants, g)
	return true
}

// inside reports whether p is root or below it, on path boundaries.
func inside(root, p string) bool {
	if root == "" || p == "" {
		return false
	}
	if p == root {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(p, strings.TrimSuffix(root, sep)+sep)
}

// Active returns the live grants (not expired, not consumed) sorted by name,
// layer, session and scope.
func Active(s *Store, now time.Time) []Grant {
	now = now.UTC()
	var out []Grant
	for _, g := range s.Grants {
		if !g.Consumed && !expired(g.ExpiresAt, now) {
			out = append(out, g)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Name != b.Name:
			return a.Name < b.Name
		case a.Layer != b.Layer:
			return a.Layer < b.Layer
		case a.Session != b.Session:
			return a.Session < b.Session
		}
		return a.Scope < b.Scope
	})
	return out
}

// ForRecord returns the live grants of one record (name, layer, record id).
func ForRecord(s *Store, name, layer, recordID string, now time.Time) []Grant {
	var out []Grant
	for _, g := range Active(s, now) {
		if g.Name == name && g.Layer == layer && g.RecordID == recordID {
			out = append(out, g)
		}
	}
	return out
}

func removeWhere(s *Store, drop func(Grant) bool) int {
	n := 0
	kept := s.Grants[:0]
	for _, g := range s.Grants {
		if drop(g) {
			n++
			continue
		}
		kept = append(kept, g)
	}
	s.Grants = kept
	return n
}

// RevokeName removes the grants of name in layer; an empty layer means every
// layer. It returns how many went.
func RevokeName(s *Store, name, layer string) int {
	return removeWhere(s, func(g Grant) bool { return g.Name == name && (layer == "" || g.Layer == layer) })
}

// RevokeAll removes every grant and every pending prompt token.
func RevokeAll(s *Store) int {
	n := len(s.Grants)
	s.Grants, s.Tokens = nil, nil
	return n
}

// RevokeSession removes the grants bound to session (project grants have no
// session and stay).
func RevokeSession(s *Store, session string) int {
	if session == "" {
		return 0
	}
	return removeWhere(s, func(g Grant) bool { return g.Session == session })
}

// DropRecord removes the grants of one record (rm, mv, value replace).
func DropRecord(s *Store, name, layer string) int {
	return RevokeName(s, name, layer)
}

// DropNonOnce removes the session and project grants of one record, keeping
// its once grants (a record that became sensitive accepts once only).
func DropNonOnce(s *Store, name, layer, recordID string) int {
	return removeWhere(s, func(g Grant) bool {
		return g.Name == name && g.Layer == layer && g.RecordID == recordID && g.Scope != ScopeOnce
	})
}

// DropLayer removes every grant of one layer. relink uses it for the old
// project layer: grants never follow a layer to a new root.
func DropLayer(s *Store, layer string) int {
	return removeWhere(s, func(g Grant) bool { return g.Layer == layer })
}
