package grants

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func issue(s *Store, at time.Time) string {
	return IssueToken(s, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 0, at)
}

func consume(s *Store, tok string, at time.Time) (string, error) {
	return ConsumeToken(s, tok, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 0, at)
}

func TestIssueTokenShapeAndStorage(t *testing.T) {
	s := &Store{}
	tok := issue(s, t0)
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != 32 {
		t.Fatalf("token is not 32 base64url bytes: err=%v len=%d", err, len(raw))
	}
	if other := issue(s, t0); other == tok {
		t.Fatal("two tokens are equal")
	}
	sum := sha256.Sum256([]byte(tok))
	wantHash := "sha256:" + hex.EncodeToString(sum[:])
	if len(s.Tokens) != 2 || s.Tokens[0].Hash != wantHash {
		t.Fatalf("tokens = %+v", s.Tokens)
	}
	if !s.Tokens[0].ExpiresAt.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("expiry = %v", s.Tokens[0].ExpiresAt)
	}
	enc, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), tok) || strings.Contains(string(enc), base64.StdEncoding.EncodeToString([]byte(tok))) {
		t.Fatal("token plaintext was stored")
	}
}

func TestConsumeToken(t *testing.T) {
	s := &Store{}
	tok := issue(s, t0)
	hash, err := consume(s, tok, t0.Add(time.Minute))
	if err != nil || !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
	if len(s.Tokens) != 0 {
		t.Fatal("token not removed")
	}
	if _, err := consume(s, tok, t0.Add(time.Minute)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("reuse: err = %v", err)
	}
}

type consumeArgs struct {
	name, layer, record string
	scope               Scope
	session             string
	ttl                 time.Duration
}

func TestConsumeTokenRefusals(t *testing.T) {
	base := consumeArgs{"A_KEY", GlobalLayer, "", ScopeSession, sessA, 0}
	with := func(f func(a *consumeArgs)) consumeArgs { a := base; f(&a); return a }
	tests := []struct {
		name  string
		token func(real string) string
		at    time.Duration
		args  consumeArgs
	}{
		{"unknown token", func(string) string { return "nope" }, time.Minute, base},
		{"empty token", func(string) string { return "" }, time.Minute, base},
		{"expired", func(r string) string { return r }, 2 * time.Minute, base},
		{"other name", func(r string) string { return r }, time.Minute, with(func(a *consumeArgs) { a.name = "B_KEY" })},
		{"other layer", func(r string) string { return r }, time.Minute, with(func(a *consumeArgs) { a.layer = ProjectLayer("/x") })},
		{"other scope", func(r string) string { return r }, time.Minute, with(func(a *consumeArgs) { a.scope = ScopeProject })},
		{"other session", func(r string) string { return r }, time.Minute, with(func(a *consumeArgs) { a.session = sessB })},
		{"other ttl", func(r string) string { return r }, time.Minute, with(func(a *consumeArgs) { a.ttl = time.Hour })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Store{}
			real := issue(s, t0)
			a := tt.args
			hash, err := ConsumeToken(s, tt.token(real), a.name, a.layer, a.record, a.scope, a.session, a.ttl, t0.Add(tt.at))
			if !errors.Is(err, ErrBadToken) || hash != "" {
				t.Fatalf("hash=%q err=%v", hash, err)
			}
			if strings.Contains(err.Error(), real) {
				t.Fatal("error leaks the token")
			}
		})
	}
}

// F3: the TTL is part of the binding; omitted means the scope's default.
func TestTokenBindsTTL(t *testing.T) {
	s := &Store{}
	tok := IssueToken(s, "A_KEY", GlobalLayer, "", ScopeSession, sessA, time.Hour, t0)
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 30*time.Minute, t0); !errors.Is(err, ErrBadToken) {
		t.Fatalf("a different ttl was accepted: %v", err)
	}
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "", ScopeSession, sessA, time.Hour, t0); !errors.Is(err, ErrBadToken) {
		t.Fatal("a token whose binding failed must be burnt")
	}
	tok = IssueToken(s, "A_KEY", GlobalLayer, "", ScopeSession, sessA, time.Hour, t0)
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "", ScopeSession, sessA, time.Hour, t0); err != nil {
		t.Fatalf("matching ttl refused: %v", err)
	}
	// Omitted ttl is the 12 hour default on both sides.
	tok = IssueToken(s, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 0, t0)
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "", ScopeSession, sessA, DefaultSessionTTL, t0); err != nil {
		t.Fatalf("explicit default ttl refused for an omitted-ttl token: %v", err)
	}
	tok = IssueToken(s, "A_KEY", GlobalLayer, "", ScopeSession, sessA, DefaultSessionTTL, t0)
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 0, t0); err != nil {
		t.Fatalf("omitted ttl refused for an explicit-default token: %v", err)
	}
	// Scopes without a ttl ignore it.
	tok = IssueToken(s, "A_KEY", GlobalLayer, "", ScopeOnce, sessA, 0, t0)
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "", ScopeOnce, sessA, 0, t0); err != nil {
		t.Fatalf("once token refused: %v", err)
	}
}

func TestTokenBindsRecordIDWhenKnown(t *testing.T) {
	s := &Store{}
	tok := IssueToken(s, "A_KEY", GlobalLayer, "record-A", ScopeSession, sessA, 0, t0)
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "record-B", ScopeSession, sessA, 0, t0); !errors.Is(err, ErrBadToken) {
		t.Fatalf("a token for record A worked for record B: %v", err)
	}
	tok = IssueToken(s, "A_KEY", GlobalLayer, "record-A", ScopeSession, sessA, 0, t0)
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 0, t0); !errors.Is(err, ErrBadToken) {
		t.Fatalf("a record-bound token worked without a record: %v", err)
	}
	tok = IssueToken(s, "A_KEY", GlobalLayer, "record-A", ScopeSession, sessA, 0, t0)
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "record-A", ScopeSession, sessA, 0, t0); err != nil {
		t.Fatalf("matching record refused: %v", err)
	}
	// Issued for a value that does not exist yet (set --grant): no record id.
	tok = IssueToken(s, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 0, t0)
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, "", ScopeSession, sessA, 0, t0); err != nil {
		t.Fatalf("unbound token refused: %v", err)
	}
}

func TestConsumeTokenBurnsOnMismatch(t *testing.T) {
	s := &Store{}
	tok := issue(s, t0)
	if _, err := ConsumeToken(s, tok, "B_KEY", GlobalLayer, "", ScopeSession, sessA, 0, t0); !errors.Is(err, ErrBadToken) {
		t.Fatal(err)
	}
	if _, err := consume(s, tok, t0); !errors.Is(err, ErrBadToken) {
		t.Fatal("a token misused once must be dead")
	}
}

func TestTokensExpiredArePurged(t *testing.T) {
	s := &Store{}
	issue(s, t0)
	issue(s, t0.Add(time.Hour))
	if len(s.Tokens) != 1 {
		t.Fatalf("tokens = %d, want only the fresh one", len(s.Tokens))
	}
	_, mutated := chk(s, "A_KEY", GlobalLayer, sessA, "", t0.Add(2*time.Hour))
	if !mutated || len(s.Tokens) != 0 {
		t.Fatalf("Check must purge expired tokens: mutated=%v tokens=%d", mutated, len(s.Tokens))
	}
}

func TestTokenHashFlowsIntoGrant(t *testing.T) {
	s := &Store{}
	tok := issue(s, t0)
	hash, err := consume(s, tok, t0)
	if err != nil {
		t.Fatal(err)
	}
	req := sessionReq("A_KEY", GlobalLayer, sessA)
	req.PromptTokenHash = hash
	g := mustAdd(t, s, req, t0)
	if g.PromptTokenHash != hash {
		t.Fatal("hash not recorded on the grant")
	}
}
