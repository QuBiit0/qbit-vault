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

func TestIssueTokenShapeAndStorage(t *testing.T) {
	s := &Store{}
	tok := IssueToken(s, "A_KEY", GlobalLayer, ScopeSession, sessA, t0)
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != 32 {
		t.Fatalf("token is not 32 base64url bytes: err=%v len=%d", err, len(raw))
	}
	if other := IssueToken(s, "A_KEY", GlobalLayer, ScopeSession, sessA, t0); other == tok {
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
	tok := IssueToken(s, "A_KEY", GlobalLayer, ScopeSession, sessA, t0)
	hash, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, ScopeSession, sessA, t0.Add(time.Minute))
	if err != nil || !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
	if len(s.Tokens) != 0 {
		t.Fatal("token not removed")
	}
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, ScopeSession, sessA, t0.Add(time.Minute)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("reuse: err = %v", err)
	}
}

func TestConsumeTokenRefusals(t *testing.T) {
	tests := []struct {
		name  string
		token func(real string) string
		at    time.Duration
		args  [4]string // name, layer, scope, session
	}{
		{"unknown token", func(string) string { return "nope" }, time.Minute, [4]string{"A_KEY", GlobalLayer, "session", sessA}},
		{"empty token", func(string) string { return "" }, time.Minute, [4]string{"A_KEY", GlobalLayer, "session", sessA}},
		{"expired", func(r string) string { return r }, 2 * time.Minute, [4]string{"A_KEY", GlobalLayer, "session", sessA}},
		{"other name", func(r string) string { return r }, time.Minute, [4]string{"B_KEY", GlobalLayer, "session", sessA}},
		{"other layer", func(r string) string { return r }, time.Minute, [4]string{"A_KEY", ProjectLayer("/x"), "session", sessA}},
		{"other scope", func(r string) string { return r }, time.Minute, [4]string{"A_KEY", GlobalLayer, "project", sessA}},
		{"other session", func(r string) string { return r }, time.Minute, [4]string{"A_KEY", GlobalLayer, "session", sessB}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Store{}
			real := IssueToken(s, "A_KEY", GlobalLayer, ScopeSession, sessA, t0)
			hash, err := ConsumeToken(s, tt.token(real), tt.args[0], tt.args[1], Scope(tt.args[2]), tt.args[3], t0.Add(tt.at))
			if !errors.Is(err, ErrBadToken) || hash != "" {
				t.Fatalf("hash=%q err=%v", hash, err)
			}
			if strings.Contains(err.Error(), real) {
				t.Fatal("error leaks the token")
			}
		})
	}
}

func TestConsumeTokenBurnsOnMismatch(t *testing.T) {
	s := &Store{}
	tok := IssueToken(s, "A_KEY", GlobalLayer, ScopeSession, sessA, t0)
	if _, err := ConsumeToken(s, tok, "B_KEY", GlobalLayer, ScopeSession, sessA, t0); !errors.Is(err, ErrBadToken) {
		t.Fatal(err)
	}
	if _, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, ScopeSession, sessA, t0); !errors.Is(err, ErrBadToken) {
		t.Fatal("a token misused once must be dead")
	}
}

func TestTokensExpiredArePurged(t *testing.T) {
	s := &Store{}
	IssueToken(s, "A_KEY", GlobalLayer, ScopeSession, sessA, t0)
	IssueToken(s, "A_KEY", GlobalLayer, ScopeSession, sessA, t0.Add(time.Hour))
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
	tok := IssueToken(s, "A_KEY", GlobalLayer, ScopeSession, sessA, t0)
	hash, err := ConsumeToken(s, tok, "A_KEY", GlobalLayer, ScopeSession, sessA, t0)
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
