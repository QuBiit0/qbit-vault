package grants

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// TokenTTL is how long a prompt token can be redeemed.
const TokenTTL = 2 * time.Minute

// Token is a pending prompt token. Only its SHA-256 is stored; it is bound to
// one (name, layer, scope, session) and valid once (L5).
type Token struct {
	Hash      string    `json:"hash"`
	Name      string    `json:"name"`
	Layer     string    `json:"layer"`
	Scope     Scope     `json:"scope"`
	Session   string    `json:"session"`
	ExpiresAt time.Time `json:"expires_at"`
}

func hashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// IssueToken creates a prompt token for the broker's own prompt backend and
// returns its plaintext, which is never stored. Expired tokens are purged.
func IssueToken(s *Store, name, layer string, scope Scope, session string, now time.Time) string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("grants: random source failed")
	}
	plaintext := base64.RawURLEncoding.EncodeToString(b[:])
	now = now.UTC()
	purge(s, now)
	s.Tokens = append(s.Tokens, Token{
		Hash: hashToken(plaintext), Name: name, Layer: layer, Scope: scope,
		Session: session, ExpiresAt: now.Add(TokenTTL),
	})
	return plaintext
}

// ConsumeToken redeems plaintext for exactly this (name, layer, scope,
// session) and returns the token's hash for the audit trail. A token that is
// found is removed whether or not it matches, so a token used for the wrong
// request is dead. Unknown, expired, reused and mismatched tokens are all
// ErrBadToken, and the message never carries the token.
func ConsumeToken(s *Store, plaintext, name, layer string, scope Scope, session string, now time.Time) (string, error) {
	h := hashToken(plaintext)
	found := -1
	for i, t := range s.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) == 1 {
			found = i
		}
	}
	if plaintext == "" || found < 0 {
		return "", ErrBadToken
	}
	t := s.Tokens[found]
	s.Tokens = append(s.Tokens[:found], s.Tokens[found+1:]...)
	if !now.UTC().Before(t.ExpiresAt) {
		return "", ErrBadToken
	}
	if t.Name != name || t.Layer != layer || t.Scope != scope || t.Session != session {
		return "", ErrBadToken
	}
	return t.Hash, nil
}
