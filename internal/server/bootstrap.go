package server

import (
	"errors"
	"os"
	"time"
	"unicode/utf8"
)

// MinBootstrapInvite and MinBootstrapDistinct are the least a code of
// QBV_SERVER_BOOTSTRAP_INVITE must have: it stands in for a random 128-bit
// invite, so it must not be guessable (`aaaa...` is not).
const (
	MinBootstrapInvite   = 24
	MinBootstrapDistinct = 12
)

// ErrWeakInvite refuses a bootstrap code that is too short or too repetitive.
var ErrWeakInvite = errors.New("server: bootstrap invite too short")

// BootstrapInvite registers code as a single-use account invite valid for
// ttl, but only while the server has no account: it is how an operator who
// cannot run `invite` inside the container (a shell-less image on a hosted
// platform) creates the first account. Like Invite, only the code's hash is
// stored. made is false when an account already exists; the code is then
// ignored and nothing is written. An invite already stored for the code keeps
// its first expiry: a restart never refreshes it.
func (s *Server) BootstrapInvite(code string, ttl time.Duration) (made bool, err error) {
	seen := map[rune]bool{}
	for _, r := range code {
		seen[r] = true
	}
	if utf8.RuneCountInString(code) < MinBootstrapInvite || len(seen) < MinBootstrapDistinct {
		return false, ErrWeakInvite
	}
	entries, err := os.ReadDir(s.st.path("accounts"))
	switch {
	case err == nil && len(entries) > 0:
		return false, nil
	case err != nil && !os.IsNotExist(err):
		return false, err
	}
	path := s.st.path("invites", hash(code))
	if _, err := os.Stat(path); err == nil {
		return true, nil
	}
	exp := s.cfg.Now().Add(ttl).UTC().Format(time.RFC3339Nano)
	if err := writeJSON(path, map[string]string{"expires_at": exp}); err != nil {
		return false, err
	}
	return true, nil
}
