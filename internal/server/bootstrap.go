package server

import (
	"errors"
	"os"
	"time"
)

// MinBootstrapInvite is the shortest code QBV_SERVER_BOOTSTRAP_INVITE accepts:
// it stands in for a random 128-bit invite, so it must not be guessable.
const MinBootstrapInvite = 24

// ErrWeakInvite refuses a bootstrap code shorter than MinBootstrapInvite.
var ErrWeakInvite = errors.New("server: bootstrap invite too short")

// BootstrapInvite registers code as a single-use account invite valid for
// ttl, but only while the server has no account: it is how an operator who
// cannot run `invite` inside the container (a shell-less image on a hosted
// platform) creates the first account. Like Invite, only the code's hash is
// stored. made is false when an account already exists; the code is then
// ignored and nothing is written.
func (s *Server) BootstrapInvite(code string, ttl time.Duration) (made bool, err error) {
	if len(code) < MinBootstrapInvite {
		return false, ErrWeakInvite
	}
	entries, err := os.ReadDir(s.st.path("accounts"))
	switch {
	case err == nil && len(entries) > 0:
		return false, nil
	case err != nil && !os.IsNotExist(err):
		return false, err
	}
	exp := s.cfg.Now().Add(ttl).UTC().Format(time.RFC3339Nano)
	if err := writeJSON(s.st.path("invites", hash(code)), map[string]string{"expires_at": exp}); err != nil {
		return false, err
	}
	return true, nil
}
