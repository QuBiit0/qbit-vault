package grants

import "time"

// DefaultCooldown is how long a declined or cancelled request for a name
// cannot be asked again in the same session (R-CAP-05).
const DefaultCooldown = 60 * time.Second

// Cooldown blocks re-asking Name in Session until Until.
type Cooldown struct {
	Name    string    `json:"name"`
	Session string    `json:"session"`
	Until   time.Time `json:"until"`
}

// Cool starts (or restarts) the cooldown of name in session from now.
func Cool(s *Store, name, session string, now time.Time) {
	until := now.UTC().Add(DefaultCooldown)
	for i, c := range s.Cooldowns {
		if c.Name == name && c.Session == session {
			s.Cooldowns[i].Until = until
			return
		}
	}
	s.Cooldowns = append(s.Cooldowns, Cooldown{Name: name, Session: session, Until: until})
}

// CoolingDown reports whether name is in its cooldown for session at now.
func CoolingDown(s *Store, name, session string, now time.Time) (time.Time, bool) {
	for _, c := range s.Cooldowns {
		if c.Name == name && c.Session == session && now.Before(c.Until) {
			return c.Until, true
		}
	}
	return time.Time{}, false
}

// Cooldowns lists the active cooldowns of session.
func Cooldowns(s *Store, session string, now time.Time) []Cooldown {
	var out []Cooldown
	for _, c := range s.Cooldowns {
		if c.Session == session && now.Before(c.Until) {
			out = append(out, c)
		}
	}
	return out
}
