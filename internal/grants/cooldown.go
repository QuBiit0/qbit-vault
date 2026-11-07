package grants

import "time"

// DefaultCooldown is how long a declined or cancelled request for a name
// cannot be asked again in the same session (R-CAP-05).
const DefaultCooldown = 60 * time.Second

// SharedCooldown is how long a declined or cancelled request for a name in a
// layer cannot be asked again by any session, so a new session cannot
// re-prompt it at once.
const SharedCooldown = 30 * time.Second

// Cooldown blocks re-asking Name in Session until Until. An entry with a
// Layer and no Session blocks every session for that name and layer.
type Cooldown struct {
	Name    string    `json:"name"`
	Session string    `json:"session"`
	Layer   string    `json:"layer,omitempty"`
	Until   time.Time `json:"until"`
}

// Cool starts (or restarts) the cooldown of name in session from now.
func Cool(s *Store, name, session string, now time.Time) {
	until := now.UTC().Add(DefaultCooldown)
	for i, c := range s.Cooldowns {
		if c.Name == name && c.Session == session && c.Layer == "" {
			s.Cooldowns[i].Until = until
			return
		}
	}
	s.Cooldowns = append(s.Cooldowns, Cooldown{Name: name, Session: session, Until: until})
}

// CoolingDown reports whether name is in its cooldown for session at now.
func CoolingDown(s *Store, name, session string, now time.Time) (time.Time, bool) {
	for _, c := range s.Cooldowns {
		if c.Name == name && c.Session == session && c.Layer == "" && now.Before(c.Until) {
			return c.Until, true
		}
	}
	return time.Time{}, false
}

// CoolShared starts (or restarts) the all-sessions cooldown of name in layer.
func CoolShared(s *Store, name, layer string, now time.Time) {
	until := now.UTC().Add(SharedCooldown)
	for i, c := range s.Cooldowns {
		if c.Name == name && c.Session == "" && c.Layer == layer {
			s.Cooldowns[i].Until = until
			return
		}
	}
	s.Cooldowns = append(s.Cooldowns, Cooldown{Name: name, Layer: layer, Until: until})
}

// CoolingDownShared reports whether name in layer is in its all-sessions
// cooldown at now.
func CoolingDownShared(s *Store, name, layer string, now time.Time) bool {
	for _, c := range s.Cooldowns {
		if c.Name == name && c.Session == "" && c.Layer == layer && now.Before(c.Until) {
			return true
		}
	}
	return false
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
