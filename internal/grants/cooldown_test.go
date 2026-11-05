package grants

import (
	"strings"
	"testing"
	"time"
)

func TestCooldownPerSessionAndName(t *testing.T) {
	s := &Store{}
	Cool(s, "A", sessA, t0)
	if until, on := CoolingDown(s, "A", sessA, t0.Add(59*time.Second)); !on || !until.Equal(t0.Add(DefaultCooldown)) {
		t.Fatalf("on=%v until=%v", on, until)
	}
	if _, on := CoolingDown(s, "A", sessB, t0); on {
		t.Fatal("cooldown leaked to another session")
	}
	if _, on := CoolingDown(s, "B", sessA, t0); on {
		t.Fatal("cooldown leaked to another name")
	}
	if _, on := CoolingDown(s, "A", sessA, t0.Add(DefaultCooldown)); on {
		t.Fatal("cooldown outlived its 60 s")
	}
	// A second decline restarts it, without duplicating the entry.
	Cool(s, "A", sessA, t0.Add(30*time.Second))
	if len(s.Cooldowns) != 1 {
		t.Fatalf("entries=%d", len(s.Cooldowns))
	}
	if got := Cooldowns(s, sessA, t0.Add(31*time.Second)); len(got) != 1 || got[0].Name != "A" {
		t.Fatalf("Cooldowns=%v", got)
	}
}

func TestCooldownsRoundTripAndPurge(t *testing.T) {
	s := &Store{}
	Cool(s, "A", sessA, t0)
	body, err := Encode(s)
	if err != nil || !strings.Contains(string(body), `"cooldowns":[`) {
		t.Fatalf("encode: %s %v", body, err)
	}
	back, err := Decode(body)
	if err != nil || len(back.Cooldowns) != 1 {
		t.Fatalf("decode: %v %v", back, err)
	}
	if !Purge(back, t0.Add(2*DefaultCooldown)) || len(back.Cooldowns) != 0 {
		t.Fatal("expired cooldown not purged")
	}
	if b, _ := Encode(&Store{}); !strings.Contains(string(b), `"cooldowns":[]`) {
		t.Fatalf("empty store: %s", b)
	}
}
