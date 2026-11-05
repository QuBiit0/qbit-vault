package vault

import "testing"

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"GITHUB_TOKEN": true, "A": true, "A1_B2": true,
		"": false, "lower": false, "1ABC": false, "_ABC": false, "A-B": false, "A B": false,
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, want)
		}
	}
	if ValidName("A"+repeat('B', 64)) || !ValidName("A"+repeat('B', 63)) {
		t.Error("length bound is 64 characters")
	}
}

func repeat(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
