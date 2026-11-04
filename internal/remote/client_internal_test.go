package remote

import "testing"

// Clients share one transport per CA so connections are reused: a fresh
// transport per client leaks idle sockets in a long-lived process (the MCP
// server) and exhausts ephemeral ports on Windows.
func TestClientsShareTheirTransport(t *testing.T) {
	a, err := NewClient("http://127.0.0.1:9", "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewClient("https://vault.example.com", "")
	if a.http.Transport != b.http.Transport {
		t.Fatal("each client built its own transport")
	}
}
