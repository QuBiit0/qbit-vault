package cli

import (
	"reflect"
	"testing"
)

func TestCommandHosts(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{"url", "curl https://api.github.com/repos/x/y", []string{"api.github.com"}},
		{"url with port and userinfo", "git clone ssh://git@Example.COM:2222/x.git", []string{"example.com"}},
		{"bare hostname", "ping db.internal.example.org", []string{"db.internal.example.org"}},
		{"module path", "go get github.com/spf13/cobra", []string{"github.com"}},
		{"ipv4", "nc 10.0.0.12 5432", []string{"10.0.0.12"}},
		{"two hosts once each", "curl a.example.com b.example.com a.example.com", []string{"a.example.com", "b.example.com"}},
		{"file names are not hosts", "cat README.md package.json main.go archive.tar.gz", nil},
		{"versions are not hosts", "tool --version 1.2.3 v2.0.1", nil},
		{"url wins over its path", "curl https://x.example.com/readme.md", []string{"x.example.com"}},
		{"no hosts", "gh pr list --json number", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commandHosts(tt.cmd); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("commandHosts(%q)\n got %q\nwant %q", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestHostsOutside(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		allowed []string
		want    bool
	}{
		{"empty list means any", "curl https://evil.example.net", nil, false},
		{"inside", "curl https://api.github.com/x", []string{"api.github.com"}, false},
		{"case-insensitive", "curl https://API.GitHub.com/x", []string{"api.github.com"}, false},
		{"outside", "curl https://evil.example.net/x", []string{"api.github.com"}, true},
		{"one inside one outside", "curl api.github.com evil.example.net", []string{"api.github.com"}, true},
		{"wildcard", "curl https://a.github.com", []string{"*.github.com"}, false},
		{"wildcard does not match the bare domain", "curl https://github.com", []string{"*.github.com"}, true},
		{"no hosts in command", "gh pr list", []string{"api.github.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostsOutside(tt.cmd, tt.allowed); got != tt.want {
				t.Fatalf("hostsOutside = %v, want %v", got, tt.want)
			}
		})
	}
}
