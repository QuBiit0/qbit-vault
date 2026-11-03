package dumpguard

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEmbeddedDefaultMatchesRepoFile(t *testing.T) {
	repo, err := os.ReadFile(filepath.Join("..", "..", "defaults", "dumpguard.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(repo) != string(defaultYAML) {
		t.Fatal("internal/dumpguard/default.yaml differs from defaults/dumpguard.yaml; copy it over")
	}
}

func TestParseAcceptedShapes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"single quotes", "format: gentle-vault-dumpguard/1\npatterns:\n  - '^env$'\n", []string{`^env$`}},
		{"double quotes", "format: gentle-vault-dumpguard/1\npatterns:\n  - \"^a\\\\b$\"\n", []string{`^a\b$`}},
		{"escaped double quote", "format: gentle-vault-dumpguard/1\npatterns:\n  - \"x\\\"y\"\n", []string{`x"y`}},
		{"doubled single quote", "format: gentle-vault-dumpguard/1\npatterns:\n  - 'it''s'\n", []string{`it's`}},
		{"comments", "# head\nformat: gentle-vault-dumpguard/1 # trailing\n\npatterns:\n  # inside\n  - '^a#b$'   # trailing\n  - \"c\"# x\n", []string{`^a#b$`, `c`}},
		{"crlf", "format: gentle-vault-dumpguard/1\r\npatterns:\r\n  - 'a'\r\n", []string{`a`}},
		{"quoted format", "format: \"gentle-vault-dumpguard/1\"\npatterns:\n- 'a'\n", []string{`a`}},
		{"no patterns", "format: gentle-vault-dumpguard/1\npatterns:\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse([]byte(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			var srcs []string
			for _, p := range got {
				srcs = append(srcs, p.src)
			}
			if !reflect.DeepEqual(srcs, tt.want) {
				t.Fatalf("got %q want %q", srcs, tt.want)
			}
		})
	}
}

func TestParseRejectsWithLineNumberOnly(t *testing.T) {
	const marker = "TESTSECRET_dump"
	hdr := "format: gentle-vault-dumpguard/1\npatterns:\n"
	tests := []struct {
		name string
		in   string
		line int
	}{
		{"unquoted item", hdr + "  - " + marker + "\n", 3},
		{"unterminated quote", hdr + "  - '" + marker + "\n", 3},
		{"junk after quote", hdr + "  - '" + marker + "' extra\n", 3},
		{"unknown key", hdr + "other: x\n", 3},
		{"bad escape", hdr + "  - \"\\s" + marker + "\"\n", 3},
		{"tab indent", hdr + "\t- '" + marker + "'\n", 3},
		{"invalid regexp", hdr + "  - '(" + marker + "'\n", 3},
		{"wrong format", "format: " + marker + "\npatterns:\n", 1},
		{"duplicate patterns key", hdr + "patterns:\n", 3},
		{"item before patterns", "format: gentle-vault-dumpguard/1\n  - 'a'\n", 2},
		{"duplicate format", "format: gentle-vault-dumpguard/1\nformat: gentle-vault-dumpguard/1\n", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parse([]byte(tt.in))
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("want *ParseError, got %v", err)
			}
			if pe.Line != tt.line {
				t.Fatalf("line %d, want %d", pe.Line, tt.line)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error echoes file content: %q", err.Error())
			}
		})
	}
}

func TestParseMissingHeaders(t *testing.T) {
	for _, in := range []string{"", "patterns:\n  - 'a'\n", "format: gentle-vault-dumpguard/1\n"} {
		if _, err := parse([]byte(in)); err == nil {
			t.Fatalf("expected an error for %q", in)
		}
	}
}

func TestDefaultPatternsParse(t *testing.T) {
	g := Default()
	if len(g.Patterns()) < 20 {
		t.Fatalf("only %d default patterns", len(g.Patterns()))
	}
}

func TestLoadUserExtensionAddsAndCannotRemove(t *testing.T) {
	home := t.TempDir()
	user := "format: gentle-vault-dumpguard/1\npatterns:\n  - '^mytool\\s+--dump$'\n  - '^env$'\n"
	if err := os.WriteFile(filepath.Join(home, "dumpguard.yaml"), []byte(user), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := Load(home)
	if err != nil {
		t.Fatal(err)
	}
	inj := []string{"TOKEN"}
	if !g.Match("mytool --dump", inj) {
		t.Fatal("user pattern not applied")
	}
	if !g.Match("printenv", inj) {
		t.Fatal("default pattern lost")
	}
	if got, want := len(g.Patterns()), len(Default().Patterns())+1; got != want {
		t.Fatalf("patterns %d, want %d (union, deduped)", got, want)
	}
	// An empty user file shortens nothing.
	if err := os.WriteFile(filepath.Join(home, "dumpguard.yaml"), []byte("format: gentle-vault-dumpguard/1\npatterns:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err = Load(home)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Match("env", inj) {
		t.Fatal("defaults must survive an empty user file")
	}
}

func TestLoadMissingFileIsDefaults(t *testing.T) {
	g, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !g.Match("printenv", []string{"X"}) {
		t.Fatal("defaults not active")
	}
}

func TestLoadMalformedUserFile(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "dumpguard.yaml"), []byte("format: gentle-vault-dumpguard/1\npatterns:\n  - nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(home)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Line != 3 {
		t.Fatalf("want ParseError line 3, got %v", err)
	}
	if !strings.Contains(err.Error(), "dumpguard.yaml") {
		t.Fatalf("error should name the file: %v", err)
	}
}
