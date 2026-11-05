// Package dumpguard refuses commands that would print the environment while
// secrets are injected (PRD R-EXEC-03, docs/CLI.md § Exec). The patterns are
// data, not code: the default file is embedded and
// $QBIT_VAULT_HOME/dumpguard.yaml can add to it, never remove from it.
//
// This is a guard, not a shell parser. It splits a command into segments
// (pipelines, lists, subshells, `sh -c` scripts) and matches RE2 patterns
// against each normalized segment. It does not expand variables, aliases,
// functions, `$'...'` strings or `${IFS}` tricks, and it cannot see a command
// that is built at run time (`echo ZW52 | base64 -d | sh`). The redactor
// (internal/redact) is the layer that still protects the output then.
package dumpguard

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed default.yaml
var defaultYAML []byte

const (
	formatID = "qbit-vault-dumpguard/1"
	fileName = "dumpguard.yaml"
	// nameToken is the placeholder that expands to the injected names.
	nameToken = "{NAME}"
)

// ParseError reports a malformed data file. It names the line only: the
// file's text is never echoed. Line 0 means a missing header.
type ParseError struct {
	Line   int
	Reason string
}

func (e *ParseError) Error() string {
	if e.Line == 0 {
		return "dumpguard: " + e.Reason
	}
	return fmt.Sprintf("dumpguard: line %d: %s", e.Line, e.Reason)
}

type pat struct {
	src  string
	line int
}

// Guard is a compiled set of patterns. Safe for concurrent use.
type Guard struct {
	pats []pat

	mu    sync.Mutex
	cache map[string][]*regexp.Regexp
}

// Default returns the guard of the embedded default patterns.
func Default() *Guard {
	pats, err := parse(defaultYAML)
	if err != nil {
		panic("dumpguard: embedded default.yaml is invalid") // covered by a test
	}
	return &Guard{pats: pats}
}

// Load returns the default patterns plus those of home/dumpguard.yaml when it
// exists (union, without duplicates). A user file cannot remove a default. An
// empty home means defaults only.
func Load(home string) (*Guard, error) {
	g := Default()
	if home == "" {
		return g, nil
	}
	data, err := os.ReadFile(filepath.Join(home, fileName))
	if errors.Is(err, os.ErrNotExist) {
		return g, nil
	}
	if err != nil {
		return nil, errors.New("dumpguard: cannot read " + fileName)
	}
	user, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileName, err)
	}
	have := map[string]bool{}
	for _, p := range g.pats {
		have[p.src] = true
	}
	for _, p := range user {
		if !have[p.src] {
			have[p.src] = true
			g.pats = append(g.pats, p)
		}
	}
	return g, nil
}

// Patterns returns the pattern sources in order (defaults first).
func (g *Guard) Patterns() []string {
	out := make([]string, len(g.pats))
	for i, p := range g.pats {
		out[i] = p.src
	}
	return out
}

// parse reads the fixed shape of the data files (L4):
//
//	format: qbit-vault-dumpguard/1
//	patterns:
//	  - 'single quoted'   # comment
//	  - "double quoted"
//
// Single quotes escape a quote by doubling it; double quotes accept \\ and \"
// only. Anything else is a ParseError naming the line.
func parse(data []byte) ([]pat, error) {
	var (
		pats       []pat
		sawFormat  bool
		inPatterns bool
	)
	bad := func(n int, why string) ([]pat, error) { return nil, &ParseError{Line: n, Reason: why} }
	for i, raw := range strings.Split(string(data), "\n") {
		n := i + 1
		line := strings.TrimSuffix(raw, "\r")
		trimmed := strings.TrimLeft(line, " ")
		if strings.HasPrefix(trimmed, "\t") || strings.Contains(line[:len(line)-len(trimmed)], "\t") {
			return bad(n, "tab indentation")
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(trimmed)
		switch {
		case strings.HasPrefix(trimmed, "-"):
			if !inPatterns {
				return bad(n, "list item outside patterns")
			}
			rest := trimmed[1:]
			if rest == "" || rest[0] != ' ' {
				return bad(n, "invalid list item")
			}
			s, err := scalar(strings.TrimLeft(rest, " "), true)
			if err != nil {
				return bad(n, err.Error())
			}
			if _, err := regexp.Compile(expand(s, []string{"X"})); err != nil {
				return bad(n, "invalid pattern")
			}
			pats = append(pats, pat{src: s, line: n})
		case indent > 0:
			return bad(n, "unexpected indentation")
		case strings.HasPrefix(trimmed, "format:"):
			if sawFormat {
				return bad(n, "duplicate format")
			}
			v, err := scalar(strings.TrimLeft(trimmed[len("format:"):], " "), false)
			if err != nil || v != formatID {
				return bad(n, "unsupported format")
			}
			sawFormat = true
		case strings.HasPrefix(trimmed, "patterns:"):
			if inPatterns {
				return bad(n, "duplicate patterns")
			}
			rest := strings.TrimLeft(trimmed[len("patterns:"):], " ")
			if rest != "" && !strings.HasPrefix(rest, "#") {
				return bad(n, "invalid patterns header")
			}
			inPatterns = true
		default:
			return bad(n, "unknown key")
		}
	}
	if !sawFormat {
		return bad(0, "missing format header")
	}
	if !inPatterns {
		return bad(0, "missing patterns")
	}
	return pats, nil
}

// scalar reads a quoted string, or a plain one when quoted is false, followed
// only by an optional comment.
func scalar(s string, quoted bool) (string, error) {
	if s == "" {
		return "", errors.New("empty value")
	}
	var (
		b   strings.Builder
		end int
	)
	switch s[0] {
	case '\'':
		i := 1
		for {
			if i >= len(s) {
				return "", errors.New("unterminated quote")
			}
			if s[i] == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i += 2
					continue
				}
				break
			}
			b.WriteByte(s[i])
			i++
		}
		end = i + 1
	case '"':
		i := 1
		for {
			if i >= len(s) {
				return "", errors.New("unterminated quote")
			}
			c := s[i]
			if c == '"' {
				break
			}
			if c == '\\' {
				if i+1 >= len(s) || (s[i+1] != '\\' && s[i+1] != '"') {
					return "", errors.New("unsupported escape")
				}
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			b.WriteByte(c)
			i++
		}
		end = i + 1
	default:
		if quoted {
			return "", errors.New("value must be quoted")
		}
		v := s
		if j := strings.Index(v, " #"); j >= 0 {
			v = v[:j]
		}
		return strings.TrimRight(v, " "), nil
	}
	rest := strings.TrimLeft(s[end:], " ")
	if rest != "" && !strings.HasPrefix(rest, "#") {
		return "", errors.New("unexpected text after value")
	}
	return b.String(), nil
}

// expand replaces {NAME} with an alternation of the quoted names.
func expand(pattern string, names []string) string {
	if !strings.Contains(pattern, nameToken) {
		return pattern
	}
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	return strings.ReplaceAll(pattern, nameToken, "(?:"+strings.Join(q, "|")+")")
}

// compiled returns the regexps for one set of injected names, compiled once.
func (g *Guard) compiled(names []string) []*regexp.Regexp {
	uniq := append([]string(nil), names...)
	sort.Strings(uniq)
	key := strings.Join(uniq, ",")
	g.mu.Lock()
	defer g.mu.Unlock()
	if res, ok := g.cache[key]; ok {
		return res
	}
	res := make([]*regexp.Regexp, 0, len(g.pats))
	for _, p := range g.pats {
		if re, err := regexp.Compile(expand(p.src, uniq)); err == nil {
			res = append(res, re)
		}
	}
	if g.cache == nil {
		g.cache = map[string][]*regexp.Regexp{}
	}
	g.cache[key] = res
	return res
}

// compiledSets reports how many name sets were compiled (tests).
func (g *Guard) compiledSets() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.cache)
}
