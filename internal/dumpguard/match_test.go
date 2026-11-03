package dumpguard

import (
	"strings"
	"testing"
)

var inj = []string{"GITHUB_TOKEN", "DB_URL"}

// perPattern pairs every default pattern, in file order, with a command it
// must refuse and one it must allow while GITHUB_TOKEN and DB_URL are injected.
var perPattern = []struct {
	pattern string
	bad     string
	good    string
}{
	{`^env$`, "env", "envsubst < t"},
	{`^env\s+-\S*0`, "env -0", "env -i true"},
	{`^printenv(\s|$)`, "printenv HOME", "printenvx"},
	{`^set$`, "set", "set -e"},
	{`^export\s+-p$`, "export -p", "export FOO=1"},
	{`^declare\s+-x`, "declare -x", "declare -a arr"},
	{`^typeset\s+-x`, "typeset -x", "typeset -i n"},
	{`^(cat|less|more|head|tail|strings|xxd|od)\s+(/proc/(self|\d+)/environ)`, "cat /proc/self/environ", "cat /proc/self/status"},
	{`^(cat|less|more|head|tail)\s+/dev/fd/`, "cat /dev/fd/3", "cat /dev/null"},
	{`(?i)^(gci|get-childitem|ls|dir)\s+env:`, "Get-ChildItem Env:", "ls /tmp"},
	{`(?i)\[environment\]::getenvironmentvariables`, "[Environment]::GetEnvironmentVariables()", "[Environment]::NewLine"},
	{`(?i)^get-item\s+env:`, "Get-Item Env:GITHUB_TOKEN", "Get-Item ./x"},
	{`^echo\s+.*\$\{?{NAME}\}?`, "echo $GITHUB_TOKEN", "echo $HOME"},
	{`^printf\s+.*\$\{?{NAME}\}?`, `printf '%s' "${DB_URL}"`, "printf '%s' hi"},
	{`(?i)^(echo|write-output|write-host)\s+.*\$env:{NAME}`, "Write-Output $env:GITHUB_TOKEN", "Write-Output $env:HOME"},
	{`^echo\s+.*%{NAME}%`, "echo %GITHUB_TOKEN%", "echo %HOME%"},
	{`^(python3?|node|ruby|perl)\s+-[ce]\s+.*(os\.environ|process\.env|ENV\[)`, `python3 -c "import os; print(os.environ)"`, `python3 -c "print(1)"`},
	{`^node\s+-p\s+process\.env`, "node -p process.env", "node -p 1+1"},
	{`(base64|xxd|od|hexdump)\s*<<<\s*"?\$\{?{NAME}`, `base64 <<< "$GITHUB_TOKEN"`, `base64 <<< "$HOME"`},
	{`^(curl|wget|http|nc|ncat|socat)\s+.*\$\{?{NAME}\}?`, `curl -H "Authorization: $GITHUB_TOKEN" x`, "curl https://example.com"},
}

func TestEveryDefaultPatternHasPositiveAndNegative(t *testing.T) {
	g := Default()
	pats := g.Patterns()
	if len(perPattern) != len(pats) {
		t.Fatalf("table has %d rows, default.yaml has %d patterns: add a case for each", len(perPattern), len(pats))
	}
	for i, tt := range perPattern {
		if pats[i] != tt.pattern {
			t.Fatalf("row %d is for %q but pattern %d is %q", i, tt.pattern, i, pats[i])
		}
		t.Run(tt.pattern, func(t *testing.T) {
			// Only this pattern is loaded, so the case proves that pattern.
			one := &Guard{pats: []pat{{src: tt.pattern, line: 1}}}
			if !one.Match(tt.bad, inj) {
				t.Errorf("%q should be refused", tt.bad)
			}
			if one.Match(tt.good, inj) {
				t.Errorf("%q should be allowed", tt.good)
			}
		})
	}
}

func TestMatchIsOffWithoutInjectedSecrets(t *testing.T) {
	g := Default()
	for _, c := range []string{"env", "env | grep PATH", "printenv", "echo $HOME"} {
		if g.Match(c, nil) {
			t.Errorf("%q must be allowed when nothing is injected", c)
		}
	}
	if !g.Match("env | grep PATH", inj) {
		t.Error("env piped to grep must be refused while a secret is injected")
	}
}

func TestMatchNameExpansion(t *testing.T) {
	g := Default()
	if !g.Match("echo $GITHUB_TOKEN", []string{"GITHUB_TOKEN"}) {
		t.Error("injected name must match")
	}
	if g.Match("echo $OTHER_NAME", []string{"GITHUB_TOKEN"}) {
		t.Error("a name that is not injected must not match")
	}
	if !g.Match("echo ${B}", []string{"A", "B", "C"}) {
		t.Error("every injected name is an alternative")
	}
	// Names are regexp-quoted: a dot in a name must not act as a wildcard.
	if g.Match("echo $AxB", []string{"A.B"}) {
		t.Error("names must be quoted")
	}
}

func TestMatchSegmentsAndWrappers(t *testing.T) {
	g := Default()
	for _, c := range []string{
		"cd /tmp && env",
		"true; printenv",
		"ls | env | cat",
		"echo $(env)",
		"echo `printenv`",
		`"env"`,
		`e\nv`,
		"env 2>&1",
		"env > /tmp/out",
		"env # comment",
		"/usr/bin/env",
		"sudo env",
		"sudo -u root printenv HOME",
		"command env",
		"exec env",
		"nohup env",
		"env FOO=1",
		"FOO=1 env",
		"bash -c 'env'",
		`sh -c "echo ok; printenv"`,
		"eval env",
		"cat < /proc/self/environ",
		"( env )",
		"{ env; }",
		"if true; then env; fi",
		"ENV",
		"SET",
	} {
		if !g.Match(c, inj) {
			t.Errorf("%q should be refused", c)
		}
	}
	for _, c := range []string{
		"git status && go test ./...",
		"echo hello",
		"set -e",
		"grep env README.md",
		"cat README.md | head",
		"gh pr list --json number",
	} {
		if g.Match(c, inj) {
			t.Errorf("%q should be allowed", c)
		}
	}
}

func TestMatchCompiledOncePerNameSet(t *testing.T) {
	g := Default()
	g.Match("ls", []string{"A"})
	g.Match("ls", []string{"A"})
	g.Match("ls", []string{"B"})
	if n := g.compiledSets(); n != 2 {
		t.Fatalf("compiled sets %d, want 2", n)
	}
}

// dumps are known dump commands; the fuzz target mutates them.
var dumps = []string{
	"env", "printenv", "printenv HOME", "env -0", "export -p", "declare -x",
	"cat /proc/self/environ", "echo $GITHUB_TOKEN", `printf "%s" ${GITHUB_TOKEN}`,
	"Get-ChildItem Env:", "gci env:", "[Environment]::GetEnvironmentVariables()",
	"Write-Output $env:GITHUB_TOKEN", "echo %GITHUB_TOKEN%", "node -p process.env",
}

var prefixes = []string{"", "cd /tmp && ", "true; ", "false || ", "x | ", "FOO=1 ", "sudo ", "sudo -E ", "env ", "command ", "exec ", "nohup ", "time ", "  ", "\t", "echo hi\n", "( ", "{ ", "! "}

var suffixes = []string{"", " | cat", " > /dev/null", " 2>&1", " && true", " ; ls", " # c", "\n", " &", " | grep PATH", " |& cat", " ) ", " ; }"}

// mutate builds a command that still holds dump as its own segment.
func mutate(dump string, pre, suf, form uint8) string {
	p := prefixes[int(pre)%len(prefixes)]
	s := suffixes[int(suf)%len(suffixes)]
	d := dump
	switch form % 4 {
	case 1:
		d = strings.ReplaceAll(d, " ", "   ")
	case 2:
		if f, rest, ok := strings.Cut(d, " "); ok && !strings.ContainsAny(f, `[:`) {
			d = `"` + f + `" ` + rest
		}
	case 3:
		if i := strings.IndexByte(d, ' '); i > 1 && !strings.ContainsAny(d[:i], `[:`) {
			d = d[:1] + "''" + d[1:]
		}
	}
	if strings.HasSuffix(p, "( ") && !strings.Contains(s, ")") {
		s += " )"
	}
	if strings.HasSuffix(p, "{ ") && !strings.Contains(s, "}") {
		s += " ; }"
	}
	return p + d + s
}

func FuzzDumpGuard(f *testing.F) {
	g := Default()
	names := []string{"GITHUB_TOKEN"}
	for i := range dumps {
		f.Add(uint8(i), uint8(0), uint8(0), uint8(0), "")
		f.Add(uint8(i), uint8(1), uint8(2), uint8(1), "x $(")
		f.Add(uint8(i), uint8(8), uint8(3), uint8(2), "\"'`\\")
	}
	f.Fuzz(func(t *testing.T, sel, pre, suf, form uint8, junk string) {
		cmd := mutate(dumps[int(sel)%len(dumps)], pre, suf, form)
		if !g.Match(cmd, names) {
			t.Fatalf("mutated dump command allowed: %q", cmd)
		}
		// Arbitrary text must never panic, whatever it is.
		_ = g.Match(junk, names)
		_ = Segments(junk)
		_ = Binaries(junk)
		_ = g.Match(junk+" ; "+cmd, names)
	})
}
