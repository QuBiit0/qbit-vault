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
	// F2: gaps found by the independent review.
	{`^export$`, "export", "export FOO=1"},
	{`^(declare|typeset)$`, "declare", "declare -a arr"},
	{`^(declare|typeset)\s+-\S*p`, "typeset -p", "declare -a arr"},
	{`^(declare|typeset)\s+(-\S+\s+)*{NAME}`, "declare GITHUB_TOKEN", "declare FOO"},
	{`^compgen\s+(-\S*[ev]|-A\s+(variable|export))`, "compgen -e", "compgen -c"},
	{`/proc/(self|thread-self|\d+|\$\$|\$\{?BASHPID\}?)(/task/\d+)?/environ`, `tr '\0' '\n' < /proc/$$/environ`, "cat /proc/self/status"},
	{`^find\s+.*-(exec|execdir|ok|okdir)\s+(\S*/)?(env|printenv)(\s|;|$)`, `find . -exec /usr/bin/printenv {} +`, `find . -exec ls {} +`},
	{`\$\{!`, "echo ${!x}", "echo ${HOME}"},
	{`<<.*\$\{?{NAME}`, "cat <<EOF\n$GITHUB_TOKEN\nEOF", "cat <<EOF\nhello\nEOF"},
	{`^(awk|gawk|mawk|nawk)\s+.*ENVIRON`, `awk 'BEGIN{print ENVIRON["GITHUB_TOKEN"]}'`, `awk '{print $1}'`},
	{`^perl\s+.*(%ENV|\$ENV\s*\{)`, `perl -e 'print $ENV{GITHUB_TOKEN}'`, `perl -e 'print 1'`},
	{`^(python3?|py)\s+.*(os\.(getenv|environ)|from\s+os\s+import\s+.*(environ|getenv))`, `python3 -c "import os; print(os.getenv('X'))"`, `python3 -c "print(1)"`},
	{`^node\s+.*process\.env`, `node -e "console.log(process.env.X)"`, "node app.js"},
	{`^ruby\s+.*\bENV\b`, `ruby -e 'puts ENV["X"]'`, `ruby -e "puts 1"`},
	{`(?i)\$\{?env:{NAME}`, "gh api --token $env:GITHUB_TOKEN", "gh api --token $env:HOME"},
	{`(?i)^(get-content|gc|cat|type)\s+(-\S+\s+)*env:`, "Get-Content -Path env:GITHUB_TOKEN", "Get-Content ./x"},
	{`(?i)\[(system\.)?environment\]::getenvironmentvariable\b`, "[System.Environment]::GetEnvironmentVariable('X')", "[Environment]::NewLine"},
	{`(?i)^set\s+"?[a-z_][a-z0-9_]*"?$`, `set "G`, "set FOO=1"},
	{`%{NAME}:[^%\s]*%`, "echo %GITHUB_TOKEN:~0,5%", "gh --token %GITHUB_TOKEN%"},
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

// F2: whole commands, through wrappers, redirects and subshells.
func TestMatchGuardGaps(t *testing.T) {
	g := Default()
	bad := []string{
		"export", "declare", "declare -p", "typeset", "typeset -p", "declare -p GITHUB_TOKEN",
		"compgen -e", "compgen -v", "compgen -A variable",
		"grep . /proc/self/environ", "cat < /proc/self/environ", `tr '\0' '\n' </proc/$$/environ`,
		"cat /proc/$BASHPID/environ", "cat /proc/1234/environ", "head -c 99 /proc/${BASHPID}/environ",
		"xargs env", "echo | xargs -n1 printenv", `find . -exec env \;`, "find / -execdir printenv {} +",
		"nice env", "nice -n 5 printenv", "timeout 5 env", "timeout -s KILL 5s env", "stdbuf -oL env",
		"stdbuf -o L env", "strace -f env", "strace -o /tmp/x -e trace=none env", "chroot /tmp env",
		"ionice -c 3 env", "setsid env", "doas env", "doas -u root env", "xargs -I {} env",
		"x=GITHUB_TOKEN; echo ${!x}", "echo ${!GITH*}",
		"cat <<< $GITHUB_TOKEN", "sed s/a/b/ <<< \"${DB_URL}\"", "cat <<EOF\n$GITHUB_TOKEN\nEOF",
		`awk 'BEGIN{print ENVIRON["DB_URL"]}'`, `perl -e 'print $ENV{DB_URL}'`, `perl -e 'print %ENV'`,
		`python3 -c "import os; print(os.getenv('X'))"`, `python3 -c "from os import environ; print(environ)"`,
		`node -e "console.log(process.env)"`, `ruby -e 'puts ENV.to_a'`,
		"gh api --token $env:GITHUB_TOKEN", "Get-Content env:GITHUB_TOKEN",
		"[System.Environment]::GetEnvironmentVariable('X')",
		"set G", `set "G`, "echo %GITHUB_TOKEN:~0,5%", "call %DB_URL:~0,5%",
	}
	good := []string{
		"export FOO=1", "export PATH=$PATH:/x", "declare -a arr", "declare FOO=1", "typeset -i n", "compgen -c", "compgen -A function",
		"cat /proc/self/status", "cat /proc/cpuinfo", "xargs echo hi", "find . -name env", `find . -exec ls {} \;`,
		"nice make", "timeout 5 make test", "timeout -s KILL 5s go test", "stdbuf -oL make", "strace -f ls", "chroot /tmp ls",
		"ionice -c 3 make", "setsid make", "doas ls",
		"echo ${HOME}", "echo ${#arr[@]}", "cat <<EOF\nhello\nEOF", "cat <<< $HOME",
		`awk '{print $1}'`, `perl -e 'print 1'`, `python3 -c "print(1)"`, "node app.js", `ruby -e "puts 1"`,
		"gh api --token $env:HOME", "Get-Content ./x", "[Environment]::NewLine", "set -e", "set FOO=1", "set -- a b",
		"echo %HOME:~0,5%", "gh --token %GITHUB_TOKEN%",
	}
	for _, c := range bad {
		if !g.Match(c, inj) {
			t.Errorf("%q should be refused", c)
		}
	}
	for _, c := range good {
		if g.Match(c, inj) {
			t.Errorf("%q should be allowed", c)
		}
	}
}

func TestMatchRawForShellsWithOtherGrammars(t *testing.T) {
	g := Default()
	// POSIX segmentation would see one harmless word here; cmd and pwsh
	// would run the second command.
	for _, c := range []string{`echo "a\" & printenv & \"b"`, `echo "a\" ; env ; \"b"`} {
		if g.Match(c, inj) {
			t.Skipf("POSIX segmentation already refuses %q", c)
		}
		if !g.MatchRaw(c, inj) {
			t.Errorf("MatchRaw(%q) should refuse", c)
		}
	}
	if !g.MatchRaw("env", inj) || !g.MatchRaw("  Env  ", inj) {
		t.Error("a plain dump command is refused as a raw segment")
	}
	if g.MatchRaw("gh --version", inj) || g.MatchRaw("env", nil) {
		t.Error("MatchRaw must allow harmless commands and be off without injected names")
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
	"export", "declare -p", "typeset", "compgen -e", "cat /proc/$$/environ", "echo ${!x}",
	"cat <<< $GITHUB_TOKEN", "gh x --t $env:GITHUB_TOKEN", "set G", "echo %GITHUB_TOKEN:~0,5%",
	"awk 'BEGIN{print ENVIRON[1]}'", "perl -e 'print %ENV'", "node -e process.env",
}

var prefixes = []string{"nice ", "timeout 5 ", "stdbuf -oL ", "strace -f ", "chroot /r ", "ionice -c 3 ", "setsid ", "doas ", "xargs ", "", "cd /tmp && ", "true; ", "false || ", "x | ", "FOO=1 ", "sudo ", "sudo -E ", "env ", "command ", "exec ", "nohup ", "time ", "  ", "\t", "echo hi\n", "( ", "{ ", "! "}

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
