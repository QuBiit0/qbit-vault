package dumpguard

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func texts(cmd string) []string {
	var out []string
	for _, s := range Segments(cmd) {
		out = append(out, s.Text)
	}
	return out
}

func TestSegments(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{"single", "ls -la", []string{"ls -la"}},
		{"spaces and tabs normalized", "  ls \t -la   /tmp ", []string{"ls -la /tmp"}},
		{"pipe", "env | grep PATH", []string{"env", "grep PATH"}},
		{"or and and", "a || b && c", []string{"a", "b", "c"}},
		{"semicolon", "a; b ;c", []string{"a", "b", "c"}},
		{"background", "a & b", []string{"a", "b"}},
		{"newline", "a\nb", []string{"a", "b"}},
		{"stderr pipe", "a |& b", []string{"a", "b"}},
		{"single quotes keep operators", "echo 'a | b; c'", []string{"echo a | b; c"}},
		{"double quotes keep operators", `echo "a && b"`, []string{"echo a && b"}},
		{"quote removal", `"env"`, []string{"env"}},
		{"split quote removal", `e""n'v'`, []string{"env"}},
		{"backslash outside quotes", `e\nv`, []string{"env"}},
		{"escaped separator", `echo a\;b`, []string{"echo a;b"}},
		{"escaped quote in double", `echo "a\"b"`, []string{`echo a"b`}},
		{"single quote is literal backslash", `echo 'a\b'`, []string{`echo a\b`}},
		{"line continuation", "en\\\nv", []string{"env"}},
		{"comment", "env # dump it", []string{"env"}},
		{"hash inside word", "echo a#b", []string{"echo a#b"}},
		{"redirect out dropped", "env > /tmp/x", []string{"env"}},
		{"redirect fd dup dropped", "env 2>&1 | cat", []string{"env", "cat"}},
		{"redirect attached target", "env 2>/dev/null", []string{"env"}},
		{"redirect both", "env &> out", []string{"env"}},
		{"redirect append", "env >> out", []string{"env"}},
		{"here-string kept", `base64 <<< "$X"`, []string{"base64 <<< $X"}},
		{"quoted gt kept", `awk '$1 > 5'`, []string{"awk $1 > 5"}},
		{"subshell dollar", "echo $(env)", []string{"echo $(env)", "env"}},
		{"subshell in double quotes", `echo "x $(printenv) y"`, []string{"echo x $(printenv) y", "printenv"}},
		{"backticks", "echo `env`", []string{"echo `env`", "env"}},
		{"nested subshell", "a $(b $(c))", []string{"a $(b $(c))", "b $(c)", "c"}},
		{"subshell with operators", "x $(a | b)", []string{"x $(a | b)", "a", "b"}},
		{"single-quoted dollar paren is literal", `echo '$(env)'`, []string{"echo $(env)"}},
		{"group parens", "(env)", []string{"env"}},
		{"leading keywords", "if env; then true; fi", []string{"env", "true"}},
		{"brace group", "{ env; }", []string{"env"}},
		{"negation", "! env", []string{"env"}},
		{"sh -c recursion", `sh -c 'env | cat'`, []string{"sh -c env | cat", "env", "cat"}},
		{"bash -lc recursion", `bash -lc "printenv"`, []string{"bash -lc printenv", "printenv"}},
		{"eval recursion", `eval "env"`, []string{"eval env", "env"}},
		{"empty", "", nil},
		{"only separators", " ; | && ", nil},
		{"unterminated quote", `echo "abc`, []string{"echo abc"}},
		{"unterminated subshell", "echo $(env", []string{"echo $(env", "env"}},
		{"trailing backslash", `echo a\`, []string{`echo a\`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := texts(tt.cmd)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Segments(%q)\n got %q\nwant %q", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestSegmentsDepthLimitDoesNotPanic(t *testing.T) {
	cmd := "x"
	for i := 0; i < 200; i++ {
		cmd = "echo $(" + cmd + ")"
	}
	if len(Segments(cmd)) == 0 {
		t.Fatal("expected segments")
	}
}

func TestBinaries(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{"plain", "gh pr list", []string{"gh"}},
		{"path stripped", "/usr/local/bin/gh pr list", []string{"gh"}},
		{"windows path and ext", `"C:\Tools\gh.exe" pr list`, []string{"gh"}},
		{"cmd and bat ext", "tool.cmd x; other.bat y", []string{"tool", "other"}},
		{"assignments", "FOO=1 BAR=2 gh pr", []string{"gh"}},
		{"assignment only", "FOO=1", nil},
		{"sudo", "sudo gh pr", []string{"gh"}},
		{"sudo flags", "sudo -E -u root -n gh pr", []string{"gh"}},
		{"sudo double dash", "sudo -- gh pr", []string{"gh"}},
		{"env", "env gh pr", []string{"gh"}},
		{"env flags and assignments", "env -i -u HOME FOO=1 gh pr", []string{"gh"}},
		{"env alone is env", "env", []string{"env"}},
		{"env assignments alone", "env FOO=1", []string{"env"}},
		{"command", "command gh pr", []string{"gh"}},
		{"command -v is command", "command -v gh", []string{"command"}},
		{"exec", "exec gh pr", []string{"gh"}},
		{"nohup", "nohup gh pr", []string{"gh"}},
		{"time", "time -p gh pr", []string{"gh"}},
		{"npx", "npx --yes prettier --check .", []string{"prettier"}},
		{"npx versioned scoped", "npx @scope/pkg@1.2.3 run", []string{"pkg"}},
		{"bunx", "bunx cowsay hi", []string{"cowsay"}},
		{"pnpm exec", "pnpm exec eslint .", []string{"eslint"}},
		{"pnpm dlx", "pnpm dlx create-vite", []string{"create-vite"}},
		{"pnpm flags before exec", "pnpm -C app exec eslint .", []string{"eslint"}},
		{"pnpm other subcommand", "pnpm install", []string{"pnpm"}},
		{"yarn dlx", "yarn dlx tsc", []string{"tsc"}},
		{"yarn other", "yarn install", []string{"yarn"}},
		{"uv run", "uv run python x.py", []string{"python"}},
		{"uv run flags", "uv run --with rich -p 3.12 python x.py", []string{"python"}},
		{"uv other", "uv sync", []string{"uv"}},
		{"uvx", "uvx ruff check", []string{"ruff"}},
		{"poetry run", "poetry run pytest", []string{"pytest"}},
		{"poetry other", "poetry install", []string{"poetry"}},
		{"stacked wrappers", "sudo env FOO=1 nohup command npx -y tool", []string{"tool"}},
		{"pipeline", "gh pr list | jq . && curl x", []string{"gh", "jq", "curl"}},
		{"duplicates collapse", "gh a; gh b", []string{"gh"}},
		{"subshell", "gh x $(curl y)", []string{"gh", "curl"}},
		{"sh -c is transparent", `sh -c 'gh pr | curl x'`, []string{"gh", "curl"}},
		{"bash without -c is bash", "bash run.sh", []string{"bash"}},
		{"eval transparent", `eval "gh pr"`, []string{"gh"}},
		{"redirects do not hide", "gh pr > out.txt", []string{"gh"}},
		{"leading keyword", "if gh auth status; then curl x; fi", []string{"gh", "curl"}},
		{"nice", "nice -n 5 gh pr", []string{"gh"}},
		{"nice alone", "nice", []string{"nice"}},
		{"timeout", "timeout 5 gh pr", []string{"gh"}},
		{"timeout flags", "timeout -s KILL -k 2 5s curl x", []string{"curl"}},
		{"timeout alone", "timeout 5", []string{"timeout"}},
		{"stdbuf", "stdbuf -oL -e0 gh pr", []string{"gh"}},
		{"stdbuf separate arg", "stdbuf -o L gh pr", []string{"gh"}},
		{"strace", "strace -f -o /tmp/x -e trace=none curl x", []string{"curl"}},
		{"chroot", "chroot /newroot curl x", []string{"curl"}},
		{"chroot flags", "chroot --userspec u:g /newroot curl x", []string{"curl"}},
		{"ionice", "ionice -c 3 -n 7 curl x", []string{"curl"}},
		{"setsid", "setsid -w curl x", []string{"curl"}},
		{"doas", "doas -u root curl x", []string{"curl"}},
		{"xargs", "echo x | xargs -n1 -I {} curl {}", []string{"echo", "curl"}},
		{"xargs alone", "xargs", []string{"xargs"}},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Binaries(tt.cmd)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Binaries(%q)\n got %q\nwant %q", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestBinariesCaseFollowsPlatform(t *testing.T) {
	got := Binaries("GH.EXE pr")
	want := []string{"GH"}
	if runtime.GOOS == "windows" {
		want = []string{"gh"}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestProgramName(t *testing.T) {
	want := map[string]string{"gh": "gh", "/usr/bin/gh": "gh", "gh.exe": "gh", "Tool.CMD": "Tool", "pkg@1.2": "pkg"}
	for in, w := range want {
		if runtime.GOOS == "windows" {
			w = strings.ToLower(w)
		}
		if got := ProgramName(in); got != w {
			t.Errorf("ProgramName(%q) = %q, want %q", in, got, w)
		}
	}
}

func TestSimpleProgram(t *testing.T) {
	tests := []struct {
		name, shell, cmd string
		want             string
		ok               bool
	}{
		{"cmd plain", "cmd", "gh --version", "gh", true},
		{"cmd path", "cmd", `C:\Tools\gh.exe pr list`, "gh", true},
		{"pwsh plain", "pwsh", "gh pr list --json number", "gh", true},
		{"extra spaces", "cmd", "  gh   pr  ", "gh", true},
		{"empty", "cmd", "   ", "", false},
		{"cmd amp", "cmd", `gh x \& curl --version`, "", false},
		{"cmd pipe", "cmd", "gh --version | curl --version", "", false},
		{"cmd quote", "cmd", `gh "a\" & curl --version & \"b"`, "", false},
		{"pwsh semicolon", "pwsh", `gh "a\" ; curl --version ; \"b"`, "", false},
		{"cmd percent", "cmd", "gh %X%", "", false},
		{"cmd caret", "cmd", "gh ^& curl", "", false},
		{"cmd bang", "cmd", "gh !X!", "", false},
		{"cmd paren", "cmd", "gh (x)", "", false},
		{"cmd redirect", "cmd", "gh > f", "", false},
		{"cmd newline", "cmd", "gh\ncurl x", "", false},
		{"cmd cr", "cmd", "gh\rcurl x", "", false},
		{"pwsh amp", "pwsh", "gh & curl", "", false},
		{"pwsh backtick", "pwsh", "gh `n curl", "", false},
		{"pwsh dollar", "pwsh", "gh $x", "", false},
		{"pwsh brace", "pwsh", "gh {x}", "", false},
		{"pwsh at", "pwsh", "gh @x", "", false},
		{"pwsh single quote", "pwsh", "gh 'x'", "", false},
		{"pwsh newline", "pwsh", "gh\ncurl", "", false},
		{"cmd allows dollar", "cmd", "gh $x", "gh", true},
		{"cmd allows single quote", "cmd", "gh 'x'", "gh", true},
		{"unknown shell", "sh", "gh", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := SimpleProgram(tt.shell, tt.cmd)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("SimpleProgram(%q, %q) = %q, %v; want %q, %v", tt.shell, tt.cmd, got, ok, tt.want, tt.ok)
			}
		})
	}
}

// Flags a wrapper does not know make the segment ambiguous: Binaries returns
// a sentinel no allowlist can contain, so the allowlist refuses it.
func TestBinariesAmbiguousWrapperFlags(t *testing.T) {
	amb := []string{Ambiguous}
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{"strace cluster, value is next word", "strace -fo gh curl --version", []string{"curl"}},
		{"strace unknown cluster letter", "strace -fQ gh curl --version", amb},
		{"xargs cluster, -n takes the attached 1", "xargs -0n1 gh curl", []string{"gh"}},
		{"xargs cluster, value is next word", "xargs -0n 1 curl x", []string{"curl"}},
		{"xargs unknown cluster letter", "xargs -0Z gh curl", amb},
		{"timeout attached value", "timeout -sKILL 5 curl x", []string{"curl"}},
		{"timeout unknown flag", "timeout --frobnicate 5 curl x", amb},
		{"nice long with equals", "nice --adjustment=5 curl x", []string{"curl"}},
		{"nice unknown long", "nice --foo curl x", amb},
		{"sudo cluster", "sudo -Eu root curl x", []string{"curl"}},
		{"sudo unknown long flag", "sudo --foo bar curl x", amb},
		{"sudo unknown short flag", "sudo -Z gh curl x", amb},
		{"env split string", "env -S 'curl x' gh", amb},
		{"npx -c runs a shell", "npx -c 'curl x' gh", amb},
		{"pnpm unknown flag before exec", "pnpm --foo bar exec curl x", amb},
		{"known forms stay exact", "sudo -u root gh x", []string{"gh"}},
		{"timeout known", "timeout -s KILL 5 gh x", []string{"gh"}},
		{"nice known", "nice -n 5 gh x", []string{"gh"}},
		{"strace known", "strace -f -o out gh x", []string{"gh"}},
		{"strace attached", "strace -fo out gh x", []string{"gh"}},
		{"xargs known", "xargs -n1 gh", []string{"gh"}},
		{"xargs attached I", "xargs -I{} gh {}", []string{"gh"}},
		{"sudo equals form", "sudo --user=root gh x", []string{"gh"}},
		{"ambiguity in a later segment", "gh a; sudo --foo x curl", []string{"gh", Ambiguous}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Binaries(tt.cmd); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Binaries(%q)\n got %q\nwant %q", tt.cmd, got, tt.want)
			}
		})
	}
}
