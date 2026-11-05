package dumpguard

import (
	"regexp"
	"runtime"
	"strings"
)

var assignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

var (
	shellNames  = set("sh", "bash", "zsh", "dash", "ksh", "ash", "fish")
	psNames     = set("pwsh", "powershell")
	psCmdFlags  = set("-c", "-command")
	cmdExeFlags = set("/c", "/k")
)

func set(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// afterPositional skips one positional word at i (the duration of `timeout`,
// the new root of `chroot`).
func afterPositional(w []string, i int) int {
	if i < len(w) {
		return i + 1
	}
	return i
}

func skipAssign(w []string, i int) int {
	for i < len(w) && assignRE.MatchString(w[i]) {
		i++
	}
	return i
}

// baseName is the last path element, split on / and \, without a .exe, .cmd
// or .bat extension and without a trailing @version (npx pkg@1.2).
func baseName(word string) string {
	if i := strings.LastIndexAny(word, `/\`); i >= 0 {
		word = word[i+1:]
	}
	if i := strings.LastIndexByte(word, '@'); i > 0 {
		word = word[:i]
	}
	low := strings.ToLower(word)
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		if strings.HasSuffix(low, ext) {
			return word[:len(word)-len(ext)]
		}
	}
	return word
}

// scriptOf returns the script text of `sh -c '...'`, `pwsh -Command ...`,
// `cmd /c ...` and `eval ...`.
func scriptOf(w []string) (string, bool) {
	idx, bare := resolve(w)
	if idx < 0 || bare {
		return "", false
	}
	name := strings.ToLower(baseName(w[idx]))
	args := w[idx+1:]
	switch {
	case name == "eval":
		if len(args) == 0 {
			return "", false
		}
		return strings.Join(args, " "), true
	case shellNames[name]:
		for i, a := range args {
			if len(a) < 2 || a[0] != '-' || a[1] == '-' {
				return "", false
			}
			if strings.Contains(a, "c") && i+1 < len(args) {
				return args[i+1], true
			}
		}
	case psNames[name]:
		for i, a := range args {
			if psCmdFlags[strings.ToLower(a)] && i+1 < len(args) {
				return strings.Join(args[i+1:], " "), true
			}
		}
	case name == "cmd":
		for i, a := range args {
			if cmdExeFlags[strings.ToLower(a)] && i+1 < len(args) {
				return strings.Join(args[i+1:], " "), true
			}
		}
	}
	return "", false
}

// ProgramName is the name a program is compared by: its base name without a
// directory, .exe/.cmd/.bat extension or @version, lowercased on Windows. The
// allowlist of a secret and Binaries use the same rule.
func ProgramName(word string) string {
	name := baseName(word)
	if runtime.GOOS == "windows" {
		name = strings.ToLower(name)
	}
	return name
}

// Binaries returns the program base name of every segment, in order and
// without duplicates, after resolving wrappers (sudo, env, command, exec,
// nohup, setsid, nice, timeout, stdbuf, strace, chroot, ionice, doas, xargs, time, npx, pnpm exec/dlx, yarn dlx, bunx, uv run, uvx, poetry run)
// and leading VAR=val assignments. Directories and .exe/.cmd/.bat are
// stripped; names are lowercased on Windows. A segment whose wrapper flags
// cannot be parsed with certainty is listed as Ambiguous. `sh -c` and `eval` scripts are
// transparent: their own segments are listed instead of the shell.
func Binaries(cmd string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range Segments(cmd) {
		if s.script {
			continue
		}
		idx, _, amb := resolveAmbiguity(s.Words)
		if idx < 0 {
			continue
		}
		name := ProgramName(s.Words[idx])
		if amb {
			name = Ambiguous
		}
		if name == "" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// Characters that let cmd.exe or PowerShell chain, start or substitute a
// command. Segments follows POSIX grammar, so for these shells the allowlist
// accepts only a command free of all of them (F1).
const (
	cmdMeta  = "&|<>^%!()\"\n\r"
	pwshMeta = ";&|<>`$(){}@\"'\n\r"
)

// SimpleProgram returns the program of cmd for shell "cmd" or "pwsh" when cmd
// is one simple command: no metacharacter that shell can use to chain, start
// or substitute another command. ok is false otherwise, for an empty command
// and for any other shell. Wrappers are not resolved: the first word is the
// program, so a wrapper has to be allowlisted itself.
func SimpleProgram(shell, cmd string) (program string, ok bool) {
	var meta string
	switch shell {
	case "cmd":
		meta = cmdMeta
	case "pwsh":
		meta = pwshMeta
	default:
		return "", false
	}
	if strings.ContainsAny(cmd, meta) {
		return "", false
	}
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return "", false
	}
	name := ProgramName(f[0])
	return name, name != ""
}

// InvokesBare reports whether cmd runs, in any of its simple commands
// (including the scripts of `sh -c` and `eval`, wrappers resolved), a program
// typed as exactly one of names with no directory part: the case where the
// system, not the caller, decides which file runs. A wrapper whose flags
// cannot be parsed with certainty counts when any of its words is such a name.
func InvokesBare(cmd string, names ...string) bool {
	bare := func(w string) bool {
		for _, n := range names {
			if strings.EqualFold(strings.TrimSuffix(strings.ToLower(w), ".exe"), n) && !strings.ContainsAny(w, `/\`) {
				return true
			}
		}
		return false
	}
	for _, s := range Segments(cmd) {
		idx, _, amb := resolveAmbiguity(s.Words)
		if idx < 0 {
			continue
		}
		if !amb {
			if bare(s.Words[idx]) {
				return true
			}
			continue
		}
		for _, w := range s.Words {
			if bare(w) {
				return true
			}
		}
	}
	return false
}
