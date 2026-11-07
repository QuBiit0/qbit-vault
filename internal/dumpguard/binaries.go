package dumpguard

import (
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

var assignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

var (
	shellNames  = set("sh", "bash", "zsh", "dash", "ksh", "ash", "fish")
	psNames     = set("pwsh", "powershell")
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
		// Options may precede -c: `-o NAME` and `+o NAME` (and bash's -O/+O)
		// and `--rcfile FILE`/`--init-file FILE` take a value, other `--long`
		// options (and `--opt=value`) stand alone, and the first short
		// cluster that contains c takes the next word as the script.
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "-o" || a == "+o" || a == "-O" || a == "+O":
				i++
			case a == "--rcfile" || a == "--init-file":
				i++
			case strings.HasPrefix(a, "--"):
			case len(a) >= 2 && (a[0] == '-' || a[0] == '+'):
				if a[0] == '-' && strings.Contains(a, "c") && i+1 < len(args) {
					return args[i+1], true
				}
			default:
				return "", false
			}
		}
	case psNames[name]:
		// PowerShell resolves -c and every longer prefix of -Command to it;
		// -ConfigurationName and -CustomPipeName are other options.
		for i, a := range args {
			if f, joined, ok := psOption(a); ok && !joined && strings.HasPrefix("command", f) && i+1 < len(args) {
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

// psValued are the PowerShell options that take a value; psSwitches are the
// ones that do not. PowerShell accepts any unique prefix of an option name.
var (
	psValued = []string{"executionpolicy", "windowstyle", "inputformat", "outputformat", "version",
		"configurationname", "configurationfile", "custompipename", "workingdirectory", "settingsfile", "encodedarguments"}
	psSwitches = []string{"noprofile", "nologo", "noexit", "noninteractive", "interactive", "mta", "sta"}
)

// psOption splits a PowerShell option word into its lowercase name and
// whether it carries its value after a colon (-Opt:Value). PowerShell accepts
// -, / and the typographic dashes as the prefix.
func psOption(a string) (name string, joined, ok bool) {
	r, n := utf8.DecodeRuneInString(a)
	switch r {
	case '-', '/', '–', '—', '―':
	default:
		return "", false, false
	}
	name = strings.ToLower(a[n:])
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name, joined = name[:i], true
	}
	return name, joined, name != ""
}

// psTakesValue reports whether option name consumes the next word. A prefix
// that could also start a switch (-i, -s) is treated as a switch: not
// skipping a value only makes the guard look at one more word.
func psTakesValue(name string) bool {
	if name == "ep" || name == "wd" {
		return true
	}
	for _, sw := range psSwitches {
		if strings.HasPrefix(sw, name) {
			return false
		}
	}
	for _, v := range psValued {
		if strings.HasPrefix(v, name) {
			return true
		}
	}
	return false
}

// encodedPowerShell reports whether w runs pwsh/powershell with an encoded
// command (-e, -ec, -en, -enc, ... -encodedcommand, any case, -, / or a
// typographic dash prefix, -e:VALUE too): the script is base64 and cannot be
// inspected. Only the options before the command or file are read. A known
// valued option is skipped with its value, so a value that looks like -File
// or -Command (-WorkingDirectory /f) does not end the scan; any other word
// that is not an option is skipped too.
func encodedPowerShell(w []string) bool {
	idx, bare := resolve(w)
	if idx < 0 || bare || !psNames[strings.ToLower(baseName(w[idx]))] {
		return false
	}
	return EncodedPowerShellArgs(w[idx+1:])
}

// EncodedPowerShellArgs is encodedPowerShell on the arguments after the
// program name.
func EncodedPowerShellArgs(args []string) bool {
	for i := 0; i < len(args); i++ {
		f, joined, ok := psOption(args[i])
		if !ok {
			continue
		}
		switch {
		case f == "ec" || strings.HasPrefix("encodedcommand", f):
			return true
		case strings.HasPrefix("command", f) || strings.HasPrefix("file", f):
			return false
		case !joined && psTakesValue(f):
			i++
		}
	}
	return false
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
