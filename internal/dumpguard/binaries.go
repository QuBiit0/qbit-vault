package dumpguard

import (
	"regexp"
	"runtime"
	"strings"
)

var assignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// flags of each wrapper that consume the following word.
var (
	sudoArgs    = set("-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t", "--user", "--group", "--host", "--prompt", "--chdir", "--chroot")
	envArgs     = set("-u", "--unset", "-C", "--chdir")
	execArgs    = set("-a")
	timeArgs    = set("-f", "-o", "--format", "--output")
	pkgArgs     = set("-p", "--package")
	pnpmArgs    = set("-C", "--dir", "-F", "--filter")
	yarnArgs    = set("--cwd")
	uvArgs      = set("--directory", "--project", "-p", "--python", "--env-file")
	uvRunArgs   = set("--with", "--with-requirements", "-p", "--python", "--directory", "--project", "--env-file", "--extra", "--group", "--package", "--from")
	poetryArgs  = set("-C", "--directory", "-P", "--project")
	niceArgs    = set("-n", "--adjustment")
	timeoutArgs = set("-s", "--signal", "-k", "--kill-after")
	stdbufArgs  = set("-i", "-o", "-e", "--input", "--output", "--error")
	straceArgs  = set("-o", "-e", "-p", "-s", "-u", "-E", "-a", "-b", "-P", "-S", "-I", "-X", "-O", "-U", "-z", "-Z")
	chrootArgs  = set("--userspec", "--groups")
	ionicArgs   = set("-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid")
	doasArgs    = set("-u", "-C", "-a")
	xargsArgs   = set("-I", "-n", "-P", "-d", "-a", "-L", "-s", "-E", "-J", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--max-lines", "--max-chars", "--eof")
	noArgs      = set()
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

// skipFlags advances past leading flags (and the values of those in withArg),
// stopping after `--` or at the first word that is not a flag.
func skipFlags(w []string, i int, withArg map[string]bool) int {
	for i < len(w) {
		a := w[i]
		if a == "--" {
			return i + 1
		}
		if len(a) < 2 || a[0] != '-' {
			return i
		}
		i++
		if withArg[a] && i < len(w) {
			i++
		}
	}
	return i
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

// wrapped returns the index where the wrapped command starts when the word at
// i is a wrapper (sudo, env, npx, ...); ok is false for anything else.
func wrapped(w []string, i int) (next int, ok bool) {
	switch strings.ToLower(baseName(w[i])) {
	case "sudo":
		return skipFlags(w, i+1, sudoArgs), true
	case "env":
		j := i + 1
		for {
			j = skipFlags(w, j, envArgs)
			k := skipAssign(w, j)
			if k == j {
				return j, true
			}
			j = k
		}
	case "command":
		if i+1 < len(w) && (w[i+1] == "-v" || w[i+1] == "-V") {
			return 0, false // a lookup, nothing runs
		}
		return skipFlags(w, i+1, noArgs), true
	case "exec":
		return skipFlags(w, i+1, execArgs), true
	case "nohup", "setsid":
		return skipFlags(w, i+1, noArgs), true
	case "nice":
		return skipFlags(w, i+1, niceArgs), true
	case "timeout":
		return afterPositional(w, skipFlags(w, i+1, timeoutArgs)), true // DURATION
	case "stdbuf":
		return skipFlags(w, i+1, stdbufArgs), true
	case "strace":
		return skipFlags(w, i+1, straceArgs), true
	case "chroot":
		return afterPositional(w, skipFlags(w, i+1, chrootArgs)), true // NEWROOT
	case "ionice":
		return skipFlags(w, i+1, ionicArgs), true
	case "doas":
		return skipFlags(w, i+1, doasArgs), true
	case "xargs":
		return skipFlags(w, i+1, xargsArgs), true
	case "time":
		return skipFlags(w, i+1, timeArgs), true
	case "npx", "bunx":
		return skipFlags(w, i+1, pkgArgs), true
	case "uvx":
		return skipFlags(w, i+1, uvRunArgs), true
	case "pnpm":
		j := skipFlags(w, i+1, pnpmArgs)
		if j < len(w) && (w[j] == "exec" || w[j] == "dlx") {
			return skipFlags(w, j+1, pkgArgs), true
		}
	case "yarn":
		j := skipFlags(w, i+1, yarnArgs)
		if j < len(w) && w[j] == "dlx" {
			return skipFlags(w, j+1, pkgArgs), true
		}
	case "uv":
		j := skipFlags(w, i+1, uvArgs)
		if j < len(w) && w[j] == "run" {
			return skipFlags(w, j+1, uvRunArgs), true
		}
		if j+1 < len(w) && w[j] == "tool" && w[j+1] == "run" {
			return skipFlags(w, j+2, uvRunArgs), true
		}
	case "poetry":
		j := skipFlags(w, i+1, poetryArgs)
		if j < len(w) && w[j] == "run" {
			return skipFlags(w, j+1, noArgs), true
		}
	}
	return 0, false
}

// resolve finds the program a segment runs after leading VAR=val assignments
// and wrappers. idx is -1 when nothing runs. bare is true when the program is
// a wrapper that was given no command (`env`, `env FOO=1`, `sudo`): it then
// runs as itself and its remaining words are not a command.
func resolve(w []string) (idx int, bare bool) {
	i := 0
	for {
		i = skipAssign(w, i)
		if i >= len(w) {
			return -1, false
		}
		next, ok := wrapped(w, i)
		if !ok {
			return i, false
		}
		if next >= len(w) {
			return i, true
		}
		i = next
	}
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
// stripped; names are lowercased on Windows. `sh -c` and `eval` scripts are
// transparent: their own segments are listed instead of the shell.
func Binaries(cmd string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range Segments(cmd) {
		if s.script {
			continue
		}
		idx, _ := resolve(s.Words)
		if idx < 0 {
			continue
		}
		name := ProgramName(s.Words[idx])
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
