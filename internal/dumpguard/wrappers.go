package dumpguard

import "strings"

// Ambiguous is what Binaries lists for a segment whose wrapper flags cannot
// be parsed with certainty. No allowlist can contain it, so every allowlist
// refuses the command (fail closed).
const Ambiguous = "?ambiguous"

// flagSet describes the flags a wrapper accepts before its command. A flag
// that is in neither set makes the parse ambiguous.
type flagSet struct {
	noArg map[string]bool // short flags as "-x", long flags as "--name"
	arg   map[string]bool // flags that take a value
}

func flags(noArg, arg []string) flagSet { return flagSet{set(noArg...), set(arg...)} }

var (
	sudoFlags = flags(
		[]string{"-A", "-B", "-b", "-E", "-H", "-i", "-K", "-k", "-n", "-P", "-S", "-s",
			"--askpass", "--background", "--login", "--non-interactive", "--reset-timestamp",
			"--set-home", "--shell", "--stdin", "--remove-timestamp", "--bell"},
		[]string{"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
			"--user", "--group", "--host", "--prompt", "--chdir", "--chroot"})
	envFlags     = flags([]string{"-i", "-0", "-v", "--ignore-environment", "--null"}, []string{"-u", "-C", "--unset", "--chdir"})
	commandFlags = flags([]string{"-p"}, nil)
	execFlags    = flags([]string{"-c", "-l"}, []string{"-a"})
	timeFlags    = flags([]string{"-p", "-v", "-a", "--portability", "--verbose", "--append"}, []string{"-f", "-o", "--format", "--output"})
	niceFlags    = flags(nil, []string{"-n", "--adjustment"})
	timeoutFlags = flags([]string{"-f", "-p", "-v", "--foreground", "--preserve-status", "--verbose"}, []string{"-s", "-k", "--signal", "--kill-after"})
	stdbufFlags  = flags(nil, []string{"-i", "-o", "-e", "--input", "--output", "--error"})
	straceFlags  = flags(
		[]string{"-c", "-C", "-D", "-f", "-F", "-i", "-k", "-n", "-q", "-r", "-t", "-T", "-v", "-w", "-x", "-y", "-z", "-Z"},
		[]string{"-o", "-e", "-p", "-s", "-u", "-E", "-a", "-b", "-P", "-S", "-I", "-X", "-O", "-U"})
	chrootFlags = flags([]string{"--skip-chdir"}, []string{"--userspec", "--groups"})
	ionicFlags  = flags([]string{"-t", "--ignore"}, []string{"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"})
	doasFlags   = flags([]string{"-n", "-s", "-L"}, []string{"-u", "-C", "-a"})
	xargsFlags  = flags(
		[]string{"-0", "-o", "-p", "-r", "-t", "-x", "--null", "--open-tty", "--interactive", "--no-run-if-empty", "--verbose", "--exit"},
		[]string{"-I", "-n", "-P", "-d", "-a", "-L", "-s", "-E", "-J", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--max-lines", "--max-chars", "--eof"})
	setsidFlags = flags([]string{"-c", "-f", "-w", "--ctty", "--fork", "--wait"}, nil)
	noFlags     = flags(nil, nil)
	pkgFlags    = flags([]string{"-y", "-q", "--yes", "--quiet", "--no", "--no-install", "--prefer-offline", "--ignore-existing"}, []string{"-p", "--package"})
	pnpmFlags   = flags([]string{"-r", "-s", "--recursive", "--silent", "--stream", "--parallel", "--workspace-root", "-w"}, []string{"-C", "--dir", "-F", "--filter"})
	yarnFlags   = flags([]string{"-q", "--quiet", "--silent"}, []string{"--cwd"})
	uvFlags     = flags([]string{"-q", "-v", "--quiet", "--verbose", "--no-cache", "--offline", "--native-tls", "--no-progress", "--no-config"}, []string{"--directory", "--project", "-p", "--python", "--env-file"})
	uvRunFlags  = flags(
		[]string{"--no-project", "--isolated", "--frozen", "--locked", "--no-sync", "--all-extras", "--no-dev", "--dev", "--offline", "-q", "-v", "--quiet", "--verbose", "--no-cache", "--active", "--exact", "--no-editable"},
		[]string{"--with", "--with-requirements", "-p", "--python", "--directory", "--project", "--env-file", "--extra", "--group", "--package", "--from"})
	poetryFlags = flags([]string{"-q", "-v", "-n", "--quiet", "--verbose", "--no-interaction", "--no-ansi", "--ansi", "--no-plugins"}, []string{"-C", "--directory", "-P", "--project"})
)

// skipFlags advances past the leading flags of a wrapper, stopping after `--`
// or at the first word that is not a flag. ambiguous is true when a flag is
// not described by fs, or a short-flag cluster cannot be read with certainty:
// every letter before the last must be a known no-argument flag, and the last
// letter a known no-argument flag or an argument-taking one, whose value is
// either attached (`-oVALUE`, `-sKILL`) or the next word.
func skipFlags(w []string, i int, fs flagSet) (next int, ambiguous bool) {
	for i < len(w) {
		a := w[i]
		if a == "--" {
			return i + 1, false
		}
		if len(a) < 2 || a[0] != '-' {
			return i, false
		}
		switch {
		case strings.HasPrefix(a, "--"):
			if name, _, hasValue := strings.Cut(a, "="); hasValue {
				if !fs.arg[name] {
					return len(w), true
				}
				i++
			} else if fs.noArg[a] {
				i++
			} else if fs.arg[a] {
				i += 2
			} else {
				return len(w), true
			}
		case fs.noArg[a]:
			i++
		case fs.arg[a]:
			i += 2
		default:
			n, ok := skipCluster(a, fs)
			if !ok {
				return len(w), true
			}
			i += n
		}
	}
	return min(i, len(w)), false
}

// skipCluster reads a short-flag cluster such as -fo or -sKILL and returns
// how many words it takes (1, or 2 when the last letter wants the next word).
func skipCluster(a string, fs flagSet) (words int, ok bool) {
	for j := 1; j < len(a); j++ {
		f := "-" + a[j:j+1]
		switch {
		case fs.noArg[f]:
		case fs.arg[f]:
			if j == len(a)-1 {
				return 2, true // the value is the next word
			}
			return 1, true // the rest of the cluster is the value
		default:
			return 0, false
		}
	}
	return 1, true
}

// wrapped returns the index where the wrapped command starts when the word at
// i is a wrapper (sudo, env, npx, ...); ok is false for anything else. When
// its flags cannot be parsed with certainty, ambiguous is true and next is
// len(w): nothing can be said about what runs.
func wrapped(w []string, i int) (next int, ok, ambiguous bool) {
	skip := func(j int, fs flagSet) (int, bool, bool) {
		n, amb := skipFlags(w, j, fs)
		return n, true, amb
	}
	switch strings.ToLower(baseName(w[i])) {
	case "sudo":
		return skip(i+1, sudoFlags)
	case "env":
		j := i + 1
		for {
			n, amb := skipFlags(w, j, envFlags)
			if amb {
				return n, true, true
			}
			k := skipAssign(w, n)
			if k == n {
				return n, true, false
			}
			j = k
		}
	case "command":
		if i+1 < len(w) && (w[i+1] == "-v" || w[i+1] == "-V") {
			return 0, false, false // a lookup, nothing runs
		}
		return skip(i+1, commandFlags)
	case "exec":
		return skip(i+1, execFlags)
	case "nohup":
		return skip(i+1, noFlags)
	case "setsid":
		return skip(i+1, setsidFlags)
	case "nice":
		return skip(i+1, niceFlags)
	case "timeout":
		n, _, amb := skip(i+1, timeoutFlags) // then DURATION
		return afterPositional(w, n), true, amb
	case "stdbuf":
		return skip(i+1, stdbufFlags)
	case "strace":
		return skip(i+1, straceFlags)
	case "chroot":
		n, _, amb := skip(i+1, chrootFlags) // then NEWROOT
		return afterPositional(w, n), true, amb
	case "ionice":
		return skip(i+1, ionicFlags)
	case "doas":
		return skip(i+1, doasFlags)
	case "xargs":
		return skip(i+1, xargsFlags)
	case "time":
		return skip(i+1, timeFlags)
	case "npx", "bunx":
		return skip(i+1, pkgFlags)
	case "uvx":
		return skip(i+1, uvRunFlags)
	case "pnpm":
		j, amb := skipFlags(w, i+1, pnpmFlags)
		if amb {
			return j, true, true
		}
		if j < len(w) && (w[j] == "exec" || w[j] == "dlx") {
			return skip(j+1, pkgFlags)
		}
	case "yarn":
		j, amb := skipFlags(w, i+1, yarnFlags)
		if amb {
			return j, true, true
		}
		if j < len(w) && w[j] == "dlx" {
			return skip(j+1, pkgFlags)
		}
	case "uv":
		j, amb := skipFlags(w, i+1, uvFlags)
		if amb {
			return j, true, true
		}
		if j < len(w) && w[j] == "run" {
			return skip(j+1, uvRunFlags)
		}
		if j+1 < len(w) && w[j] == "tool" && w[j+1] == "run" {
			return skip(j+2, uvRunFlags)
		}
	case "poetry":
		j, amb := skipFlags(w, i+1, poetryFlags)
		if amb {
			return j, true, true
		}
		if j < len(w) && w[j] == "run" {
			return skip(j+1, noFlags)
		}
	}
	return 0, false, false
}

// resolve finds the program a segment runs after leading VAR=val assignments
// and wrappers. idx is -1 when nothing runs. bare is true when the program is
// a wrapper that was given no command (`env`, `env FOO=1`, `sudo`): it then
// runs as itself and its remaining words are not a command.
func resolve(w []string) (idx int, bare bool) {
	idx, bare, _ = resolveAmbiguity(w)
	return idx, bare
}

// resolveAmbiguity is resolve that also reports a wrapper whose flags could
// not be parsed with certainty; idx is then that wrapper and bare is true.
func resolveAmbiguity(w []string) (idx int, bare, ambiguous bool) {
	i := 0
	for {
		i = skipAssign(w, i)
		if i >= len(w) {
			return -1, false, false
		}
		next, ok, amb := wrapped(w, i)
		if !ok {
			return i, false, false
		}
		if amb {
			return i, true, true
		}
		if next >= len(w) {
			return i, true, false
		}
		i = next
	}
}
