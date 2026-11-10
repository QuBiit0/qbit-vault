package hook

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/qbitdevz/qbit-vault/internal/dumpguard"
)

// DenyReason is the fixed refusal the agent reads. It never includes the
// command: the text of a refused command could be a pasted secret.
const DenyReason = "This qbit-vault command is user-only: ask the user to run it in their own terminal. The agent's shell cannot run it."

const (
	preToolUse = "PreToolUse"
	program    = "qbit-vault"
	maxDepth   = 8
)

// agentAllowed are the qbit-vault subcommands the agent may run in its own
// shell (docs/CLI.md): they read metadata or run a child with a grant, and
// never prompt, mutate the vault or print a value. Everything else is
// refused, including unknown names, so a new command is user-only until it is
// added here on purpose.
var agentAllowed = map[string]bool{
	"version": true, "help": true, "list": true, "describe": true,
	"grants": true, "audit": true, "doctor": true,
}

// RunPreBash is `qbit-vault hook pre-bash`.
func RunPreBash(in io.Reader, out, errOut io.Writer) int {
	return Run(in, out, errOut, preToolUse, PreBash)
}

// PreBash refuses user-only qbit-vault invocations in the agent's shell
// (ROADMAP 3.2, PRD R-SYNC-05). Any other command, and every allowed
// qbit-vault command, gets no answer at all so the host's own permission flow
// stays in charge; an explicit "allow" would skip the user's prompt.
//
// Rewriting commands that reference bound secrets into `qbit-vault exec`
// (R-EXEC-02) needs the vault's names and bindings and is not done here.
func PreBash(ev Event) (*Output, error) {
	if ev.ToolName != "Bash" && ev.ToolName != "PowerShell" {
		return nil, nil
	}
	var in struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(ev.ToolInput, &in); err != nil {
		return nil, err
	}
	if !Refuses(in.Command) {
		return nil, nil
	}
	return &Output{Specific: &Specific{
		HookEventName:            preToolUse,
		PermissionDecision:       "deny",
		PermissionDecisionReason: DenyReason,
	}}, nil
}

// Refuses reports whether the command line runs a qbit-vault subcommand the
// agent may not run. A line that mentions qbit-vault and cannot be parsed is
// refused: an unparseable line could hide an invocation.
func Refuses(command string) bool {
	return refusesLine(command, 0)
}

func refusesLine(line string, depth int) bool {
	cmds, ok := scan(line)
	if !ok {
		return mentions(line)
	}
	for _, w := range cmds {
		if refusesCommand(w, depth) {
			return true
		}
	}
	return false
}

func mentions(s ...string) bool {
	return strings.Contains(strings.ToLower(strings.Join(s, " ")), program)
}

var (
	assignRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	redirectRE = regexp.MustCompile(`^[0-9]*(>>?|<|>&|<&|&>)-?$`)
	attachedRE = regexp.MustCompile(`^[0-9]*(>>?|<|&>)[^&-]`)
)

// reserved words that can precede a command.
var reserved = map[string]bool{
	"{": true, "}": true, "!": true, "if": true, "then": true, "else": true,
	"elif": true, "fi": true, "do": true, "done": true, "while": true,
	"until": true, "case": true, "esac": true,
}

// wrappers run the rest of their arguments as a command; the value is the set
// of their options that take a separate value.
var wrappers = map[string]map[string]bool{
	"sudo":    set("-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "-R", "--user", "--group"),
	"doas":    set("-u", "-C"),
	"env":     set("-u", "-C", "-S", "--unset", "--chdir"),
	"exec":    set("-a"),
	"command": set(),
	"builtin": set(),
	"nohup":   set(),
	"time":    set("-f", "-o"),
	"nice":    set("-n"),
	"xargs":   set("-I", "-n", "-L", "-P", "-d", "-E", "-s", "-a"),
	"timeout": set("-s", "-k"),
}

// runners fetch and run a package: `npx [opts] qbit-vault[@v] args`.
var runners = map[string]bool{"npx": true, "bunx": true, "pnpx": true}

// packageManagers run a package through one of these subcommands.
var packageManagers = map[string]bool{"npm": true, "pnpm": true, "yarn": true, "bun": true}

var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"fish": true, "pwsh": true, "powershell": true, "cmd": true,
}

// indirect programs run text we cannot analyse: if they mention qbit-vault the
// line is refused.
var indirect = map[string]bool{
	"eval": true, "iex": true, "invoke-expression": true, "start-process": true,
	"saps": true, "invoke-command": true, "icm": true,
}

func set(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// baseName is the lower-cased program name without directory or Windows
// extension: `C:\bin\Qbit-Vault.EXE` and `./qbit-vault` are both qbit-vault.
func baseName(w string) string {
	if i := strings.LastIndexAny(w, `/\`); i >= 0 {
		w = w[i+1:]
	}
	w = strings.ToLower(w)
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		w = strings.TrimSuffix(w, ext)
	}
	return w
}

func refusesCommand(w []string, depth int) bool {
	if depth > maxDepth {
		return true
	}
	for len(w) > 0 {
		switch {
		case assignRE.MatchString(w[0]) || reserved[w[0]] || attachedRE.MatchString(w[0]):
			w = w[1:]
		case redirectRE.MatchString(w[0]):
			if len(w) < 2 {
				return false
			}
			w = w[2:]
		default:
			return refusesProgram(w, depth)
		}
	}
	return false
}

func refusesProgram(w []string, depth int) bool {
	prog, args := baseName(w[0]), w[1:]
	switch {
	case prog == program:
		return refusesQBitVault(args, depth)
	case wrappers[prog] != nil:
		return refusesCommand(skipOptions(args, wrappers[prog], prog == "timeout"), depth+1)
	case runners[prog]:
		return refusesRunner(args, depth)
	case packageManagers[prog]:
		if len(args) > 0 && (args[0] == "exec" || args[0] == "dlx" || args[0] == "x") {
			return refusesRunner(args[1:], depth)
		}
	case shells[prog]:
		if (prog == "pwsh" || prog == "powershell") && dumpguard.EncodedPowerShellArgs(args) {
			return true
		}
		for i, a := range args {
			if isCommandFlag(a) && i+1 < len(args) {
				if refusesLine(strings.Join(args[i+1:], " "), depth+1) {
					return true
				}
			}
		}
	case indirect[prog]:
		return mentions(args...)
	}
	return false
}

// skipOptions drops leading options (and the values of those in valued), and
// optionally one positional argument such as timeout's duration.
func skipOptions(args []string, valued map[string]bool, positional bool) []string {
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "--":
			args = args[1:]
			goto done
		case len(a) > 1 && a[0] == '-':
			if valued[a] && len(args) > 1 {
				args = args[2:]
			} else {
				args = args[1:]
			}
		default:
			goto done
		}
	}
done:
	if positional && len(args) > 0 {
		args = args[1:]
	}
	return args
}

// refusesRunner handles `npx -y qbit-vault@1.2.3 …`.
func refusesRunner(args []string, depth int) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" || a == "--call":
			return i+1 < len(args) && refusesLine(args[i+1], depth+1)
		case a == "-p" || a == "--package":
			i++
		case a == "--":
		case len(a) > 1 && a[0] == '-':
		default:
			name := a
			if at := strings.LastIndexByte(name, '@'); at > 0 {
				name = name[:at]
			}
			return refusesCommand(append([]string{name}, args[i+1:]...), depth+1)
		}
	}
	return false
}

// isCommandFlag reports shells' "run this string" flags: -c, -lc, -Command,
// /c, /k.
func isCommandFlag(a string) bool {
	l := strings.ToLower(a)
	if l == "/c" || l == "/k" {
		return true
	}
	if len(l) < 2 || l[0] != '-' || l[1] == '-' {
		return false
	}
	for _, r := range l[1:] {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return strings.Contains(l, "c")
}

// refusesQBitVault decides on a qbit-vault invocation from its arguments.
func refusesQBitVault(args []string, depth int) bool {
	i := 0
	for i < len(args) {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			break
		}
		name, _, hasValue := strings.Cut(a, "=")
		if (name == "--home" || name == "--session") && !hasValue {
			i += 2
		} else {
			i++
		}
	}
	if i >= len(args) {
		return false // bare, or only flags: usage, --help, --version
	}
	sub, rest := args[i], args[i+1:]
	switch {
	case agentAllowed[sub]:
		return false
	case sub == "exec":
		// The words after `--` are one command string for a shell: a vault
		// subcommand hidden in it is judged like one typed directly.
		for j, a := range rest {
			if a == "--" {
				return refusesLine(strings.Join(rest[j+1:], " "), depth+1)
			}
		}
		return false
	}
	return true
}
