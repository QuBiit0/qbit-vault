// Package claude is the Claude Code host adapter (docs/AGENT_INTEGRATIONS.md
// § Registration written by init, PRD R-HOST-02, R-INS-05). Three steps, each
// an edit of one JSON file through internal/filemerge:
//
//	mcp    ~/.claude.json            mcpServers.qbit-vault (user scope MCP server)
//	hooks  ~/.claude/settings.json   four hook entries running `qbit-vault hook …`
//	deny   ~/.claude/settings.json   permissions.deny entries for the vault home
//
// Claude Code keeps user-scoped MCP servers in ~/.claude.json, not in
// settings.json (https://code.claude.com/docs/en/mcp.md § User scope).
// Entries of other tools (Gentle AI hooks, the user's own servers and deny
// rules) are never touched or reordered. Nothing here reads a secret.
package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/QuBiit0/qbit-vault/internal/filemerge"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
)

// Name is the host name used by --agents, state.json and doctor.
const Name = "claude-code"

const (
	serverName  = "qbit-vault"
	hookMarker  = "qbit-vault hook"
	preTimeout  = 10 // seconds; the pre hook never opens the vault
	postTimeout = 30 // seconds; the other hooks open the vault without prompting
)

var errNoUserHome = errors.New("claude-code: the user home directory is unknown")

// Adapter registers qbit-vault with Claude Code.
type Adapter struct {
	exe      string
	lookPath func(string) (string, error)
}

// New returns the adapter for the running qbit-vault executable.
func New() *Adapter { return &Adapter{lookPath: exec.LookPath} }

// NewWithExe is New with a fixed executable path (tests).
func NewWithExe(exe string) *Adapter { return &Adapter{exe: exe, lookPath: exec.LookPath} }

// WithLookPath replaces the PATH lookup Detect uses (tests).
func (a *Adapter) WithLookPath(f func(string) (string, error)) *Adapter {
	a.lookPath = f
	return a
}

func (a *Adapter) Name() string { return Name }

// Detect is read-only: Claude Code looks installed when ~/.claude is a
// directory or a `claude` binary is on PATH.
func (a *Adapter) Detect(env hosts.Env) bool {
	if env.UserHome != "" {
		if fi, err := os.Stat(filepath.Join(env.UserHome, ".claude")); err == nil && fi.IsDir() {
			return true
		}
	}
	if a.lookPath != nil {
		if _, err := a.lookPath("claude"); err == nil {
			return true
		}
	}
	return false
}

// executable is the absolute, symlink-resolved path of the running binary.
func (a *Adapter) executable() (string, error) {
	exe := a.exe
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return "", errors.New("claude-code: cannot locate the qbit-vault executable")
		}
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
	}
	if !filepath.IsAbs(exe) && !strings.HasPrefix(exe, "/") {
		return "", errors.New("claude-code: the qbit-vault executable path is not absolute")
	}
	return exe, nil
}

// Steps lists mcp, hooks and deny, in that order.
func (a *Adapter) Steps(env hosts.Env) []hosts.Step {
	return []hosts.Step{
		a.step("mcp", claudeJSONPath, a.mcpEdits),
		a.step("hooks", settingsPath, a.hookEdits),
		a.step("deny", settingsPath, denyEdits),
	}
}

func claudeJSONPath(env hosts.Env) (string, error) { return userFile(env, ".claude.json") }
func settingsPath(env hosts.Env) (string, error) {
	return userFile(env, filepath.Join(".claude", "settings.json"))
}

func userFile(env hosts.Env, rel string) (string, error) {
	if env.UserHome == "" {
		return "", errNoUserHome
	}
	return filepath.Join(env.UserHome, rel), nil
}

func (a *Adapter) step(name string, path func(hosts.Env) (string, error), edits func(hosts.Env) ([]filemerge.JSONEdit, error)) hosts.Step {
	prepare := func(env hosts.Env) (string, []filemerge.JSONEdit, error) {
		p, err := path(env)
		if err != nil {
			return "", nil, err
		}
		e, err := edits(env)
		return p, e, err
	}
	return hosts.Step{
		Name: name,
		Apply: func(env hosts.Env, prev *filemerge.Receipt) (filemerge.Receipt, error) {
			p, e, err := prepare(env)
			if err != nil {
				return filemerge.Receipt{}, err
			}
			return filemerge.MergeJSONFile(env.VaultHome, p, e, prev)
		},
		Revert: func(env hosts.Env, r filemerge.Receipt) (filemerge.Outcome, error) {
			_, e, err := prepare(env)
			if err != nil {
				return "", err
			}
			return filemerge.RevertJSONFile(env.VaultHome, r, e)
		},
		Check: func(env hosts.Env, _ filemerge.Receipt) error {
			p, e, err := prepare(env)
			if err != nil {
				return err
			}
			return hosts.CheckJSON(p, e)
		},
	}
}

// marshal is json.Marshal without HTML escaping, so `&` in a path stays.
func marshal(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// ---- mcp ---------------------------------------------------------------

type mcpServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

func (a *Adapter) mcpEdits(env hosts.Env) ([]filemerge.JSONEdit, error) {
	exe, err := a.executable()
	if err != nil {
		return nil, err
	}
	s := mcpServer{Type: "stdio", Command: exe, Args: []string{"mcp"}}
	if env.UserHome != "" && filepath.Clean(env.VaultHome) != filepath.Join(env.UserHome, ".qbit-vault") {
		s.Env = map[string]string{"QBIT_VAULT_HOME": env.VaultHome}
	}
	return []filemerge.JSONEdit{{Path: []string{"mcpServers", serverName}, Value: marshal(s)}}, nil
}

// ---- hooks -------------------------------------------------------------

type hookCommand struct {
	Type          string   `json:"type"`
	Command       string   `json:"command"`
	Args          []string `json:"args"`
	Timeout       int      `json:"timeout"`
	StatusMessage string   `json:"statusMessage"`
}

type hookEntry struct {
	Matcher string        `json:"matcher,omitempty"`
	Hooks   []hookCommand `json:"hooks"`
}

// shellTools are the tools whose commands the hooks watch: Bash and
// PowerShell are separate tools, and on Windows without Git Bash only the
// latter exists.
const shellTools = "Bash|PowerShell"

// hookEdits owns one array element per hook. The element carries its marker
// (`qbit-vault hook <sub>`) in statusMessage, which Claude Code shows as the
// spinner text, because the command is in exec form (command = the binary,
// args = hook, <sub>), which is the only form that survives spaces in a
// Windows path without quoting.
func (a *Adapter) hookEdits(hosts.Env) ([]filemerge.JSONEdit, error) {
	exe, err := a.executable()
	if err != nil {
		return nil, err
	}
	defs := []struct{ event, matcher, sub string }{
		{"PreToolUse", shellTools, "pre-bash"},
		{"PostToolUse", shellTools, "post-bash"},
		{"PostToolUse", "Read", "post-read"},
		{"UserPromptSubmit", "", "user-prompt"},
	}
	var edits []filemerge.JSONEdit
	for _, d := range defs {
		marker := hookMarker + " " + d.sub
		timeout := postTimeout
		if d.sub == "pre-bash" {
			timeout = preTimeout
		}
		edits = append(edits, filemerge.JSONEdit{
			Path:   []string{"hooks", d.event},
			Marker: marker,
			Value: marshal(hookEntry{Matcher: d.matcher, Hooks: []hookCommand{{
				Type: "command", Command: exe, Args: []string{"hook", d.sub}, Timeout: timeout, StatusMessage: marker,
			}}}),
		})
	}
	return edits, nil
}

// ---- deny --------------------------------------------------------------

// denyEdits keeps the model away from the vault directory: Read rules also
// cover cat/head/tail in Bash, Edit rules cover every write tool (Write
// rules never match in Claude Code). Each entry is owned by its full string.
func denyEdits(env hosts.Env) ([]filemerge.JSONEdit, error) {
	home, err := denyPath(env.VaultHome)
	if err != nil {
		return nil, err
	}
	var edits []filemerge.JSONEdit
	for _, tool := range []string{"Read", "Edit"} {
		rule := tool + "(" + home + "/**)"
		edits = append(edits, filemerge.JSONEdit{Path: []string{"permissions", "deny"}, Marker: rule, Value: marshal(rule)})
	}
	return edits, nil
}

// denyPath renders an absolute directory the way Claude Code permission
// rules want it (https://code.claude.com/docs/en/permissions.md § How path
// patterns match): `//` plus the POSIX path, and on Windows C:\Users\a
// becomes //c/Users/a. A single leading slash would anchor at ~/.claude.
func denyPath(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("claude-code: the vault home is unknown")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", errors.New("claude-code: cannot resolve the vault home")
	}
	p := filepath.ToSlash(filepath.Clean(abs))
	switch {
	case len(p) > 1 && p[1] == ':':
		p = "/" + strings.ToLower(p[:1]) + p[2:]
	case strings.HasPrefix(p, "//"):
		return "", errors.New("claude-code: a network path cannot be a vault home")
	}
	return "/" + strings.TrimSuffix(p, "/"), nil
}
