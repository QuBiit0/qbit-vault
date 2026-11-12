// Package pi is the Pi / Gentle Shell host adapter (docs/AGENT_INTEGRATIONS.md
// § Pi / Gentle Shell, PRD R-HOST-01). Two steps through internal/filemerge:
//
//	mcp    <Pi agent dir>/mcp.json  mcpServers.qbit-vault
//	skill  ~/.agents/skills/qbit-vault/SKILL.md  the agent skill, shared with
//	       Codex (Pi reads ~/.agents/skills too; internal/hosts/skill)
//
// Pi 0.99 and later connects MCP servers natively and reads user-level ones
// from `<agent dir>/mcp.json`, a top-level `mcpServers` object whose stdio
// entries use command, args and env (https://github.com/badlogic/pi-mono
// packages/coding-agent/docs/mcp.md, checked 2026-11-04). The agent dir is
// `~/.pi/agent` unless PI_CODING_AGENT_DIR overrides it
// (docs/environment-variables.md, same source). Only our entry is edited; the
// rest of the user's file stays byte for byte as it was.
//
// The rich path (/vault commands, footer status, paste interception) is the
// qbit-vault-pi extension. Installing it needs the network, so init never does
// it: init and sync only print its install command as a suggestion.
// Nothing here reads a secret.
package pi

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/qbitdevz/qbit-vault/internal/filemerge"
	"github.com/qbitdevz/qbit-vault/internal/hosts"
	"github.com/qbitdevz/qbit-vault/internal/hosts/skill"
)

// Name is the host name used by --agents, state.json and doctor.
const Name = "pi"

// The extension is distributed as an immutable git tag of this repository, not
// on npm (odd/tasks/pi-extension.md S12): the tag pi-v<ExtensionVersion> holds
// only the built package. A test keeps ExtensionVersion equal to the version
// in packages/qbit-vault-pi/package.json.
const (
	ExtensionVersion = "0.2.2"
	ExtensionSource  = "git:github.com/qbitdevz/qbit-vault@pi-v" + ExtensionVersion
)

// ExtensionInstallCommand and ExtensionInstallCommandPi are what init and sync
// suggest for the user to run (Gentle Shell passes everything after `--` to
// Pi). They are text only: qbit-vault never executes them (invariant 8).
const (
	ExtensionInstallCommand   = "gentle-shell -- install " + ExtensionSource
	ExtensionInstallCommandPi = "pi install " + ExtensionSource
)

const (
	serverName  = "qbit-vault"
	agentDirEnv = "PI_CODING_AGENT_DIR"
)

var errNoUserHome = errors.New("pi: the user home directory is unknown")

// Adapter registers qbit-vault with Pi.
type Adapter struct {
	exe      string
	lookPath func(string) (string, error)
	getenv   func(string) string
}

// New returns the adapter for the running qbit-vault executable.
func New() *Adapter { return &Adapter{lookPath: exec.LookPath, getenv: os.Getenv} }

// NewWithExe is New with a fixed executable path (tests).
func NewWithExe(exe string) *Adapter {
	return &Adapter{exe: exe, lookPath: exec.LookPath, getenv: os.Getenv}
}

// WithLookPath replaces the PATH lookup Detect uses (tests).
func (a *Adapter) WithLookPath(f func(string) (string, error)) *Adapter {
	a.lookPath = f
	return a
}

// WithGetenv replaces the environment lookup of PI_CODING_AGENT_DIR (tests).
// It is only ever asked for that one variable, a directory and not a secret.
func (a *Adapter) WithGetenv(f func(string) string) *Adapter {
	a.getenv = f
	return a
}

func (a *Adapter) Name() string { return Name }

// Detect is read-only: Pi looks installed when its agent directory exists,
// `~/.pi` is a directory, or a `pi` or `gentle-shell` binary is on PATH.
func (a *Adapter) Detect(env hosts.Env) bool {
	isDir := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && fi.IsDir()
	}
	if dir, err := a.agentDir(env); err == nil && isDir(dir) {
		return true
	}
	if env.UserHome != "" && isDir(filepath.Join(env.UserHome, ".pi")) {
		return true
	}
	if a.lookPath != nil {
		for _, bin := range []string{"pi", "gentle-shell"} {
			if _, err := a.lookPath(bin); err == nil {
				return true
			}
		}
	}
	return false
}

// agentDir is PI_CODING_AGENT_DIR when set (a leading `~` is the user home;
// a relative path is refused, it would depend on the working directory), else
// <UserHome>/.pi/agent.
func (a *Adapter) agentDir(env hosts.Env) (string, error) {
	if a.getenv != nil {
		if v := strings.TrimSpace(a.getenv(agentDirEnv)); v != "" {
			if v == "~" || strings.HasPrefix(v, "~/") || strings.HasPrefix(v, `~\`) {
				if env.UserHome == "" {
					return "", errNoUserHome
				}
				v = filepath.Join(env.UserHome, v[1:])
			}
			if !filepath.IsAbs(v) {
				return "", errors.New("pi: " + agentDirEnv + " is not an absolute path")
			}
			return filepath.Clean(v), nil
		}
	}
	if env.UserHome == "" {
		return "", errNoUserHome
	}
	return filepath.Join(env.UserHome, ".pi", "agent"), nil
}

// executable is the absolute, symlink-resolved path of the running binary.
func (a *Adapter) executable() (string, error) {
	exe := a.exe
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return "", errors.New("pi: cannot locate the qbit-vault executable")
		}
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
	}
	if !filepath.IsAbs(exe) && !strings.HasPrefix(exe, "/") {
		return "", errors.New("pi: the qbit-vault executable path is not absolute")
	}
	return exe, nil
}

type mcpServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// Steps lists mcp and skill.
func (a *Adapter) Steps(hosts.Env) []hosts.Step {
	prepare := func(env hosts.Env) (string, []filemerge.JSONEdit, error) {
		dir, err := a.agentDir(env)
		if err != nil {
			return "", nil, err
		}
		exe, err := a.executable()
		if err != nil {
			return "", nil, err
		}
		s := mcpServer{Command: exe, Args: []string{"mcp"}}
		if env.UserHome != "" && filepath.Clean(env.VaultHome) != filepath.Join(env.UserHome, ".qbit-vault") {
			// Pi expands ${VAR} and a leading ! (a command) in env values.
			if strings.Contains(env.VaultHome, "${") || strings.HasPrefix(env.VaultHome, "!") {
				return "", nil, errors.New("pi: the vault home path would be expanded by Pi's mcp.json env syntax")
			}
			s.Env = map[string]string{"QBIT_VAULT_HOME": env.VaultHome}
		}
		return filepath.Join(dir, "mcp.json"), []filemerge.JSONEdit{{Path: []string{"mcpServers", serverName}, Value: marshal(s)}}, nil
	}
	return []hosts.Step{{
		Name: "mcp",
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
	}, skill.Step(Name, skill.AgentsPath)}
}

// marshal is json.Marshal without HTML escaping, so `&` in a path stays.
func marshal(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}
