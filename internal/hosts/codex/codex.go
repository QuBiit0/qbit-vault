// Package codex is the Codex host adapter (docs/AGENT_INTEGRATIONS.md § Codex,
// PRD R-HOST-03). Two steps through internal/filemerge:
//
//	mcp    ~/.codex/config.toml  [mcp_servers.qbit-vault] (+ its env subtable)
//	skill  ~/.agents/skills/qbit-vault/SKILL.md  the agent skill, shared with Pi
//	       (Codex reads user skills from ~/.agents/skills; internal/hosts/skill)
//
// Codex keeps MCP servers in `[mcp_servers.<name>]` tables of config.toml with
// the keys command, args and env (https://developers.openai.com/codex/mcp
// § Configure with config.toml, checked 2026-11-04). Only our table is
// edited, as text; every other byte of the user's file stays identical.
// Nothing here reads a secret.
//
// Limitation: Codex relocates its config when CODEX_HOME is set, and
// hosts.Env does not carry it, so the adapter always uses <UserHome>/.codex.
package codex

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/QuBiit0/qbit-vault/internal/filemerge"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/hosts/skill"
)

// Name is the host name used by --agents, state.json and doctor.
const Name = "codex"

const table = "mcp_servers.qbit-vault"

var errNoUserHome = errors.New("codex: the user home directory is unknown")

// Adapter registers qbit-vault with Codex.
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

// Detect is read-only: Codex looks installed when ~/.codex is a directory or
// a `codex` binary is on PATH.
func (a *Adapter) Detect(env hosts.Env) bool {
	if env.UserHome != "" {
		if fi, err := os.Stat(filepath.Join(env.UserHome, ".codex")); err == nil && fi.IsDir() {
			return true
		}
	}
	if a.lookPath != nil {
		if _, err := a.lookPath("codex"); err == nil {
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
			return "", errors.New("codex: cannot locate the qbit-vault executable")
		}
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
	}
	if !filepath.IsAbs(exe) && !strings.HasPrefix(exe, "/") {
		return "", errors.New("codex: the qbit-vault executable path is not absolute")
	}
	return exe, nil
}

// Steps lists mcp and skill.
func (a *Adapter) Steps(hosts.Env) []hosts.Step {
	prepare := func(env hosts.Env) (path, block string, err error) {
		if env.UserHome == "" {
			return "", "", errNoUserHome
		}
		exe, err := a.executable()
		if err != nil {
			return "", "", err
		}
		return filepath.Join(env.UserHome, ".codex", "config.toml"), mcpBlock(env, exe), nil
	}
	return []hosts.Step{{
		Name: "mcp",
		Apply: func(env hosts.Env, prev *filemerge.Receipt) (filemerge.Receipt, error) {
			p, b, err := prepare(env)
			if err != nil {
				return filemerge.Receipt{}, err
			}
			return filemerge.MergeTOMLFile(env.VaultHome, p, table, b, prev)
		},
		Revert: func(env hosts.Env, r filemerge.Receipt) (filemerge.Outcome, error) {
			if _, _, err := prepare(env); err != nil {
				return "", err
			}
			return filemerge.RevertTOMLFile(env.VaultHome, r, table)
		},
		Check: func(env hosts.Env, _ filemerge.Receipt) error {
			p, b, err := prepare(env)
			if err != nil {
				return err
			}
			return hosts.CheckTOML(p, table, b)
		},
	}, skill.Step(Name, skill.AgentsPath)}
}

// mcpBlock is the text of our table. QBIT_VAULT_HOME is set only for a vault
// home other than the default, as in the Claude Code entry. The prompt
// backend is left to auto-selection (see docs/AGENT_INTEGRATIONS.md).
func mcpBlock(env hosts.Env, exe string) string {
	var b strings.Builder
	b.WriteString("[mcp_servers.qbit-vault]\n")
	b.WriteString("command = " + quote(exe) + "\n")
	b.WriteString("args = [\"mcp\"]\n")
	if filepath.Clean(env.VaultHome) != filepath.Join(env.UserHome, ".qbit-vault") {
		b.WriteString("\n[mcp_servers.qbit-vault.env]\n")
		b.WriteString("QBIT_VAULT_HOME = " + quote(env.VaultHome) + "\n")
	}
	return b.String()
}

// quote renders s as a TOML basic string: backslash, quote and control
// characters are escaped, everything else (UTF-8 included) is literal.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\u` + strings.ToUpper(leftPad(strconv.FormatInt(int64(r), 16))))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func leftPad(h string) string { return strings.Repeat("0", 4-len(h)) + h }
