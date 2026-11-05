// Package skill is the qbit-vault agent skill and the host step that keeps it
// installed (docs/AGENT_INTEGRATIONS.md § Agent skill). The skill tells the
// model when and how to use the broker's tools; it is embedded in the binary,
// so every release carries its own text and `sync` (run by the install
// scripts after an upgrade) rewrites an installed copy that differs. A copy
// that is already current is never written. The file is whole and ours,
// recognized by Marker; a file at that path without it is the user's and is
// refused, never replaced.
//
// Claude Code reads ~/.claude/skills; Codex and Pi both read the Agent Skills
// location ~/.agents/skills, so they share one file there (two copies would
// collide in Pi). A shared file is removed only when no other registered host
// still records it.
package skill

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/QuBiit0/qbit-vault/internal/filemerge"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// Content is the SKILL.md this build installs.
//
//go:embed SKILL.md
var Content []byte

// Marker identifies a skill file qbit-vault manages.
const Marker = "<!-- Managed by qbit-vault:"

// StepName keys the step's receipt in state.json.
const StepName = "skill"

const dirName = "qbit-vault"

var errNoUserHome = errors.New("skill: the user home directory is unknown")

// ClaudePath is ~/.claude/skills/qbit-vault/SKILL.md.
func ClaudePath(env hosts.Env) (string, error) { return under(env, ".claude") }

// AgentsPath is ~/.agents/skills/qbit-vault/SKILL.md, the Agent Skills user
// location that Codex and Pi read.
func AgentsPath(env hosts.Env) (string, error) { return under(env, ".agents") }

func under(env hosts.Env, root string) (string, error) {
	if env.UserHome == "" {
		return "", errNoUserHome
	}
	return filepath.Join(env.UserHome, root, "skills", dirName, "SKILL.md"), nil
}

// Step is the skill step of host, writing the skill at path.
func Step(host string, path func(hosts.Env) (string, error)) hosts.Step {
	return hosts.Step{
		Name: StepName,
		Apply: func(env hosts.Env, prev *filemerge.Receipt) (filemerge.Receipt, error) {
			p, err := path(env)
			if err != nil {
				return filemerge.Receipt{}, err
			}
			return filemerge.WriteOwnedFile(env.VaultHome, p, Content, Marker, prev)
		},
		Revert: func(env hosts.Env, r filemerge.Receipt) (filemerge.Outcome, error) {
			shared, err := sharedWith(env, host, r.Path)
			if err != nil {
				return "", err
			}
			if shared {
				return filemerge.Unchanged, nil
			}
			return filemerge.RemoveOwnedFile(env.VaultHome, r, Marker)
		},
		Check: func(env hosts.Env, _ filemerge.Receipt) error {
			p, err := path(env)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			switch {
			case errors.Is(err, os.ErrNotExist):
				return fmt.Errorf("%w: file is missing", hosts.ErrDrift)
			case err != nil:
				return errors.New("skill: cannot read the skill file")
			case !bytes.Equal(b, Content):
				return fmt.Errorf("%w: skill is out of date", hosts.ErrDrift)
			}
			return nil
		},
	}
}

// sharedWith reports whether a host other than host still records a skill
// receipt for path.
func sharedWith(env hosts.Env, host, path string) (bool, error) {
	all, err := vault.ReadHosts(env.VaultHome)
	if err != nil {
		return false, err
	}
	for name, h := range all {
		if name == host {
			continue
		}
		if r, ok := h.Receipts[StepName]; ok && filepath.Clean(r.Path) == filepath.Clean(path) {
			return true, nil
		}
	}
	return false, nil
}
