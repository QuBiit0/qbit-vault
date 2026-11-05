// Package fake is a host adapter for tests only: it registers a JSON entry in
// two files under a directory. No release registry includes it.
package fake

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/QuBiit0/qbit-vault/internal/filemerge"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
)

// Adapter is a fake host whose "installation" is the existence of Dir.
type Adapter struct {
	name string
	Dir  string
}

// New returns a fake host called name configured under dir.
func New(name, dir string) *Adapter { return &Adapter{name: name, Dir: dir} }

func (a *Adapter) Name() string { return a.name }

func (a *Adapter) Detect(hosts.Env) bool {
	fi, err := os.Stat(a.Dir)
	return err == nil && fi.IsDir()
}

func (a *Adapter) Steps(hosts.Env) []hosts.Step {
	return []hosts.Step{
		a.step("mcp", "config.json", []string{"mcpServers", "qbit-vault"}, `{"command":"qbit-vault","args":["mcp"]}`),
		a.step("hooks", "hooks.json", []string{"hooks", "qbit-vault"}, `{"command":"qbit-vault hook"}`),
	}
}

func (a *Adapter) step(name, file string, path []string, value string) hosts.Step {
	target := filepath.Join(a.Dir, file)
	edits := []filemerge.JSONEdit{{Path: path, Value: json.RawMessage(value)}}
	return hosts.Step{
		Name: name,
		Apply: func(env hosts.Env, prev *filemerge.Receipt) (filemerge.Receipt, error) {
			return filemerge.MergeJSONFile(env.VaultHome, target, edits, prev)
		},
		Revert: func(env hosts.Env, r filemerge.Receipt) (filemerge.Outcome, error) {
			return filemerge.RevertJSONFile(env.VaultHome, r, edits)
		},
		Check: func(_ hosts.Env, _ filemerge.Receipt) error { return hosts.CheckJSON(target, edits) },
	}
}
