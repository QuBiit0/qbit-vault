package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/qbitdevz/qbit-vault/internal/filemerge"
	"github.com/qbitdevz/qbit-vault/internal/hosts"
)

// hooksTimeout is the seconds Codex gives a qbit-vault hook; both open the
// vault without prompting. Codex' own default is 600.
const hooksTimeout = 30

// hooksPath is ~/.codex/hooks.json, one of the places Codex reads hooks from
// (https://learn.chatgpt.com/docs/hooks.md § Where Codex looks for hooks).
func hooksPath(env hosts.Env) (string, error) {
	if env.UserHome == "" {
		return "", errNoUserHome
	}
	return filepath.Join(env.UserHome, ".codex", "hooks.json"), nil
}

// hooksStep merges our two hook entries into hooks.json through
// internal/filemerge: snapshot first, atomic write, other tools' entries
// (Orca, the user's own) untouched, revert removing only ours.
func (a *Adapter) hooksStep() hosts.Step {
	prepare := func(env hosts.Env) (string, []filemerge.JSONEdit, error) {
		p, err := hooksPath(env)
		if err != nil {
			return "", nil, err
		}
		exe, err := a.executable()
		if err != nil {
			return "", nil, err
		}
		e, err := hookEdits(exe)
		return p, e, err
	}
	return hosts.Step{
		Name: "hooks",
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

type hookCommand struct {
	Type          string `json:"type"`
	Command       string `json:"command"`
	Timeout       int    `json:"timeout"`
	StatusMessage string `json:"statusMessage"`
}

type hookEntry struct {
	Matcher string        `json:"matcher"`
	Hooks   []hookCommand `json:"hooks"`
}

// hookEdits owns one array element per hook. The marker is the statusMessage
// (`qbit-vault hook <sub>`), which Codex shows while the hook runs, so the
// element is found again whatever the binary is called. Codex hooks take a
// shell command line, not an argv, so the executable is written as one word
// (shellWord).
func hookEdits(exe string) ([]filemerge.JSONEdit, error) {
	word, err := shellWord(exe)
	if err != nil {
		return nil, err
	}
	defs := []struct{ event, matcher, sub string }{
		{"PostToolUse", "Bash", "post-bash"},
		{"PreToolUse", "apply_patch", "pre-write"},
	}
	var edits []filemerge.JSONEdit
	for _, d := range defs {
		marker := "qbit-vault hook " + d.sub
		edits = append(edits, filemerge.JSONEdit{
			Path:   []string{"hooks", d.event},
			Marker: marker,
			Value: marshal(hookEntry{Matcher: d.matcher, Hooks: []hookCommand{{
				Type: "command", Command: word + " hook " + d.sub + " --host codex", Timeout: hooksTimeout, StatusMessage: marker,
			}}}),
		})
	}
	return edits, nil
}

// shellWord renders the executable path as one word of a command line that
// sh, cmd.exe and PowerShell all read the same way: forward slashes (a
// backslash is an escape in sh), bare when it has only plain characters,
// double-quoted when it has a space. A path with a character any of those
// shells treats as syntax inside double quotes is refused rather than
// guessed. Which shell Codex uses for hooks on Windows is not documented.
func shellWord(exe string) (string, error) {
	p := filepath.ToSlash(exe)
	if strings.ContainsAny(p, "\"$`%!^&|<>;'()\r\n\t\x00") {
		return "", errors.New("codex: the qbit-vault executable path has a character a hook command line cannot carry safely")
	}
	if strings.ContainsAny(p, " ") {
		return `"` + p + `"`, nil
	}
	return p, nil
}

// marshal is json.Marshal without HTML escaping.
func marshal(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}
