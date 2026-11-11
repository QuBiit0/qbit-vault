package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/qbitdevz/qbit-vault/internal/filemerge"
	"github.com/qbitdevz/qbit-vault/internal/hosts"
)

// hooksTimeout is the seconds Codex gives a qbit-vault hook; both open the
// vault without prompting. Codex' own default is 600.
const hooksTimeout = 30

// ErrHookPath: the qbit-vault executable path cannot be written into a Codex
// hook command (it is not valid UTF-8 or holds a NUL, so hooks.json cannot
// carry it). init, sync and doctor report it by name; the Codex output guard
// is then not installed.
var ErrHookPath = errors.New("codex: the qbit-vault executable path cannot be written into a hook command")

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

// ExecutableProblem is read-only and says, for `doctor`, why the Codex hooks
// cannot be registered with the running executable: the empty string when
// they can.
func (a *Adapter) ExecutableProblem(hosts.Env) string {
	exe, err := a.executable()
	if err != nil {
		return ""
	}
	if _, err := hookEdits(exe); errors.Is(err, ErrHookPath) {
		return "the qbit-vault path cannot be written into a Codex hook command (not valid UTF-8), so the output guard is not installed; reinstall qbit-vault in another folder and run 'qbit-vault sync'"
	}
	return ""
}

type hookCommand struct {
	Type           string `json:"type"`
	Command        string `json:"command"`
	CommandWindows string `json:"commandWindows"`
	Timeout        int    `json:"timeout"`
	StatusMessage  string `json:"statusMessage"`
}

type hookEntry struct {
	Matcher string        `json:"matcher"`
	Hooks   []hookCommand `json:"hooks"`
}

// hookEdits owns one array element per hook. The marker is the statusMessage
// (`qbit-vault hook <sub>`), which Codex shows while the hook runs, so the
// element is found again whatever the binary is called. Codex hooks take a
// shell command line, not an argv, and `commandWindows` overrides `command`
// on Windows, so the executable is written once as a word of an sh command
// line and once as a PowerShell call (posixWord, powershellCall).
func hookEdits(exe string) ([]filemerge.JSONEdit, error) {
	if !utf8.ValidString(exe) || strings.ContainsRune(exe, 0) {
		return nil, ErrHookPath
	}
	defs := []struct{ event, matcher, sub string }{
		{"PostToolUse", "Bash", "post-bash"},
		{"PreToolUse", "apply_patch", "pre-write"},
	}
	var edits []filemerge.JSONEdit
	for _, d := range defs {
		marker := "qbit-vault hook " + d.sub
		args := " hook " + d.sub + " --host codex"
		edits = append(edits, filemerge.JSONEdit{
			Path:   []string{"hooks", d.event},
			Marker: marker,
			Value: marshal(hookEntry{Matcher: d.matcher, Hooks: []hookCommand{{
				Type: "command", Command: posixWord(exe) + args, CommandWindows: powershellCall(exe) + args,
				Timeout: hooksTimeout, StatusMessage: marker,
			}}}),
		})
	}
	return edits, nil
}

// posixWord renders the executable path as one word of an sh command line:
// bare when it has only characters sh reads literally, else in single quotes,
// inside which only the quote itself needs an escape (close the quote, an
// escaped quote, reopen). Backslashes stay as they are (literal in single
// quotes), so a Windows path survives.
func posixWord(exe string) string {
	plain := exe != ""
	for _, r := range exe {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+:@=,", r)) {
			plain = false
			break
		}
	}
	if plain {
		return exe
	}
	return "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
}

// powershellCall renders the executable path as a PowerShell call: the call
// operator and a single-quoted string, which takes everything literally ($,
// backtick, %, &, parentheses) except the quote characters. PowerShell reads
// the typographic single quotes U+2018 to U+201B as quotes too, so each is
// doubled like the ASCII one.
func powershellCall(exe string) string {
	var b strings.Builder
	b.WriteString("& '")
	for _, r := range exe {
		b.WriteRune(r)
		if r == '\'' || r >= '\u2018' && r <= '\u201b' {
			b.WriteRune(r)
		}
	}
	b.WriteString("'")
	return b.String()
}

// marshal is json.Marshal without HTML escaping.
func marshal(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}
