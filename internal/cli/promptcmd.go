package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/grants"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// maxReasonBytes bounds the reason a requester can put on the prompt.
const maxReasonBytes = 1024

// valueFD is the file descriptor the value of `prompt --value` is written to.
const valueFD = 3

var (
	errNoFD3      = errors.New("--value needs file descriptor 3 to be open")
	errFD3Windows = errors.New("--value is not supported on Windows (no file descriptor 3); capture with the host's own prompt and store with set --stdin")
)

// openValueFD opens the descriptor the value goes to. It is a seam for tests.
// Windows does not hand a child a numbered descriptor the way POSIX does, so
// there `--value` is refused: a Windows host captures with its own prompt (the
// Pi extension) or the native dialog of `set`, and stores with `set --stdin`.
var openValueFD = func() (io.WriteCloser, error) {
	if runtime.GOOS == "windows" {
		return nil, errFD3Windows
	}
	return openValueFDNum(valueFD)
}

// openValueFDNum opens descriptor fd for the value. Only a descriptor a host
// can pass (valueFDKindOK) is wrapped in an *os.File: wrapping anything else,
// such as the Go runtime's own poller, which takes fd 3 on macOS when the
// parent passed nothing there, would hand it the value and let the file's
// finalizer close the runtime's descriptor.
func openValueFDNum(fd int) (io.WriteCloser, error) {
	if !valueFDKindOK(fd) {
		return nil, errNoFD3
	}
	f := os.NewFile(uintptr(fd), "value-fd")
	if f == nil {
		return nil, errNoFD3
	}
	return f, nil
}

type promptBody struct {
	OK      bool   `json:"ok"`
	Token   string `json:"token"`
	Scope   string `json:"scope"`
	Layer   string `json:"layer"`
	ValueFD int    `json:"value_on_fd,omitempty"`
}

// parseList validates a comma-separated flag against the allowed words and
// returns them without duplicates, in the order given.
func parseList(in []string, allowed []string, msg string) ([]string, error) {
	var out []string
	for _, w := range in {
		w = strings.TrimSpace(w)
		if !slices.Contains(allowed, w) {
			return nil, usageError{msg}
		}
		if !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	if len(out) == 0 {
		return nil, usageError{msg}
	}
	return out, nil
}

// hostOf is the host part of a session id ("pi:abc..." is "pi").
func hostOf(session string) string {
	host, _, _ := strings.Cut(session, ":")
	return host
}

// newPromptCmd is the broker's own prompt (docs/CLI.md § Host plumbing): it
// asks the user, on the controlling terminal, which layer and scope to allow
// and, with --value, for the value, then issues a prompt token the host
// redeems with `grant --from-prompt-token` or `set --grant`. The value goes to
// file descriptor 3 only, never to stdout.
func newPromptCmd(g *globals) *cobra.Command {
	var (
		name, reason  string
		withValue     bool
		scopes, layer []string
	)
	cmd := &cobra.Command{
		Use:   "prompt --name NAME --reason R [--value] [--scopes once,session,project] [--layers global,project]",
		Short: "Ask the user to allow a secret and print a prompt token (host plumbing)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch {
			case name == "":
				return usageError{"missing --name"}
			case strings.TrimSpace(reason) == "":
				return usageError{"missing --reason"}
			case len(reason) > maxReasonBytes:
				return usageError{"--reason is too long"}
			}
			if err := checkName(name); err != nil {
				return err
			}
			scopeNames, err := parseList(scopes, []string{"once", "session", "project"}, "invalid --scopes: must be once, session or project")
			if err != nil {
				return err
			}
			layerNames, err := parseList(layer, []string{"global", "project"}, "invalid --layers: must be global or project")
			if err != nil {
				return err
			}
			var want []grants.Scope
			for _, sc := range scopeOrder {
				if slices.Contains(scopeNames, string(sc)) {
					want = append(want, sc)
				}
			}
			var fd io.WriteCloser
			if withValue {
				if fd, err = openValueFD(); err != nil {
					return usageError{err.Error()}
				}
				defer fd.Close()
			}
			ask, err := g.backend()
			if err != nil {
				return promptFail(err, "")
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			var avail []vault.Layer
			for _, l := range layerNames {
				if l == "global" {
					avail = append(avail, vault.Global())
					continue
				}
				switch proj, perr := vault.ProjectLayer(cwd); {
				case perr == nil:
					avail = append(avail, proj)
				case !errors.Is(perr, vault.ErrNoProject):
					return mapErr(perr, "")
				}
			}
			if len(avail) == 0 {
				return mapErr(vault.ErrNoProject, "")
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			g.pullBeforeCmd(cmd, s)

			layerChoice := avail[0]
			// From here the user is asked, so the outcome is audited, best effort.
			// The record never holds the reason, the value or the token.
			var outcome, auditedLayer, auditedScope = "cancelled", "", ""
			defer func() {
				if outcome == "" {
					return // refused before the user was asked about the secret
				}
				g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventPrompt, Names: []string{name}, Layer: auditedLayer, Scope: auditedScope, Outcome: outcome})
			}()
			if len(avail) == 1 {
				auditedLayer = auditLayer(layerChoice)
			}
			if len(avail) > 1 {
				opts := make([]string, len(avail))
				for i, l := range avail {
					opts[i] = layerOption(l)
				}
				i, err := ask.Choose("Where should "+name+" be saved?", opts, 0)
				if err != nil {
					return promptFail(err, "")
				}
				layerChoice = avail[i]
				auditedLayer = auditLayer(layerChoice)
			}

			var (
				exists    bool
				sensitive bool
				recordID  string
			)
			all, err := s.v.ListAll()
			if err != nil {
				return mapErr(err, name)
			}
			for _, e := range all {
				if e.Name == name && sameLayer(e.Layer, layerChoice) {
					exists, sensitive, recordID = true, e.Record.Sensitive, e.Record.ID
				}
			}
			wipeEntries(all)
			if !withValue && !exists {
				outcome = ""
				return mapErr(vault.ErrNotFound, name)
			}

			allowed := g.allowedScopes(name, layerChoice, sensitive, want)
			if !layerChoice.Project {
				// The token is redeemed by another call, maybe with another cwd:
				// a project grant of a global secret is offered only where the
				// decision and the grant happen in one step.
				allowed = slices.DeleteFunc(allowed, func(s grants.Scope) bool { return s == grants.ScopeProject })
			}
			if len(allowed) == 0 {
				outcome = ""
				return g.noScopeError(name, layerChoice, sensitive, want)
			}

			var raw []byte
			if withValue {
				raw, err = askValue(ask, prompt.SecretRequest{
					Name: name, Reason: reason, Host: hostOf(g.Session), Session: g.Session,
					Project: layerRequest(layerChoice), Existing: exists,
				}, "")
				if err != nil {
					return err
				}
				defer clear(raw)
				// A new record has no id yet; a replaced one keeps the id it
				// had when the user was asked.
				if !exists {
					recordID = ""
				}
			}

			opts, def := scopeLabels(allowed, "", false)
			opts = append(opts, denyOption)
			i, err := ask.Choose(allowQuestion(prompt.Requester(hostOf(g.Session), ""), []string{name + " (" + whereText(layerChoice) + ")"}, reason), opts, def)
			if err != nil {
				return promptFail(err, "")
			}
			if i >= len(allowed) {
				outcome = "denied"
				return refusal.New(refusal.UserDeclined, name)
			}
			scope := allowed[i]

			req := g.grantRequest(name, layerChoice, recordID, scope, 0, sensitive)
			var token string
			err = g.mutateGrants(cmd.ErrOrStderr(), s, func(st *grants.Store) (bool, error) {
				token = grants.IssueToken(st, req.Name, req.Layer, req.RecordID, req.Scope, req.Session, req.TTL, clock())
				return true, nil
			})
			if err != nil {
				return err
			}
			outcome, auditedScope = "issued", string(scope)
			body := promptBody{OK: true, Token: token, Scope: string(scope), Layer: layerName(layerChoice)}
			if withValue {
				if _, werr := fd.Write(bytes.TrimSpace(raw)); werr != nil {
					return errors.New("cannot write the value to file descriptor 3")
				}
				body.ValueFD = valueFD
			}
			return writeJSON(cmd.OutOrStdout(), body)
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "secret name")
	f.StringVar(&reason, "reason", "", "why the secret is needed (shown to the user)")
	f.BoolVar(&withValue, "value", false, "also ask for the value and write it to file descriptor 3")
	f.StringSliceVar(&scopes, "scopes", []string{"once", "session", "project"}, "scopes the user may allow")
	f.StringSliceVar(&layer, "layers", []string{"global", "project"}, "layers the user may choose")
	return cmd
}

// noScopeError explains why none of the wanted scopes can be granted.
func (g *globals) noScopeError(name string, layer vault.Layer, sensitive bool, want []grants.Scope) error {
	if g.Session == "" && slices.ContainsFunc(want, func(sc grants.Scope) bool { return sc != grants.ScopeProject }) {
		return usageError{"--session is required for the once and session scopes"}
	}
	for _, sc := range want {
		if err := grants.Validate(g.grantRequest(name, layer, "", sc, 0, sensitive)); err != nil {
			return grantErr(err, name)
		}
	}
	return usageError{"invalid grant request"}
}
