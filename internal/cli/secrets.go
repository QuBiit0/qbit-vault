package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/grants"
	"github.com/QuBiit0/gentle-vault/internal/prompt"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// maxValueBytes bounds a value read from stdin (docs/CLI.md § set).
const maxValueBytes = 64 * 1024

// valueSlackBytes is how much surrounding whitespace readValue tolerates
// beyond maxValueBytes.
const valueSlackBytes = 4096

type projectRef struct {
	Root  string `json:"root"`
	Label string `json:"label"`
}

type setBody struct {
	OK       bool        `json:"ok"`
	Name     string      `json:"name"`
	Layer    string      `json:"layer"`
	Project  *projectRef `json:"project"`
	Replaced bool        `json:"replaced"`
	// GrantsDropped counts the grants a value replacement removed (L7); it is
	// omitted when none went.
	GrantsDropped int       `json:"grants_dropped,omitempty"`
	Grant         *grantOut `json:"grant,omitempty"` // set --grant only
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

type removeBody struct {
	OK      bool   `json:"ok"`
	Name    string `json:"name"`
	Layer   string `json:"layer"`
	Removed bool   `json:"removed"`
	// GrantsDropped counts the grants the removal dropped; omitted when none.
	GrantsDropped int `json:"grants_dropped,omitempty"`
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

type editBody struct {
	OK      bool        `json:"ok"`
	Name    string      `json:"name"`
	Layer   string      `json:"layer"`
	Project *projectRef `json:"project"`
	Updated bool        `json:"updated"`
	// GrantsDropped counts the grants an edit to sensitive dropped; omitted
	// when none.
	GrantsDropped int `json:"grants_dropped,omitempty"`
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

type describeBody struct {
	OK              bool            `json:"ok"`
	Name            string          `json:"name"`
	Layer           string          `json:"layer"`
	Project         *projectRef     `json:"project"`
	OverridesGlobal bool            `json:"overrides_global"`
	Description     string          `json:"description"`
	Sensitive       bool            `json:"sensitive"`
	Binaries        []string        `json:"binaries"`
	Hosts           []string        `json:"hosts"`
	CreatedAt       string          `json:"created_at"`
	UpdatedAt       string          `json:"updated_at"`
	Grants          []describeGrant `json:"grants"`
}

type listEntry struct {
	Name            string   `json:"name"`
	Layer           string   `json:"layer"`
	ProjectLabel    string   `json:"project_label,omitempty"`
	OverridesGlobal bool     `json:"overrides_global"`
	Description     string   `json:"description"`
	Sensitive       bool     `json:"sensitive"`
	Binaries        []string `json:"binaries"`
	Hosts           []string `json:"hosts"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
	// Unlinked marks a layer synced from another device that has no root
	// on this one (gentle-vault link binds it).
	Unlinked bool `json:"unlinked,omitempty"`
}

type listBody struct {
	OK      bool        `json:"ok"`
	Project *projectRef `json:"project"`
	Secrets []listEntry `json:"secrets"`
}

// layerFlags are --global and --project, shared by the NAME commands.
type layerFlags struct{ global, project bool }

func (l *layerFlags) bind(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&l.global, "global", false, "act on the global layer")
	cmd.Flags().BoolVar(&l.project, "project", false, "act on the project layer of the current repository")
}

func (l layerFlags) validate() error {
	if l.global && l.project {
		return usageError{"choose only one of --global and --project"}
	}
	return nil
}

func (l layerFlags) explicit() bool { return l.global || l.project }

// pick returns the layer named by the flags. --project outside a repository
// is the no_project refusal.
func (l layerFlags) pick(cwd string) (vault.Layer, error) {
	if l.global {
		return vault.Global(), nil
	}
	layer, err := vault.ProjectLayer(cwd)
	if err != nil {
		return vault.Layer{}, mapErr(err, "")
	}
	return layer, nil
}

// metaFlags are the metadata flags of set and edit.
type metaFlags struct {
	description string
	sensitive   bool
	binaries    []string
	hosts       []string
}

func (m *metaFlags) bind(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&m.description, "description", "", "what the secret is for")
	f.BoolVar(&m.sensitive, "sensitive", false, "restrict grants to a single use (--sensitive=false to clear)")
	f.StringSliceVar(&m.binaries, "binaries", nil, "executables allowed to receive it, comma-separated (empty = any)")
	f.StringSliceVar(&m.hosts, "hosts", nil, "hostnames it is meant for, comma-separated (advisory)")
}

// apply copies the metadata flags the user actually passed onto rec and
// reports whether there was any.
func (m *metaFlags) apply(cmd *cobra.Command, rec *vault.Record) bool {
	f, changed := cmd.Flags(), false
	if f.Changed("description") {
		rec.Description, changed = m.description, true
	}
	if f.Changed("sensitive") {
		rec.Sensitive, changed = m.sensitive, true
	}
	if f.Changed("binaries") {
		rec.Binaries, changed = cleanList(m.binaries), true
	}
	if f.Changed("hosts") {
		rec.Hosts, changed = cleanList(m.hosts), true
	}
	return changed
}

func cleanList(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func nameArg(_ *cobra.Command, args []string) error {
	switch {
	case len(args) == 0:
		return usageError{"missing NAME"}
	case len(args) > 1:
		return usageError{"unexpected arguments"}
	}
	return nil
}

// checkName rejects an illegal name before the vault is needed. The name is
// never echoed.
func checkName(name string) error {
	if !vault.ValidName(name) {
		return refusal.New(refusal.InvalidName, "")
	}
	return nil
}

func getwd() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", errors.New("cannot determine the working directory")
	}
	return cwd, nil
}

func layerName(l vault.Layer) string {
	if l.Project {
		return "project"
	}
	return "global"
}

func projectOf(l vault.Layer) *projectRef {
	if !l.Project {
		return nil
	}
	return &projectRef{Root: l.Root, Label: l.Label}
}

// layerText is "global" or "project <label>", for human output.
func layerText(l vault.Layer) string {
	if l.Project {
		return "project " + l.Label
	}
	return "global"
}

func sameLayer(a, b vault.Layer) bool {
	return a.Project == b.Project && (!a.Project || a.Root == b.Root)
}

func wipeEntries(es []vault.Entry) {
	for _, e := range es {
		e.Record.Value.Wipe()
	}
}

// findEntry returns the record NAME refers to: the layer the flags name, else
// the layer NAME resolves to from cwd. The caller wipes the entry's value.
func findEntry(s *session, name string, lf layerFlags, cwd string) (vault.Entry, error) {
	var layer vault.Layer
	if lf.explicit() {
		var err error
		if layer, err = lf.pick(cwd); err != nil {
			return vault.Entry{}, err
		}
	} else {
		rec, l, err := s.v.Resolve(name, cwd)
		if err != nil {
			return vault.Entry{}, mapErr(err, name)
		}
		rec.Value.Wipe()
		layer = l
	}
	all, err := s.v.ListAll()
	if err != nil {
		return vault.Entry{}, mapErr(err, name)
	}
	defer wipeEntries(all)
	for _, e := range all {
		if e.Name == name && sameLayer(e.Layer, layer) {
			// Return a copy of the value so wiping all does not blank it.
			b := e.Record.Value.Reveal()
			e.Record.Value = secret.New(name, b)
			clear(b)
			return e, nil
		}
	}
	return vault.Entry{}, mapErr(vault.ErrNotFound, name)
}

// readValue reads the secret value from r: at most maxValueBytes, surrounding
// whitespace trimmed, blank refused (R-CAP-04). The caller wipes the result.
func readValue(r io.Reader) ([]byte, error) {
	// Read some slack past the limit so surrounding whitespace (a trailing
	// newline from echo) does not count against it; the limit applies to the
	// trimmed value.
	b, err := io.ReadAll(io.LimitReader(r, maxValueBytes+valueSlackBytes+1))
	if err != nil {
		return nil, errors.New("cannot read the value from stdin")
	}
	v := bytes.TrimSpace(b)
	if len(v) > maxValueBytes || len(b) > maxValueBytes+valueSlackBytes {
		clear(b)
		return nil, usageError{"value too large"}
	}
	if len(v) == 0 {
		clear(b)
		return nil, usageError{"empty value"}
	}
	return v, nil
}

func newSet(g *globals) *cobra.Command {
	var (
		lf       layerFlags
		meta     metaFlags
		stdin    bool
		grantStr string
		token    string
	)
	cmd := &cobra.Command{
		Use:   "set NAME [--global|--project] [--stdin] [--grant once|session|project [--from-prompt-token T]]",
		Short: "Store or replace a secret value (masked prompt, or --stdin)",
		Args:  nameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := lf.validate(); err != nil {
				return err
			}
			if err := checkName(name); err != nil {
				return err
			}
			// With --stdin the value is on stdin, so a grant cannot be
			// confirmed by asking: it needs a prompt token. Interactively the
			// scope question after the value is the confirmation.
			f := cmd.Flags()
			tokenGiven := f.Changed("from-prompt-token")
			var (
				scope grants.Scope
				ttl   time.Duration
			)
			switch {
			case f.Changed("grant"):
				switch {
				case stdin && !tokenGiven:
					return usageError{"--grant requires --from-prompt-token"}
				case !stdin && tokenGiven:
					return usageError{"--from-prompt-token needs --stdin"}
				}
				var err error
				if scope, ttl, err = (grantFlags{}).parse(cmd, grantStr, g.Session); err != nil {
					return err
				}
			case tokenGiven:
				return usageError{"--from-prompt-token requires --grant"}
			}
			var ask prompt.Backend
			if !stdin {
				var err error
				if ask, err = g.backend(); err != nil {
					return promptFail(err, "use --stdin")
				}
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			var layer vault.Layer
			switch {
			case lf.explicit():
				if layer, err = lf.pick(cwd); err != nil {
					return err
				}
			default:
				switch proj, perr := vault.ProjectLayer(cwd); {
				case perr == nil && stdin:
					return usageError{"choose --global or --project"}
				case perr == nil:
					i, err := ask.Choose("Where should "+name+" live?", []string{"global", "this project (" + proj.Label + ")"}, 0)
					if err != nil {
						return promptFail(err, "use --stdin")
					}
					layer = vault.Global()
					if i == 1 {
						layer = proj
					}
				case errors.Is(perr, vault.ErrNoProject):
					layer = vault.Global()
				default:
					return mapErr(perr, "")
				}
			}
			var value []byte
			if stdin {
				if value, err = readValue(stdinOf(cmd)); err != nil {
					return err
				}
				defer clear(value)
			}

			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			g.pullBeforeCmd(cmd, s)

			var rec vault.Record
			replaced := false
			all, err := s.v.ListAll()
			if err != nil {
				return mapErr(err, name)
			}
			for _, e := range all {
				if e.Name == name && sameLayer(e.Layer, layer) {
					replaced = true
					// Metadata the user did not pass again survives a replace.
					rec.Kind, rec.Description, rec.Sensitive = e.Record.Kind, e.Record.Description, e.Record.Sensitive
					rec.Binaries, rec.Hosts = e.Record.Binaries, e.Record.Hosts
				}
			}
			wipeEntries(all)
			meta.apply(cmd, &rec)

			if !stdin {
				// Refuse a grant that cannot be made before asking for the
				// value, so nothing is typed in vain.
				if scope != "" {
					if err := grants.Validate(g.grantRequest(name, layer, "", scope, ttl, rec.Sensitive)); err != nil {
						return grantErr(err, name)
					}
				}
				raw, chosen, err := g.captureValue(ask, name, layer, replaced, scope, rec.Sensitive)
				if err != nil {
					return err
				}
				defer clear(raw)
				value, scope = bytes.TrimSpace(raw), chosen
			}
			rec.Value = secret.New(name, value)

			// Settle the grant before anything is stored, so a refused
			// grant leaves the vault as it was.
			var (
				req       grants.Request
				tokenHash string
			)
			if scope != "" {
				// The record id does not exist until the value is stored.
				req = g.grantRequest(name, layer, "", scope, ttl, rec.Sensitive)
				if err := grants.Validate(req); err != nil {
					return grantErr(err, name)
				}
				if stdin {
					tokenHash, err = g.confirm(cmd, s, req, layer, token, true)
				} else {
					tokenHash, err = g.promptToken(cmd, s, req)
				}
				if err != nil {
					return err
				}
			}

			res, err := s.v.ReplaceWithGrants(layer, name, rec, newGrantsEditor())
			if err != nil {
				return mapErr(err, name)
			}
			g.noteGrantsReset(cmd.ErrOrStderr(), res.Reset)
			recd := audit.Record{Event: audit.EventCapture, Names: []string{name}, Layer: auditLayer(layer)}
			if replaced {
				recd.Detail = "replaced"
			}
			if !stdin {
				recd.Reason = manualEntry
			}
			g.record(cmd.ErrOrStderr(), recd)
			body := setBody{OK: true, Name: name, Layer: layerName(layer), Project: projectOf(layer), Replaced: replaced, GrantsDropped: res.Changed}
			body.Remote = g.pushAfterCmd(cmd, s)
			var granted *grants.Grant
			if scope != "" {
				req.RecordID = res.RecordID
				gr, err := g.create(cmd, s, req, tokenHash)
				if err != nil {
					return err
				}
				granted = &gr
				out := toGrantOut(gr)
				body.Grant = &out
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), body)
			}
			if _, err = fmt.Fprintf(cmd.OutOrStdout(), "stored %s (%s)\n", name, layerText(layer)); err != nil {
				return err
			}
			if granted != nil {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "granted %s (%s): %s\n", name, layerText(layer), grantText(*granted))
			}
			return err
		},
	}
	lf.bind(cmd)
	meta.bind(cmd)
	cmd.Flags().BoolVar(&stdin, "stdin", false, "read the value from stdin instead of the masked prompt")
	cmd.Flags().StringVar(&grantStr, "grant", "", "also grant the secret to --session: once, session or project (with --stdin it needs --from-prompt-token; interactively it is the proposed scope)")
	cmd.Flags().StringVar(&token, "from-prompt-token", "", "prompt token that confirms --grant (with --stdin)")
	return cmd
}

func newRm(g *globals) *cobra.Command {
	var (
		lf  layerFlags
		yes bool
	)
	cmd := &cobra.Command{
		Use:   "rm NAME [--global|--project] [--yes]",
		Short: "Delete a secret",
		Args:  nameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := lf.validate(); err != nil {
				return err
			}
			// Without --yes the user is asked on the controlling terminal (L4);
			// with none, --yes is required.
			var ask prompt.Backend
			if !yes {
				var err error
				if ask, err = g.backend(); err != nil {
					return orInstead(err, usageError{"confirmation required; pass --yes"})
				}
			}
			if err := checkName(name); err != nil {
				return err
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			e, err := findEntry(s, name, lf, cwd)
			if err != nil {
				return err
			}
			e.Record.Value.Wipe()
			if !yes {
				if err := confirmChange(ask, fmt.Sprintf("Remove %s (%s)?", name, layerText(e.Layer)), usageError{"confirmation required; pass --yes"}); err != nil {
					return err
				}
			}
			res, err := s.v.RemoveWithGrants(e.Layer, name, newGrantsEditor())
			if err != nil {
				return mapErr(err, name)
			}
			g.noteGrantsReset(cmd.ErrOrStderr(), res.Reset)
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventRm, Names: []string{name}, Layer: auditLayer(e.Layer)})
			remoteState := g.pushAfterCmd(cmd, s)
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), removeBody{OK: true, Name: name, Layer: layerName(e.Layer), Removed: true, GrantsDropped: res.Changed, Remote: remoteState})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "removed %s (%s)\n", name, layerText(e.Layer))
			return err
		},
	}
	lf.bind(cmd)
	cmd.Flags().BoolVar(&yes, "yes", false, "remove without asking (for scripts)")
	return cmd
}

func newDescribe(g *globals) *cobra.Command {
	var lf layerFlags
	cmd := &cobra.Command{
		Use:   "describe NAME [--global|--project]",
		Short: "Show a secret's metadata (never its value)",
		Args:  nameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := lf.validate(); err != nil {
				return err
			}
			if err := checkName(name); err != nil {
				return err
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			g.pullBeforeCmd(cmd, s)
			e, err := findEntry(s, name, lf, cwd)
			if err != nil {
				return err
			}
			e.Record.Value.Wipe()
			r := e.Record
			active, err := g.recordGrants(cmd.ErrOrStderr(), s, name, e.Layer, e.Record.ID)
			if err != nil {
				return err
			}
			if g.JSON {
				shown := []describeGrant{}
				for _, gr := range active {
					shown = append(shown, describeGrant{Scope: string(gr.Scope), Session: nullable(gr.Session), ExpiresAt: expiryText(gr.ExpiresAt)})
				}
				return writeJSON(cmd.OutOrStdout(), describeBody{
					OK: true, Name: name, Layer: layerName(e.Layer), Project: projectOf(e.Layer),
					OverridesGlobal: e.OverridesGlobal, Description: r.Description, Sensitive: r.Sensitive,
					Binaries: nonNil(r.Binaries), Hosts: nonNil(r.Hosts), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
					Grants: shown,
				})
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s (%s)\n", name, layerText(e.Layer))
			fmt.Fprintf(&b, "  description: %s\n", oneLine(r.Description))
			fmt.Fprintf(&b, "  sensitive:   %s\n", yesNo(r.Sensitive))
			fmt.Fprintf(&b, "  binaries:    %s\n", listText(r.Binaries))
			fmt.Fprintf(&b, "  hosts:       %s\n", listText(r.Hosts))
			if e.OverridesGlobal {
				fmt.Fprintf(&b, "  overrides:   global %s\n", name)
			}
			fmt.Fprintf(&b, "  created:     %s\n", r.CreatedAt)
			fmt.Fprintf(&b, "  updated:     %s\n", r.UpdatedAt)
			if len(active) == 0 {
				fmt.Fprintf(&b, "  grants:      none\n")
			} else {
				texts := make([]string, len(active))
				for i, gr := range active {
					texts[i] = grantText(gr)
				}
				fmt.Fprintf(&b, "  grants:      %s\n", strings.Join(texts, "; "))
			}
			_, err = io.WriteString(cmd.OutOrStdout(), b.String())
			return err
		},
	}
	lf.bind(cmd)
	return cmd
}

func newEdit(g *globals) *cobra.Command {
	var (
		lf   layerFlags
		meta metaFlags
	)
	cmd := &cobra.Command{
		Use:   "edit NAME [--global|--project] [--description D] [--sensitive=true|false] [--binaries a,b] [--hosts h]",
		Short: "Change a secret's metadata (never its value)",
		Args:  nameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := lf.validate(); err != nil {
				return err
			}
			f := cmd.Flags()
			if !f.Changed("description") && !f.Changed("sensitive") && !f.Changed("binaries") && !f.Changed("hosts") {
				return usageError{"nothing to change; pass --description, --sensitive, --binaries or --hosts"}
			}
			if err := checkName(name); err != nil {
				return err
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			e, err := findEntry(s, name, lf, cwd)
			if err != nil {
				return err
			}
			defer e.Record.Value.Wipe()
			meta.apply(cmd, &e.Record)
			// Becoming sensitive drops the record's session and project grants.
			res, err := s.v.EditWithGrants(e.Layer, name, e.Record, newGrantsEditor())
			if err != nil {
				return mapErr(err, name)
			}
			g.noteGrantsReset(cmd.ErrOrStderr(), res.Reset)
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventEdit, Names: []string{name}, Layer: auditLayer(e.Layer)})
			remoteState := g.pushAfterCmd(cmd, s)
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), editBody{OK: true, Name: name, Layer: layerName(e.Layer), Project: projectOf(e.Layer), Updated: true, GrantsDropped: res.Changed, Remote: remoteState})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "updated %s (%s)\n", name, layerText(e.Layer))
			return err
		},
	}
	lf.bind(cmd)
	meta.bind(cmd)
	return cmd
}

func newList(g *globals) *cobra.Command {
	var layer string
	cmd := &cobra.Command{
		Use:   "list [--layer here|global|project|all]",
		Short: "List secret names and metadata (never values)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch layer {
			case "here", "global", "project", "all":
			default:
				return usageError{"invalid --layer: must be here, global, project or all"}
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			cur, perr := vault.ProjectLayer(cwd)
			if perr != nil && !errors.Is(perr, vault.ErrNoProject) {
				return mapErr(perr, "")
			}
			if layer == "project" && perr != nil {
				return mapErr(perr, "")
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			g.pullBeforeCmd(cmd, s)

			var entries []vault.Entry
			if layer == "here" {
				entries, err = s.v.List(cwd)
			} else {
				entries, err = s.v.ListAll()
			}
			if err != nil {
				return mapErr(err, "")
			}
			defer wipeEntries(entries)
			var shown []vault.Entry
			for _, e := range entries {
				switch layer {
				case "global":
					if e.Layer.Project {
						continue
					}
				case "project":
					if !sameLayer(e.Layer, cur) {
						continue
					}
				}
				shown = append(shown, e)
			}
			out := cmd.OutOrStdout()
			if g.JSON {
				body := listBody{OK: true, Project: projectOf(cur), Secrets: []listEntry{}}
				for _, e := range shown {
					le := listEntry{
						Name: e.Name, Layer: layerName(e.Layer), OverridesGlobal: e.OverridesGlobal,
						Description: e.Record.Description, Sensitive: e.Record.Sensitive,
						Binaries: nonNil(e.Record.Binaries), Hosts: nonNil(e.Record.Hosts),
						CreatedAt: e.Record.CreatedAt, UpdatedAt: e.Record.UpdatedAt,
					}
					if e.Layer.Project {
						le.ProjectLabel = e.Layer.Label
					}
					le.Unlinked = e.Unlinked
					body.Secrets = append(body.Secrets, le)
				}
				return writeJSON(out, body)
			}
			if _, err = io.WriteString(out, listTable(shown)); err != nil {
				return err
			}
			if n, cerr := s.v.ConflictCount(); cerr == nil && n > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "%d sync conflicts; run 'gentle-vault remote conflicts'\n", n)
			}
			// A layer synced from another device that matches this
			// repository is only suggested; the user links it (R-SYNC-11).
			if label, ok, merr := s.v.UnlinkedMatch(cwd); merr == nil && ok {
				fmt.Fprintf(cmd.ErrOrStderr(), "hint: project secrets %q from another device match this repository; run 'gentle-vault link %s'\n", oneLine(label), oneLine(label))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&layer, "layer", "here", "which layers to show: here, global, project or all")
	return cmd
}

// listTable renders entries as an aligned NAME / LAYER / DESCRIPTION table.
func listTable(es []vault.Entry) string {
	if len(es) == 0 {
		return "no secrets\n"
	}
	rows := [][3]string{{"NAME", "LAYER", "DESCRIPTION"}}
	for _, e := range es {
		layer := "global"
		if e.Layer.Project {
			layer = "project:" + e.Layer.Label
		}
		desc := oneLine(e.Record.Description)
		if e.OverridesGlobal {
			desc = strings.TrimSpace(desc + " (overrides global)")
		}
		if e.Unlinked {
			desc = strings.TrimSpace(desc + " (not linked on this device)")
		}
		rows = append(rows, [3]string{e.Name, oneLine(layer), desc})
	}
	var w [2]int
	for _, r := range rows {
		w[0], w[1] = max(w[0], len(r[0])), max(w[1], len(r[1]))
	}
	var b strings.Builder
	for _, r := range rows {
		line := fmt.Sprintf("%-*s  %-*s  %s", w[0], r[0], w[1], r[1], r[2])
		b.WriteString(strings.TrimRight(line, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// oneLine keeps stored text on one line so it cannot forge extra output rows.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, s)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func listText(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return oneLine(strings.Join(s, ", "))
}
