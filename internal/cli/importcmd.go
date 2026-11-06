package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/dotenv"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// maxDotenvBytes bounds the dotenv file import reads.
const maxDotenvBytes = 1 << 20

type importedOut struct {
	Name     string `json:"name"`
	Replaced bool   `json:"replaced"`
}

type importBody struct {
	OK            bool          `json:"ok"`
	Layer         string        `json:"layer"`
	Project       *projectRef   `json:"project"`
	Imported      []importedOut `json:"imported"`
	Skipped       int           `json:"skipped"`
	GrantsDropped int           `json:"grants_dropped"`
	SourceRemoved bool          `json:"source_removed"`
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

// importSource is what an import read: names in order and their values.
type importSource struct {
	order   []string
	values  map[string][]byte
	skipped int
}

func (s *importSource) wipe() {
	for _, v := range s.values {
		clear(v)
	}
}

func (s *importSource) add(name string, v []byte) error {
	if len(v) > maxValueBytes {
		clear(v)
		return usageError{name + " is too large"}
	}
	s.order = append(s.order, name)
	s.values[name] = v
	return nil
}

// newImport is the explicit, user-run import of R-VAULT-08: values from the
// current environment or a dotenv file, confirmed by the user, stored in one
// locked write. init never runs it. Values are never echoed: errors name the
// variable or the line only.
func newImport(g *globals) *cobra.Command {
	var (
		lf           layerFlags
		fromEnv      string
		fromFile     string
		fromExport   string
		names        []string
		removeSource bool
		yes          bool
	)
	cmd := &cobra.Command{
		Use:   "import --from-env NAME[,NAME...] | --from-file PATH [--names A,B] [--global|--project] [--yes] [--remove-source] | --from-export FILE [--yes]",
		Short: "Import secrets from the environment, a dotenv file or an export",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			envGiven, fileGiven, exportGiven := f.Changed("from-env"), f.Changed("from-file"), f.Changed("from-export")
			switch {
			case b2i(envGiven)+b2i(fileGiven)+b2i(exportGiven) != 1:
				return usageError{"choose --from-env, --from-file or --from-export"}
			case f.Changed("names") && !fileGiven:
				return usageError{"--names needs --from-file"}
			case removeSource && !fileGiven:
				return usageError{"--remove-source needs --from-file"}
			}
			if exportGiven {
				if lf.explicit() {
					return usageError{"--global and --project do not apply to --from-export; every secret returns to its own layer"}
				}
				return importFromExport(g, cmd, fromExport, yes)
			}
			if err := lf.validate(); err != nil {
				return err
			}
			src := &importSource{values: map[string][]byte{}}
			defer src.wipe()
			from := "the environment"
			if envGiven {
				if err := g.readEnv(src, cleanList(strings.Split(fromEnv, ","))); err != nil {
					return err
				}
			} else {
				from = "the dotenv file"
				if err := readDotenv(src, fromFile, cleanList(names)); err != nil {
					return err
				}
			}
			if len(src.order) == 0 {
				return usageError{"nothing to import"}
			}

			var ask prompt.Backend
			backend := func() (prompt.Backend, error) {
				if ask == nil {
					var err error
					ask, err = g.backend()
					return ask, err
				}
				return ask, nil
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			layer, err := g.importLayer(lf, cwd, backend)
			if err != nil {
				return err
			}
			if !yes {
				b, err := backend()
				if err != nil {
					return orInstead(err, usageError{"confirmation required; pass --yes"})
				}
				q := fmt.Sprintf("Import %s from %s into %s? Existing secrets with these names are replaced.", strings.Join(src.order, ", "), from, layerText(layer))
				if err := confirmChange(b, q, usageError{"confirmation required; pass --yes"}); err != nil {
					return err
				}
			}

			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			recs := make(map[string]vault.Record, len(src.order))
			for _, n := range src.order {
				recs[n] = vault.Record{Value: secret.New(n, src.values[n])}
			}
			res, replaced, err := s.v.PutManyWithGrants(layer, src.order, recs, newGrantsEditor())
			for _, r := range recs {
				r.Value.Wipe()
			}
			if err != nil {
				return mapErr(err, "")
			}
			stderr := cmd.ErrOrStderr()
			g.noteGrantsReset(stderr, res.Reset)
			reason := "import from env"
			if fileGiven {
				reason = "import from file"
			}
			g.record(stderr, audit.Record{Event: audit.EventCapture, Names: src.order, Layer: auditLayer(layer), By: "user", Reason: reason, Detail: "import"})

			removed := false
			if fileGiven {
				del := removeSource
				if !del && !yes {
					if b, err := backend(); err == nil {
						del, _ = b.Confirm("Delete the dotenv file now that its values are in the vault?")
					}
				}
				if del {
					if err := os.Remove(fromFile); err != nil {
						fmt.Fprintln(stderr, "warning: could not delete the dotenv file")
					} else {
						removed = true
					}
				}
			}
			if src.skipped > 0 {
				fmt.Fprintf(stderr, "note: skipped %d %s (invalid name, no '=', or empty value)\n", src.skipped, plural(src.skipped, "line", "lines"))
			}
			if envGiven {
				fmt.Fprintf(stderr, "hint: unset %s in your shell; qbit-vault cannot change the environment of the shell that started it\n", strings.Join(src.order, " "))
			}
			remoteState := g.pushAfterCmd(cmd, s)
			return writeImported(g, cmd.OutOrStdout(), layer, src, replaced, res.Changed, removed, remoteState)
		},
	}
	lf.bind(cmd)
	fl := cmd.Flags()
	fl.StringVar(&fromEnv, "from-env", "", "comma-separated variable names to read from the current environment")
	fl.StringVar(&fromFile, "from-file", "", "dotenv file to read")
	fl.StringVar(&fromExport, "from-export", "", "export file written by 'qbit-vault export' (asks its passphrase)")
	fl.StringSliceVar(&names, "names", nil, "with --from-file: import only these names")
	fl.BoolVar(&removeSource, "remove-source", false, "with --from-file: delete the file after a successful import")
	fl.BoolVar(&yes, "yes", false, "import without asking (for scripts)")
	return cmd
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func (g *globals) readEnv(src *importSource, names []string) error {
	seen := map[string]bool{}
	for _, n := range names {
		if err := checkName(n); err != nil {
			return err
		}
		if seen[n] {
			return usageError{n + " is listed twice"}
		}
		seen[n] = true
		v := bytes.TrimSpace([]byte(g.getenv(n)))
		if len(v) == 0 {
			return usageError{n + " is not set or empty in the environment"}
		}
		if err := src.add(n, v); err != nil {
			return err
		}
	}
	return nil
}

func readDotenv(src *importSource, path string, only []string) error {
	fh, err := os.Open(path)
	if err != nil {
		return usageError{"cannot read the dotenv file"}
	}
	data, err := io.ReadAll(io.LimitReader(fh, maxDotenvBytes+1))
	_ = fh.Close()
	defer clear(data)
	if err != nil {
		return usageError{"cannot read the dotenv file"}
	}
	if len(data) > maxDotenvBytes {
		return usageError{"dotenv file too large"}
	}
	entries, skipped, err := dotenv.Parse(data)
	if err != nil {
		var le *dotenv.LineError
		if errors.As(err, &le) {
			return usageError{fmt.Sprintf("the dotenv file has an error at line %d: %s", le.Line, le.What)}
		}
		return usageError{"cannot read the dotenv file"}
	}
	defer dotenv.Wipe(entries)
	src.skipped = skipped
	byName := make(map[string][]byte, len(entries))
	for _, e := range entries {
		byName[e.Name] = e.Value
	}
	want := only
	if len(want) == 0 {
		for _, e := range entries {
			want = append(want, e.Name)
		}
	}
	seen := map[string]bool{}
	for _, n := range want {
		if err := checkName(n); err != nil {
			return err
		}
		if seen[n] {
			return usageError{n + " is listed twice"}
		}
		seen[n] = true
		v, ok := byName[n]
		if !ok {
			return usageError{n + " is not set in the file"}
		}
		if err := src.add(n, bytes.Clone(v)); err != nil {
			return err
		}
	}
	return nil
}

// importLayer is the layer choice of set: the flag, else outside a
// repository global, else the user's answer (no prompt backend: a usage
// error naming the flags).
func (g *globals) importLayer(lf layerFlags, cwd string, backend func() (prompt.Backend, error)) (vault.Layer, error) {
	if lf.explicit() {
		return lf.pick(cwd)
	}
	proj, err := vault.ProjectLayer(cwd)
	switch {
	case errors.Is(err, vault.ErrNoProject):
		return vault.Global(), nil
	case err != nil:
		return vault.Layer{}, mapErr(err, "")
	}
	b, err := backend()
	if err != nil {
		return vault.Layer{}, orInstead(err, usageError{"choose --global or --project"})
	}
	i, err := b.Choose("Where should these secrets live?", []string{"global", "this project (" + proj.Label + ")"}, 0)
	if err != nil {
		return vault.Layer{}, orInstead(err, usageError{"choose --global or --project"})
	}
	if i == 1 {
		return proj, nil
	}
	return vault.Global(), nil
}

func writeImported(g *globals, out io.Writer, layer vault.Layer, src *importSource, replaced []string, dropped int, removed bool, remoteState string) error {
	isReplaced := map[string]bool{}
	for _, n := range replaced {
		isReplaced[n] = true
	}
	if g.JSON {
		body := importBody{OK: true, Layer: layerName(layer), Project: projectOf(layer), Skipped: src.skipped, GrantsDropped: dropped, SourceRemoved: removed, Remote: remoteState}
		for _, n := range src.order {
			body.Imported = append(body.Imported, importedOut{Name: n, Replaced: isReplaced[n]})
		}
		return writeJSON(out, body)
	}
	line := fmt.Sprintf("imported %d %s into %s: %s", len(src.order), plural(len(src.order), "secret", "secrets"), layerText(layer), strings.Join(src.order, ", "))
	if len(replaced) > 0 {
		line += " (replaced: " + strings.Join(replaced, ", ") + ")"
	}
	_, err := fmt.Fprintln(out, line)
	return err
}
