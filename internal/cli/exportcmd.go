package cli

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/exportfile"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

const (
	msgExportShort   = "the export passphrase must be at least 12 characters"
	exportKeepNote   = "keep the file and its passphrase in different places; anyone with both can read every secret"
	msgConfirmNeeded = "confirmation required; pass --yes"
)

// errExportDamaged is every way an export fails to open: wrong passphrase, a
// changed byte, a truncated file, an unknown format. They are not told apart.
var errExportDamaged = codedError{"export_unopenable", "cannot open the export: wrong passphrase or damaged file", exitcode.Failure}

type exportBody struct {
	OK      bool   `json:"ok"`
	File    string `json:"file"`
	Secrets int    `json:"secrets"`
	Layers  int    `json:"layers"`
}

func fileArg(_ *cobra.Command, args []string) error {
	switch {
	case len(args) == 0:
		return usageError{"missing FILE"}
	case len(args) > 1:
		return usageError{"unexpected arguments"}
	}
	return nil
}

// newExport writes the offline backup of docs/STORAGE.md § Export file
// format: every layer and record, sealed under a passphrase chosen now. It
// needs no server and makes no network call. The passphrase comes from the
// prompt backend only.
func newExport(g *globals) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "export FILE [--force]",
		Short: "Write an encrypted, portable copy of the whole vault to FILE",
		Args:  fileArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			file := args[0]
			if !force && exportfile.Exists(file) {
				return usageError{file + " exists; pass --force to overwrite"}
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			layers, unlinked, err := s.v.ExportAll()
			if err != nil {
				return mapErr(err, "")
			}
			defer wipeLayers(layers)
			secrets := 0
			for _, l := range layers {
				secrets += len(l.Records)
			}
			if secrets == 0 && unlinked > 0 {
				return usageError{fmt.Sprintf("nothing to export on this device: %d %s in project layers not linked here; run 'qbit-vault link' or export from the device that has them", unlinked, plural(unlinked, "secret is", "secrets are"))}
			}
			if secrets == 0 {
				return usageError{"the vault is empty; nothing to export"}
			}
			ask, err := g.backend()
			if err != nil {
				return promptFail(err, "")
			}
			pass, err := ask.Passphrase(prompt.ExportPassphrase.Twice())
			if err != nil {
				return promptFail(err, "")
			}
			defer pass.Wipe()
			if err := exportfile.CheckPassphrase(pass); err != nil {
				return usageError{msgExportShort}
			}
			payload := exportPayload(layers)
			defer payload.Wipe()
			data, err := exportfile.Seal(pass, payload, clock())
			if errors.Is(err, exportfile.ErrTooLarge) {
				return usageError{"the export would be larger than 64 MiB and could not be imported back"}
			}
			if err != nil {
				return err
			}
			switch err := exportfile.Write(file, data, force); {
			case errors.Is(err, exportfile.ErrExists):
				return usageError{file + " exists; pass --force to overwrite"}
			case err != nil:
				return usageError{"cannot write the export file"}
			}
			stderr := cmd.ErrOrStderr()
			g.record(stderr, audit.Record{Event: audit.EventExport, Detail: fmt.Sprintf("%d %s", secrets, plural(secrets, "secret", "secrets"))})
			if unlinked > 0 {
				fmt.Fprintf(stderr, "note: %d %s in project layers not linked on this device %s not exported\n", unlinked, plural(unlinked, "secret", "secrets"), plural(unlinked, "was", "were"))
			}
			fmt.Fprintln(stderr, exportKeepNote)
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), exportBody{OK: true, File: file, Secrets: secrets, Layers: len(layers)})
			}
			global, projects := 0, 0
			for _, l := range layers {
				if l.Layer.Project {
					projects += len(l.Records)
				} else {
					global += len(l.Records)
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "exported %d %s (global: %d, projects: %d) to %s\n", secrets, plural(secrets, "secret", "secrets"), global, projects, file)
			return err
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "replace FILE if it exists")
	return cmd
}

func wipeLayers(layers []vault.LayerRecords) {
	for _, l := range layers {
		for _, r := range l.Records {
			r.Record.Value.Wipe()
		}
	}
}

// exportPayload copies the revealed records into the file's payload; the
// caller wipes it.
func exportPayload(layers []vault.LayerRecords) exportfile.Payload {
	var p exportfile.Payload
	for _, l := range layers {
		el := exportfile.Layer{Project: l.Layer.Project, Root: l.Layer.Root, Label: l.Layer.Label}
		for _, nr := range l.Records {
			r := nr.Record
			el.Records = append(el.Records, exportfile.Record{
				Name: nr.Name, Value: r.Value.Reveal(), Kind: r.Kind, Description: r.Description,
				Sensitive: r.Sensitive, Binaries: r.Binaries, Hosts: r.Hosts,
				CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
			})
		}
		p.Layers = append(p.Layers, el)
	}
	return p
}

type exportImportedOut struct {
	Name     string      `json:"name"`
	Layer    string      `json:"layer"`
	Project  *projectRef `json:"project"`
	Replaced bool        `json:"replaced"`
}

// exportImportBody is the import shape with "source":"export": the secrets
// come from several layers, so each entry carries its own.
type exportImportBody struct {
	OK            bool                `json:"ok"`
	Source        string              `json:"source"`
	Imported      []exportImportedOut `json:"imported"`
	Skipped       int                 `json:"skipped"`
	GrantsDropped int                 `json:"grants_dropped"`
	SourceRemoved bool                `json:"source_removed"`
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

// importFromExport is `import --from-export` (docs/CLI.md § import): the
// export is merged into the vault. Every record returns to its own layer; one
// whose name already exists there is replaced whole and loses its grants,
// every other record of the vault is untouched. Grants are never imported.
func importFromExport(g *globals, cmd *cobra.Command, file string, yes bool) error {
	data, err := exportfile.Read(file)
	if err != nil {
		return usageError{"cannot read the export file"}
	}
	s, err := g.openSession()
	if err != nil {
		return err
	}
	defer s.close()
	ask, err := g.backend()
	if err != nil {
		return promptFail(err, "")
	}
	pass, err := ask.Passphrase(prompt.ImportPassphrase)
	if err != nil {
		return promptFail(err, "")
	}
	defer pass.Wipe()
	payload, err := exportfile.Open(pass, data)
	if err != nil {
		return errExportDamaged
	}
	defer payload.Wipe()
	layers, err := importLayers(payload)
	if err != nil {
		return err
	}
	defer wipeLayers(layers)

	if !yes {
		clashes, err := s.v.Clashes(layers)
		if err != nil {
			return mapErr(err, "")
		}
		q := fmt.Sprintf("Import %d %s from the export?", countRecords(layers), plural(countRecords(layers), "secret", "secrets"))
		if len(clashes) > 0 {
			q += " These replace existing ones: " + strings.Join(replacedNames(clashes), ", ")
		}
		if err := confirmChange(ask, q, usageError{msgConfirmNeeded}); err != nil {
			return err
		}
	}
	res, replaced, err := s.v.ImportAll(layers, newGrantsEditor())
	if err != nil {
		return mapErr(err, "")
	}
	stderr := cmd.ErrOrStderr()
	g.noteGrantsReset(stderr, res.Reset)
	g.record(stderr, audit.Record{Event: audit.EventCapture, Names: importedNames(layers), By: "user", Reason: "import from export", Detail: "import"})
	remoteState := g.pushAfterCmd(cmd, s)
	return writeExportImported(g, cmd.OutOrStdout(), layers, replaced, res.Changed, remoteState)
}

// importLayers converts a verified payload to vault layers, refusing what the
// vault could not hold (a name outside the rule, an oversized value). The
// file was authenticated, so such content means it was not made by this tool.
func importLayers(p exportfile.Payload) ([]vault.LayerRecords, error) {
	var out []vault.LayerRecords
	for _, l := range p.Layers {
		lr := vault.LayerRecords{Layer: vault.Layer{Project: l.Project, Root: l.Root, Label: l.Label}}
		if l.Project && l.Root == "" {
			wipeLayers(out)
			return nil, errExportDamaged
		}
		for _, r := range l.Records {
			if !vault.ValidName(r.Name) || len(r.Value) == 0 || len(r.Value) > maxValueBytes {
				wipeLayers(out)
				wipeLayers([]vault.LayerRecords{lr})
				return nil, errExportDamaged
			}
			lr.Records = append(lr.Records, vault.NamedRecord{Name: r.Name, Record: vault.Record{
				Value: secret.New(r.Name, r.Value), Kind: r.Kind, Description: r.Description, Sensitive: r.Sensitive,
				Binaries: r.Binaries, Hosts: r.Hosts, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
			}})
		}
		out = append(out, lr)
	}
	return out, nil
}

func countRecords(layers []vault.LayerRecords) int {
	n := 0
	for _, l := range layers {
		n += len(l.Records)
	}
	return n
}

// displayName is a record name with its project when it is not global, so
// the same name in two layers reads as two records.
func displayName(l vault.Layer, name string) string {
	if l.Project {
		return name + " (" + layerText(l) + ")"
	}
	return name
}

func replacedNames(rs []vault.Replaced) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, displayName(r.Layer, r.Name))
	}
	sort.Strings(out)
	return out
}

func importedNames(layers []vault.LayerRecords) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range layers {
		for _, r := range l.Records {
			if !seen[r.Name] {
				seen[r.Name] = true
				out = append(out, r.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

func writeExportImported(g *globals, out io.Writer, layers []vault.LayerRecords, replaced []vault.Replaced, dropped int, remoteState string) error {
	was := map[string]bool{}
	for _, r := range replaced {
		was[r.Layer.Key()+"\x00"+r.Name] = true
	}
	n := countRecords(layers)
	if g.JSON {
		body := exportImportBody{OK: true, Source: "export", Imported: []exportImportedOut{}, GrantsDropped: dropped, Remote: remoteState}
		for _, l := range layers {
			for _, r := range l.Records {
				body.Imported = append(body.Imported, exportImportedOut{Name: r.Name, Layer: layerName(l.Layer), Project: projectOf(l.Layer), Replaced: was[l.Layer.Key()+"\x00"+r.Name]})
			}
		}
		return writeJSON(out, body)
	}
	line := fmt.Sprintf("imported %d %s from the export", n, plural(n, "secret", "secrets"))
	if len(replaced) > 0 {
		line += " (replaced: " + strings.Join(replacedNames(replaced), ", ") + ")"
	}
	_, err := fmt.Fprintln(out, line)
	return err
}
