package hosts

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/QuBiit0/qbit-vault/internal/filemerge"
)

// CheckJSON is the read-only Check of a JSON step: nil when applying edits to
// the file at path would change nothing, ErrDrift when it would (the entry is
// gone or altered) or when the file is missing or no longer valid JSON.
func CheckJSON(path string, edits []filemerge.JSONEdit) error {
	return checkMerge(path, func(doc []byte) ([]byte, error) { return filemerge.MergeJSON(doc, edits) })
}

// CheckTOML is CheckJSON for a TOML step (see filemerge.MergeTOML).
func CheckTOML(path, table, block string) error {
	return checkMerge(path, func(doc []byte) ([]byte, error) { return filemerge.MergeTOML(doc, table, block) })
}

func checkMerge(path string, merge func([]byte) ([]byte, error)) error {
	doc, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: file is missing", ErrDrift)
		}
		return errors.New("hosts: cannot read the host config")
	}
	out, err := merge(doc)
	if err != nil {
		return fmt.Errorf("%w: file cannot be parsed", ErrDrift)
	}
	if !bytes.Equal(out, doc) {
		return fmt.Errorf("%w: entry changed or removed", ErrDrift)
	}
	return nil
}
