package filemerge

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrForeignFile: the target exists, differs from what we would write and
// does not carry our marker, so it is someone else's file and is left alone.
var ErrForeignFile = errors.New("filemerge: file exists and is not managed by qbit-vault")

// WriteOwnedFile makes the file at path hold exactly content, a whole file
// qbit-vault owns (a skill), recognized by marker, which content must carry.
// Same order as MergeJSONFile: read, compare, snapshot, write atomically. A
// file already equal to content is not written and takes no snapshot; a file
// that exists without the marker is refused with ErrForeignFile and untouched.
func WriteOwnedFile(home, path string, content []byte, marker string, prev *Receipt) (Receipt, error) {
	if marker == "" || !bytes.Contains(content, []byte(marker)) {
		return Receipt{}, fail(ErrInvalidEdit, path)
	}
	return mergeFile(home, path, prev, func(doc []byte) ([]byte, error) {
		if len(doc) > 0 && !bytes.Equal(doc, content) && !bytes.Contains(doc, []byte(marker)) {
			return nil, ErrForeignFile
		}
		return content, nil
	})
}

// RemoveOwnedFile undoes WriteOwnedFile: a file that still carries marker is
// snapshotted and deleted (Deleted), and its directory too when that is left
// empty; a file without it is the user's now and stays (Unchanged); a missing
// file is Absent.
func RemoveOwnedFile(home string, r Receipt, marker string) (Outcome, error) {
	if r.Path == "" || marker == "" {
		return "", fail(ErrNotOurChange, r.Path)
	}
	doc, exists, err := readTarget(r.Path)
	if err != nil {
		return "", err
	}
	if !exists {
		return Absent, nil
	}
	if !bytes.Contains(doc, []byte(marker)) {
		return Unchanged, nil
	}
	if _, err := TakeSnapshot(home, r.Path); err != nil {
		return "", err
	}
	if err := os.Remove(r.Path); err != nil {
		return "", fail(fmt.Errorf("filemerge: delete: %w", bare(err)), r.Path)
	}
	_ = os.Remove(filepath.Dir(r.Path)) // only succeeds when empty
	return Deleted, nil
}
