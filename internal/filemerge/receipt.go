package filemerge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Receipt records one registration so `sync` can re-apply it and `uninstall`
// can revert it. It is plain data (absolute paths only) meant for state.json.
type Receipt struct {
	Path string `json:"path"` // absolute path of the config file
	// Snapshot is the copy taken before the latest rewrite.
	Snapshot Snapshot `json:"snapshot"`
	// SHA256 (hex) is the digest of the bytes we last wrote.
	SHA256 string `json:"sha256"`
	// Created: the file did not exist before our first change.
	Created bool `json:"created"`
	// Exact: Snapshot is the state immediately before our only change, so a
	// file still equal to what we wrote can be restored from it byte for
	// byte. A re-apply over an existing receipt clears it (the snapshot then
	// holds our earlier entries, or a user edit made between the two writes).
	Exact bool `json:"exact"`
	// Original is the copy taken before our first change to this file, kept
	// unchanged by every re-apply. Revert reads it to tell containers we
	// created from ones the user had. Zero (Path empty) when unknown: a
	// receipt written before this field existed.
	Original Snapshot `json:"original"`
	// Changed is set on the result of a merge that wrote the file. It is not
	// stored.
	Changed bool `json:"-"`
}

// original returns the snapshot of the file as it was before our first
// change. An Exact receipt has not been re-applied, so its Snapshot is that
// state.
func (r Receipt) original() (Snapshot, bool) {
	if r.Original.Path != "" {
		return r.Original, true
	}
	if r.Exact && r.Snapshot.Path != "" {
		return r.Snapshot, true
	}
	return Snapshot{}, false
}

// Outcome says what Revert did.
type Outcome string

const (
	Restored  Outcome = "restored"  // file was still ours: snapshot restored byte for byte
	Stripped  Outcome = "stripped"  // user edited since: only our entries removed
	Deleted   Outcome = "deleted"   // nothing but our content remained in a file we created
	Absent    Outcome = "absent"    // the file is gone; nothing to do
	Unchanged Outcome = "unchanged" // none of our entries are in the file
)

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// readTarget returns the file's bytes and whether it exists, refusing links.
func readTarget(path string) ([]byte, bool, error) {
	if !filepath.IsAbs(path) {
		return nil, false, fail(ErrNotAbsolute, path)
	}
	if _, err := statTarget(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fail(fmt.Errorf("filemerge: read: %w", bare(err)), path)
	}
	return b, true, nil
}

// MergeJSONFile applies edits to the JSON file at path (created, with its
// parent directories, when absent). prev is the receipt of an earlier apply
// of the same registration, or nil.
//
// Order: read, compute the merge in memory (a refusal touches nothing),
// compare, snapshot, write atomically. A merge that changes nothing writes no
// file and takes no snapshot; it returns prev (with Changed false) or, when
// prev is nil, a receipt that Revert strips instead of restoring.
func MergeJSONFile(home, path string, edits []JSONEdit, prev *Receipt) (Receipt, error) {
	return mergeFile(home, path, prev, func(doc []byte) ([]byte, error) { return MergeJSON(doc, edits) })
}

// MergeTOMLFile is MergeJSONFile for a TOML file and our table (see MergeTOML).
func MergeTOMLFile(home, path, table, block string, prev *Receipt) (Receipt, error) {
	return mergeFile(home, path, prev, func(doc []byte) ([]byte, error) { return MergeTOML(doc, table, block) })
}

func mergeFile(home, path string, prev *Receipt, merge func([]byte) ([]byte, error)) (Receipt, error) {
	doc, exists, err := readTarget(path)
	if err != nil {
		return Receipt{}, err
	}
	path = filepath.Clean(path)
	out, err := merge(doc)
	if err != nil {
		return Receipt{}, wrapRefusal(err, path)
	}
	if exists && bytes.Equal(out, doc) {
		if prev != nil {
			r := *prev
			r.Changed = false
			return r, nil
		}
		// Nothing was written, so there is no copy; the snapshot only names
		// the file (state.json needs an absolute path) and Revert strips.
		return Receipt{Path: path, Snapshot: Snapshot{Path: path, Existed: true}, SHA256: digest(doc)}, nil
	}
	snap, err := TakeSnapshot(home, path)
	if err != nil {
		return Receipt{}, err
	}
	if err := writeAtomic(path, out); err != nil {
		return Receipt{}, err
	}
	r := Receipt{Path: path, Snapshot: snap, SHA256: digest(out), Created: !snap.Existed, Exact: true, Changed: true}
	if prev != nil && prev.Path == path {
		r.Created = prev.Created
		r.Exact = false
		if orig, ok := prev.original(); ok {
			r.Original = orig
		}
	}
	return r, nil
}

// RevertJSONFile undoes a MergeJSONFile (see revert for the rule); edits are
// the ones that were merged, only Path and Marker are used.
func RevertJSONFile(home string, r Receipt, edits []JSONEdit) (Outcome, error) {
	return revert(home, r, func(doc []byte, prune func([]string) bool) ([]byte, error) {
		return unmergeJSON(doc, edits, prune)
	}, jsonIsEmptyObject)
}

// RevertTOMLFile undoes a MergeTOMLFile (see revert for the rule).
func RevertTOMLFile(home string, r Receipt, table string) (Outcome, error) {
	return revert(home, r, func(doc []byte, _ func([]string) bool) ([]byte, error) { return UnmergeTOML(doc, table) },
		func(b []byte) bool { return len(bytes.TrimSpace(b)) == 0 })
}

// revert is the 3-way revert. Comparing the file now with what we wrote:
//
//  1. File absent: nothing to do (Absent).
//  2. File equal to what we wrote and the receipt is Exact: restore the
//     snapshot byte for byte (Restored); if the file did not exist before,
//     delete it (Deleted). If the snapshot copy has been pruned, fall
//     through to rule 3.
//  3. Otherwise (the user edited the file since, or the receipt is not
//     Exact): remove only our entries and keep everything else (Stripped).
//     Empty parents we may have created are pruned only when the file was
//     Created by us; if what is left is empty, the file is deleted (Deleted).
//     Otherwise an object or array that removing our entries left empty is
//     pruned only when it was absent from the original file (the receipt's
//     original copy, see Receipt.original); a container the user had, or any
//     container when the original is unknown or pruned, is kept. The result
//     is still reported as Stripped even when it equals the original bytes.
//     If none of our entries are present nothing is written (Unchanged).
//
// The current file is snapshotted before any write or delete. A file that
// became ambiguous or invalid since is refused with the usual typed error and
// left alone.
func revert(home string, r Receipt, strip func([]byte, func([]string) bool) ([]byte, error), isEmpty func([]byte) bool) (Outcome, error) {
	if r.Path == "" {
		return "", fail(ErrNotOurChange, "")
	}
	doc, exists, err := readTarget(r.Path)
	if err != nil {
		return "", err
	}
	if !exists {
		return Absent, nil
	}
	if r.Exact && digest(doc) == r.SHA256 {
		if !r.Snapshot.Existed {
			if _, err := TakeSnapshot(home, r.Path); err != nil {
				return "", err
			}
			if err := os.Remove(r.Path); err != nil {
				return "", fail(fmt.Errorf("filemerge: delete: %w", bare(err)), r.Path)
			}
			return Deleted, nil
		}
		if orig, err := os.ReadFile(r.Snapshot.Backup); err == nil {
			if _, err := TakeSnapshot(home, r.Path); err != nil {
				return "", err
			}
			if err := writeAtomic(r.Path, orig); err != nil {
				return "", err
			}
			return Restored, nil
		}
	}
	out, err := strip(doc, pruneRule(r))
	if err != nil {
		return "", wrapRefusal(err, r.Path)
	}
	if bytes.Equal(out, doc) {
		return Unchanged, nil
	}
	if _, err := TakeSnapshot(home, r.Path); err != nil {
		return "", err
	}
	if r.Created && isEmpty(out) {
		if err := os.Remove(r.Path); err != nil {
			return "", fail(fmt.Errorf("filemerge: delete: %w", bare(err)), r.Path)
		}
		return Deleted, nil
	}
	if err := writeAtomic(r.Path, out); err != nil {
		return "", err
	}
	return Stripped, nil
}

// pruneRule says which emptied containers (by key path) revert may remove.
// A file we created is ours entirely: everything goes. Otherwise a container
// goes only when the original file had no such key; with no readable original
// (old receipt, pruned copy, unparsable file) nothing is pruned.
func pruneRule(r Receipt) func([]string) bool {
	if r.Created {
		return func([]string) bool { return true }
	}
	orig, ok := r.original()
	if !ok || !orig.Existed {
		return nil
	}
	b, err := os.ReadFile(orig.Backup)
	if err != nil {
		return nil
	}
	root, err := parseJSON(b)
	if err != nil || root.kind != 'o' {
		return nil
	}
	return func(path []string) bool {
		_, n, _, err := walk(root, path)
		return err == nil && n < len(path)
	}
}

// wrapRefusal attaches the path to a typed refusal.
func wrapRefusal(err error, path string) error {
	var fe *Error
	if errors.As(err, &fe) {
		return err
	}
	return fail(err, path)
}
