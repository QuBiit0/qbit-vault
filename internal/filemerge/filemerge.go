// Package filemerge edits user configuration files for the host adapters
// without damaging them (AGENTS.md invariant 7, PRD R-INS-04, R-INS-09):
// every mutation is snapshotted first under <vault home>/backups/<ts>/ and
// written atomically; JSON and TOML edits touch only the entries qbit-vault
// owns and keep every other byte; Revert undoes our change without losing
// what the user changed after us. Errors never contain file contents.
package filemerge

import (
	"errors"
	"os"
)

// Typed refusals. Callers match them with errors.Is; the wrapped *Error adds
// the file path, never a byte of the file.
var (
	ErrInvalidJSON  = errors.New("filemerge: file is not valid JSON")
	ErrJSONShape    = errors.New("filemerge: JSON structure conflicts with the requested key")
	ErrInvalidTOML  = errors.New("filemerge: file is not well-formed TOML")
	ErrAmbiguous    = errors.New("filemerge: ambiguous definition that cannot be edited safely")
	ErrInvalidEdit  = errors.New("filemerge: invalid edit request")
	ErrSymlink      = errors.New("filemerge: target is a symbolic link; refusing to replace or follow it")
	ErrNotRegular   = errors.New("filemerge: target is not a regular file")
	ErrNotAbsolute  = errors.New("filemerge: path is not absolute")
	ErrNotOurChange = errors.New("filemerge: receipt does not describe this file")
)

// Error is a typed refusal or failure about one file.
type Error struct {
	Err  error  // one of the Err* values, or an I/O cause with no path in it
	Path string // the config file concerned
}

func (e *Error) Error() string { return e.Err.Error() + ": " + e.Path }
func (e *Error) Unwrap() error { return e.Err }

func fail(err error, path string) error { return &Error{Err: err, Path: path} }

// bare strips the path-bearing wrapper of an os error, leaving the errno text.
func bare(err error) error {
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
