//go:build !windows

package perm

import (
	"errors"
	"fmt"
	"os"
)

const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

func target(isDir bool) os.FileMode {
	if isDir {
		return dirMode
	}
	return fileMode
}

func ensure(path string, _ bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("perm: stat: %w", bare(err))
	}
	want := target(info.IsDir())
	if info.Mode().Perm()&0o077 == 0 { // owner-only already; stricter modes are left alone
		return nil
	}
	if err := os.Chmod(path, want); err != nil {
		return fmt.Errorf("perm: chmod: %w", bare(err))
	}
	return nil
}

func check(path string) (bool, string) {
	info, err := os.Stat(path)
	if err != nil {
		return false, "cannot stat"
	}
	if got := info.Mode().Perm(); got&0o077 != 0 {
		return false, fmt.Sprintf("mode %04o is wider than %04o", got, target(info.IsDir()))
	}
	return true, ""
}

func bare(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
