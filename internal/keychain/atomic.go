package keychain

import (
	"github.com/QuBiit0/gentle-vault/internal/perm"

	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// writeAtomic writes data to dir/name through a temp file in the same
// directory: write, fsync, rename. On POSIX the file is 0600 and the
// directory is fsynced. Failures name no path.
func writeAtomic(dir, name string, data []byte) (err error) {
	var r [4]byte
	if _, err := rand.Read(r[:]); err != nil {
		return fmt.Errorf("keychain: random source failed")
	}
	tmp := filepath.Join(dir, name+".tmp."+hex.EncodeToString(r[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("keychain: create temp file: %w", bare(err))
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	// Owner-only before any key bytes are written (Windows DACL, POSIX 0600).
	if err = perm.EnsureFile(tmp); err != nil {
		_ = f.Close()
		return fmt.Errorf("keychain: secure temp file: %w", bare(err))
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("keychain: write temp file: %w", bare(err))
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("keychain: replace file: %w", bare(err))
	}
	if runtime.GOOS != "windows" {
		if d, derr := os.Open(dir); derr == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}
