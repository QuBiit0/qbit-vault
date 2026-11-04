package keychain

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// A rekey stores the new master key durably before any file is re-sealed with
// it, so a crash can always be finished (docs/STORAGE.md § Master key). The
// staged key lives next to the main one: OS keychain account
// "master:next:<vault-id>", or key.next.enc wrapped with the same passphrase
// as key.enc.

const stagedFileName = "key.next.enc"

func stagedID(vaultID string) string { return "next:" + vaultID }

func stagedPath(home string) string { return filepath.Join(home, stagedFileName) }

// NewKey returns a fresh random master key. The caller wipes it.
func NewKey() (secret.Secret, error) { return newKey() }

// Stage stores next as the pending master key. In passphrase mode the
// passphrase is asked once and must unwrap key.enc to current, so a typo can
// never strand the new key behind a passphrase nobody knows (ErrBadPassphrase,
// nothing written). In keychain mode it needs no input.
func Stage(home, vaultID string, current, next secret.Secret, opts Options) error {
	if err := checkID(vaultID); err != nil {
		return err
	}
	if next.Len() != keySize {
		return errors.New("keychain: master key must be 32 bytes")
	}
	mode, err := ModeOf(home, opts)
	if err != nil {
		return err
	}
	if mode != ModePassphrase {
		return opts.os().Set(stagedID(vaultID), next)
	}
	if opts.Passphrase == nil {
		return ErrUnavailable
	}
	pass, err := askPassphrase(opts.Passphrase, false)
	if err != nil {
		return err
	}
	defer pass.Wipe()
	onDisk, err := readKeyFile(home, pass)
	if err != nil {
		return err
	}
	defer onDisk.Wipe()
	a, b := onDisk.Reveal(), current.Reveal()
	defer clear(a)
	defer clear(b)
	if !bytes.Equal(a, b) {
		return ErrBadPassphrase
	}
	return writeKeyFileAs(home, stagedFileName, next, pass)
}

// HasStaged reports whether a staged key exists. In passphrase mode it only
// looks for key.next.enc; in keychain mode it reads the entry.
func HasStaged(home, vaultID string, opts Options) (bool, error) {
	if err := checkID(vaultID); err != nil {
		return false, err
	}
	exists, err := fileExists(stagedPath(home))
	if err != nil || exists {
		return exists, err
	}
	k, err := opts.os().Get(stagedID(vaultID))
	switch {
	case err == nil:
		k.Wipe()
		return true, nil
	case errors.Is(err, ErrNoKey):
		return false, nil
	default:
		return false, err
	}
}

// Staged returns the staged key, or ErrNoKey. In passphrase mode it asks the
// passphrase (the unlock cache holds only the main key). The caller wipes it.
func Staged(home, vaultID string, opts Options) (secret.Secret, error) {
	if err := checkID(vaultID); err != nil {
		return secret.Secret{}, err
	}
	exists, err := fileExists(stagedPath(home))
	if err != nil {
		return secret.Secret{}, err
	}
	if !exists {
		return opts.os().Get(stagedID(vaultID))
	}
	if opts.Passphrase == nil {
		return secret.Secret{}, ErrUnavailable
	}
	pass, err := askPassphrase(opts.Passphrase, false)
	if err != nil {
		return secret.Secret{}, err
	}
	defer pass.Wipe()
	return readKeyFileAt(stagedPath(home), pass)
}

// Promote makes next the master key and removes the staged entry: keychain
// mode overwrites the main entry then deletes the staged one; passphrase mode
// renames key.next.enc over key.enc (atomic) and refreshes the unlock cache.
// Running it again after a crash is harmless.
func Promote(home, vaultID string, next secret.Secret, opts Options) error {
	if err := checkID(vaultID); err != nil {
		return err
	}
	exists, err := fileExists(stagedPath(home))
	if err != nil {
		return err
	}
	if exists {
		// Drop the cached old key first: Unlock trusts the cache, so a crash
		// or a failed write after the rename must never leave it behind.
		if err := cacheDelete(opts, vaultID); err != nil {
			return err
		}
		if err := os.Rename(stagedPath(home), keyFilePath(home)); err != nil {
			return fmt.Errorf("keychain: promote staged key: %w", bare(err))
		}
		cachePut(opts, vaultID, next)
		return nil
	}
	mode, err := ModeOf(home, opts)
	if err != nil {
		return err
	}
	if mode == ModePassphrase {
		// Already renamed by an earlier run; make sure the cache is current.
		cachePut(opts, vaultID, next)
		return nil
	}
	b := opts.os()
	if err := b.Set(vaultID, next); err != nil {
		return err
	}
	if err := b.Delete(stagedID(vaultID)); err != nil && !errors.Is(err, ErrNoKey) {
		return err
	}
	return nil
}

// Unstage discards a staged key, for a rekey that was refused before any file
// was re-sealed. Nothing staged is fine.
func Unstage(home, vaultID string, opts Options) error {
	if err := checkID(vaultID); err != nil {
		return err
	}
	if err := os.Remove(stagedPath(home)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("keychain: remove staged key: %w", bare(err))
	}
	if mode, err := ModeOf(home, opts); err != nil || mode == ModePassphrase {
		return err
	}
	if err := opts.os().Delete(stagedID(vaultID)); err != nil && !errors.Is(err, ErrNoKey) {
		return err
	}
	return nil
}
