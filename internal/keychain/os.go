package keychain

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"runtime"

	"github.com/zalando/go-keyring"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

const service = "qbit-vault"

// OSBackend stores the master key in the OS keychain through go-keyring,
// under service "qbit-vault" and account "master:<vault-id>". The value is
// the base64 of the key; go-keyring only speaks strings, so that string copy
// cannot be wiped.
type OSBackend struct{}

// NewOS returns the OS keychain backend.
func NewOS() *OSBackend { return &OSBackend{} }

// Name returns the capabilities-enum name of the keychain for this GOOS.
func (*OSBackend) Name() string {
	switch runtime.GOOS {
	case "darwin":
		return string(ModeMacOS)
	case "windows":
		return string(ModeWindows)
	default:
		return string(ModeSecretSvc)
	}
}

func account(vaultID string) string { return "master:" + vaultID }

// Available probes the keychain with a throwaway account: set, get, delete.
// Any error means unavailable.
func (*OSBackend) Available() bool {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return false
	}
	acct := "probe:" + hex.EncodeToString(r[:])
	if err := keyring.Set(service, acct, "probe"); err != nil {
		// Best effort: the entry may exist even though Set reported an error.
		_ = keyring.Delete(service, acct)
		return false
	}
	got, err := keyring.Get(service, acct)
	_ = keyring.Delete(service, acct)
	return err == nil && got == "probe"
}

// Get reads the key for vaultID. A missing entry is ErrNoKey.
func (*OSBackend) Get(vaultID string) (secret.Secret, error) {
	v, err := keyring.Get(service, account(vaultID))
	if errors.Is(err, keyring.ErrNotFound) {
		return secret.Secret{}, ErrNoKey
	}
	if err != nil {
		return secret.Secret{}, errors.New("keychain: OS keychain read failed")
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	defer clear(raw)
	if err != nil || len(raw) != keySize {
		return secret.Secret{}, ErrCorrupt
	}
	return secret.New("master", raw), nil
}

// Set stores key for vaultID, replacing any previous entry.
func (*OSBackend) Set(vaultID string, key secret.Secret) error {
	if key.Len() != keySize {
		return errors.New("keychain: master key must be 32 bytes")
	}
	raw := key.Reveal()
	defer clear(raw)
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	defer clear(enc)
	base64.StdEncoding.Encode(enc, raw)
	if err := keyring.Set(service, account(vaultID), string(enc)); err != nil {
		return errors.New("keychain: OS keychain write failed")
	}
	return nil
}

// Delete removes the entry. A missing entry is ErrNoKey.
func (*OSBackend) Delete(vaultID string) error {
	err := keyring.Delete(service, account(vaultID))
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNoKey
	}
	if err != nil {
		return errors.New("keychain: OS keychain delete failed")
	}
	return nil
}
