// Package vault is the encrypted store: the AEAD envelope, atomic writes with
// backups, the rollback counter and the layered secret body (docs/STORAGE.md).
package vault

import (
	"fmt"

	"github.com/QuBiit0/gentle-vault/internal/envelope"
	"github.com/QuBiit0/gentle-vault/internal/secret"
)

const (
	// FormatVault is the envelope format identifier, also part of the AAD.
	FormatVault = "gentle-vault/1"
	// FormatGrants identifies grants.enc.
	FormatGrants = "gentle-vault-grants/1"
	// CipherName is the only supported AEAD.
	CipherName = envelope.CipherName
)

var (
	// ErrCorrupt means the vault file cannot be trusted: it is malformed, was
	// altered, or was opened with the wrong key. Messages never carry content.
	ErrCorrupt = envelope.ErrCorrupt
	// ErrRollback means vault.enc is older than state.json says it should be.
	// It also satisfies errors.Is(err, ErrCorrupt).
	ErrRollback = fmt.Errorf("%w: vault file is older than recorded state", ErrCorrupt)
)

// AAD is the authenticated cleartext header (see internal/envelope).
type AAD = envelope.AAD

func corrupt(why string) error { return fmt.Errorf("%w: %s", ErrCorrupt, why) }

func checkKey(key secret.Secret) error { return envelope.CheckKey(key) }

// seal encrypts plaintext as a vault.enc envelope.
func seal(key secret.Secret, aad AAD, plaintext []byte) ([]byte, error) {
	return envelope.Seal(FormatVault, key, aad, plaintext)
}

// open verifies and decrypts a vault.enc envelope. The caller must wipe the
// returned plaintext.
func open(key secret.Secret, data []byte) ([]byte, AAD, error) {
	return envelope.Open(FormatVault, key, data)
}
