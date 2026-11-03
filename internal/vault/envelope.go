// Package vault is the encrypted store: the AEAD envelope, atomic writes with
// backups, the rollback counter and the layered secret body (docs/STORAGE.md).
package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

const (
	// FormatVault is the envelope format identifier, also part of the AAD.
	FormatVault = "gentle-vault/1"
	// CipherName is the only supported AEAD.
	CipherName = "xchacha20poly1305"
)

var (
	// ErrCorrupt means the vault file cannot be trusted: it is malformed, was
	// altered, or was opened with the wrong key. Messages never carry content.
	ErrCorrupt = errors.New("vault_corrupt")
	// ErrRollback means vault.enc is older than state.json says it should be.
	// It also satisfies errors.Is(err, ErrCorrupt).
	ErrRollback = fmt.Errorf("%w: vault file is older than recorded state", ErrCorrupt)
)

// AAD is the authenticated cleartext header. Field order is part of the
// format: its canonical JSON encoding is the AEAD additional data.
type AAD struct {
	Format    string `json:"format"`
	CreatedAt string `json:"created_at"`
	Writes    uint64 `json:"writes"`
}

type envelope struct {
	Format string          `json:"format"`
	Cipher string          `json:"cipher"`
	KDF    json.RawMessage `json:"kdf"`
	Nonce  string          `json:"nonce"`
	AAD    AAD             `json:"aad"`
	CT     string          `json:"ct"`
}

func corrupt(why string) error { return fmt.Errorf("%w: %s", ErrCorrupt, why) }

func checkKey(key secret.Secret) error {
	if key.Len() != chacha20poly1305.KeySize {
		return fmt.Errorf("vault: master key must be %d bytes", chacha20poly1305.KeySize)
	}
	return nil
}

// seal encrypts plaintext under key with a fresh random nonce and returns the
// envelope JSON. The caller keeps ownership of plaintext.
func seal(key secret.Secret, aad AAD, plaintext []byte) ([]byte, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	k := key.Reveal()
	defer clear(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, errors.New("vault: cipher setup failed")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("vault: random source failed")
	}
	aadBytes, err := json.Marshal(aad)
	if err != nil {
		return nil, errors.New("vault: header encoding failed")
	}
	ct := aead.Seal(nil, nonce, plaintext, aadBytes)
	return json.Marshal(envelope{
		Format: FormatVault,
		Cipher: CipherName,
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		AAD:    aad,
		CT:     base64.StdEncoding.EncodeToString(ct),
	})
}

// open verifies and decrypts an envelope. Every failure to trust the data is
// ErrCorrupt. The caller must wipe the returned plaintext.
func open(key secret.Secret, data []byte) ([]byte, AAD, error) {
	if err := checkKey(key); err != nil {
		return nil, AAD{}, err
	}
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&env); err != nil {
		return nil, AAD{}, corrupt("unreadable envelope")
	}
	if dec.More() {
		return nil, AAD{}, corrupt("trailing data")
	}
	if env.Format != FormatVault || env.AAD.Format != FormatVault {
		return nil, AAD{}, corrupt("unsupported format")
	}
	if env.Cipher != CipherName {
		return nil, AAD{}, corrupt("unsupported cipher")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, AAD{}, corrupt("bad nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, AAD{}, corrupt("bad ciphertext encoding")
	}
	k := key.Reveal()
	defer clear(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, AAD{}, errors.New("vault: cipher setup failed")
	}
	aadBytes, err := json.Marshal(env.AAD)
	if err != nil {
		return nil, AAD{}, corrupt("bad header")
	}
	pt, err := aead.Open(nil, nonce, ct, aadBytes)
	if err != nil {
		return nil, AAD{}, corrupt("authentication failed")
	}
	return pt, env.AAD, nil
}
