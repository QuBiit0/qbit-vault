package keychain

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/QuBiit0/gentle-vault/internal/perm"
	"github.com/QuBiit0/gentle-vault/internal/secret"
)

const (
	formatKey   = "gentle-vault-key/1"
	algArgon2id = "argon2id"
	saltSize    = 16

	maxT    = 10
	maxMKiB = 1 << 20 // 1 GiB
	maxP    = 16
)

// kdfParams describes how key.enc was wrapped. Field order is part of the
// format: its canonical JSON, with the format string, is the AEAD AAD, so the
// parameters cannot be altered without detection.
type kdfParams struct {
	Alg  string `json:"alg"`
	Salt string `json:"salt"`
	T    uint32 `json:"t"`
	MKiB uint32 `json:"m_kib"`
	P    uint8  `json:"p"`
}

// argonParams are the parameters new key files are written with; minMKiB is
// the lowest memory cost accepted on read. Tests lower both.
var (
	argonParams = kdfParams{Alg: algArgon2id, T: 3, MKiB: 64 * 1024, P: 4}
	minMKiB     = uint32(64 * 1024)
)

type keyFile struct {
	Format string    `json:"format"`
	KDF    kdfParams `json:"kdf"`
	Nonce  string    `json:"nonce"`
	CT     string    `json:"ct"`
}

type keyFileAAD struct {
	Format string    `json:"format"`
	KDF    kdfParams `json:"kdf"`
}

func (p kdfParams) checkBounds() error {
	if p.Alg != algArgon2id || p.T < 1 || p.T > maxT ||
		p.MKiB < minMKiB || p.MKiB > maxMKiB || p.P < 1 || p.P > maxP {
		return fmt.Errorf("%w: kdf parameters out of bounds", ErrCorrupt)
	}
	return nil
}

// askPassphrase calls the source and rejects blank input. The caller wipes
// the result.
func askPassphrase(f PassphraseFunc, confirm bool) (secret.Secret, error) {
	pass, err := f(confirm)
	if err != nil {
		return secret.Secret{}, err
	}
	b := pass.Reveal()
	defer clear(b)
	if len(bytes.TrimSpace(b)) == 0 {
		pass.Wipe()
		return secret.Secret{}, ErrEmptyPassphrase
	}
	return pass, nil
}

func derive(pass secret.Secret, salt []byte, p kdfParams) []byte {
	pb := pass.Reveal()
	defer clear(pb)
	return argon2.IDKey(pb, salt, p.T, p.MKiB, p.P, keySize)
}

func aadBytes(p kdfParams) ([]byte, error) {
	return json.Marshal(keyFileAAD{Format: formatKey, KDF: p})
}

// writeKeyFile wraps key with a key derived from pass and writes key.enc
// atomically into home.
func writeKeyFile(home string, key, pass secret.Secret) error {
	return writeKeyFileAs(home, keyFileName, key, pass)
}

// writeKeyFileAs is writeKeyFile for another file name in home (the staged
// key of a rekey).
func writeKeyFileAs(home, name string, key, pass secret.Secret) error {
	if key.Len() != keySize {
		return errors.New("keychain: master key must be 32 bytes")
	}
	salt := make([]byte, saltSize)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(salt); err != nil {
		return errors.New("keychain: random source failed")
	}
	if _, err := rand.Read(nonce); err != nil {
		return errors.New("keychain: random source failed")
	}
	params := argonParams
	params.Salt = base64.StdEncoding.EncodeToString(salt)

	dk := derive(pass, salt, params)
	defer clear(dk)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return errors.New("keychain: cipher setup failed")
	}
	aad, err := aadBytes(params)
	if err != nil {
		return errors.New("keychain: header encoding failed")
	}
	kb := key.Reveal()
	defer clear(kb)
	ct := aead.Seal(nil, nonce, kb, aad)
	out, err := json.MarshalIndent(keyFile{
		Format: formatKey,
		KDF:    params,
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		CT:     base64.StdEncoding.EncodeToString(ct),
	}, "", "  ")
	if err != nil {
		return errors.New("keychain: key file encoding failed")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fmt.Errorf("keychain: create home: %w", bare(err))
	}
	if err := perm.EnsureDir(home); err != nil {
		return fmt.Errorf("keychain: secure home: %w", bare(err))
	}
	return writeAtomic(home, name, out)
}

// readKeyFile decrypts key.enc with pass. Malformed or out-of-bounds files
// are ErrCorrupt, rejected before Argon2 runs; a failed authentication is
// ErrBadPassphrase.
func readKeyFile(home string, pass secret.Secret) (secret.Secret, error) {
	return readKeyFileAt(keyFilePath(home), pass)
}

// readKeyFileAt is readKeyFile for the key file at path.
func readKeyFileAt(path string, pass secret.Secret) (secret.Secret, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("keychain: read key file: %w", bare(err))
	}
	var f keyFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return secret.Secret{}, fmt.Errorf("%w: unreadable key file", ErrCorrupt)
	}
	if dec.More() || f.Format != formatKey {
		return secret.Secret{}, fmt.Errorf("%w: unsupported key file", ErrCorrupt)
	}
	if err := f.KDF.checkBounds(); err != nil {
		return secret.Secret{}, err
	}
	salt, err := base64.StdEncoding.DecodeString(f.KDF.Salt)
	if err != nil || len(salt) != saltSize {
		return secret.Secret{}, fmt.Errorf("%w: bad salt", ErrCorrupt)
	}
	nonce, err := base64.StdEncoding.DecodeString(f.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return secret.Secret{}, fmt.Errorf("%w: bad nonce", ErrCorrupt)
	}
	ct, err := base64.StdEncoding.DecodeString(f.CT)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("%w: bad ciphertext encoding", ErrCorrupt)
	}
	aad, err := aadBytes(f.KDF)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("%w: bad header", ErrCorrupt)
	}
	dk := derive(pass, salt, f.KDF)
	defer clear(dk)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return secret.Secret{}, errors.New("keychain: cipher setup failed")
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	defer clear(pt)
	if err != nil || len(pt) != keySize {
		return secret.Secret{}, ErrBadPassphrase
	}
	return secret.New("master", pt), nil
}
