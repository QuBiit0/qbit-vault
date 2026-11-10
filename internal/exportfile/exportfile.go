// Package exportfile is the passphrase-sealed export of a whole vault
// (docs/STORAGE.md § Export file format): a portable copy that needs no
// server, no account and no key from the machine it came from, only the
// file and the passphrase chosen at export time.
//
// The file is a JSON header (format, cipher, created_at, kdf) plus a nonce
// and the ciphertext of the payload. The payload is sealed with the AEAD of
// internal/envelope under a key derived from the passphrase with Argon2id,
// and the whole header is the additional data, so any changed byte fails to
// open. Messages never carry content.
package exportfile

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/qbitdevz/qbit-vault/internal/envelope"
	"github.com/qbitdevz/qbit-vault/internal/perm"
	"github.com/qbitdevz/qbit-vault/internal/secret"
)

const (
	// Format is the format string of the export file.
	Format = "qbit-vault-export/1"
	// MinPassphraseChars is the shortest export passphrase accepted.
	MinPassphraseChars = 12
	// MaxFileBytes bounds the file Open reads.
	MaxFileBytes = 64 << 20

	algArgon2id = "argon2id"
	saltSize    = 16
	keySize     = 32

	maxT    = 10
	maxMKiB = 1 << 19 // 512 MiB: a crafted header cannot make Open use more
	maxP    = 16
)

// maxFileBytes is MaxFileBytes; tests lower it.
var maxFileBytes = MaxFileBytes

var (
	// ErrOpen means the file could not be opened: wrong passphrase, a changed
	// byte, a truncated file, an unknown format. The causes are not told
	// apart, on purpose.
	ErrOpen = errors.New("cannot open the export")
	// ErrShort means the passphrase is blank or shorter than MinPassphraseChars.
	ErrShort = errors.New("export passphrase too short")
	// ErrExists means the target file exists and replacing it was not asked for.
	ErrExists = errors.New("export file exists")
	// ErrWrite means the file could not be written.
	ErrWrite = errors.New("cannot write the export file")
	// ErrTooLarge means the sealed file would be larger than Read accepts, so
	// it could never be imported back.
	ErrTooLarge = errors.New("the export would be too large to import back")
)

// KDF describes how the key was derived. Its canonical JSON is part of the
// additional data.
type KDF struct {
	Alg  string `json:"alg"`
	Salt string `json:"salt"`
	T    uint32 `json:"t"`
	MKiB uint32 `json:"m_kib"`
	P    uint8  `json:"p"`
}

// kdfParams are the parameters new exports are written with: Argon2id with
// twice the memory of key.enc (128 MiB, t=3, p=4), because the file leaves the
// machine and its only protection is the passphrase. minMKiB is the lowest
// memory cost accepted on read. Tests lower both.
var (
	kdfParams = KDF{Alg: algArgon2id, T: 3, MKiB: 128 * 1024, P: 4}
	minMKiB   = uint32(64 * 1024)
)

// header is the authenticated cleartext. Field order is part of the format.
type header struct {
	Format    string `json:"format"`
	Cipher    string `json:"cipher"`
	CreatedAt string `json:"created_at"`
	KDF       KDF    `json:"kdf"`
}

type fileJSON struct {
	Format    string `json:"format"`
	Cipher    string `json:"cipher"`
	CreatedAt string `json:"created_at"`
	KDF       KDF    `json:"kdf"`
	Nonce     string `json:"nonce"`
	CT        string `json:"ct"`
}

// Record is one secret with its metadata. Value is base64 in the payload.
type Record struct {
	Name        string   `json:"name"`
	Value       []byte   `json:"value"`
	Kind        string   `json:"kind,omitempty"`
	Description string   `json:"description"`
	Sensitive   bool     `json:"sensitive"`
	Binaries    []string `json:"binaries"`
	Hosts       []string `json:"hosts"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// Layer is the global layer or one project layer (identified by its root).
type Layer struct {
	Project bool     `json:"project"`
	Root    string   `json:"root,omitempty"`
	Label   string   `json:"label,omitempty"`
	Records []Record `json:"records"`
}

// Payload is what an export seals: every layer and every record. It holds
// no grant, token, audit data, key or sync state.
type Payload struct {
	Layers []Layer `json:"layers"`
}

// Wipe zeroes every value in p.
func (p *Payload) Wipe() {
	for _, l := range p.Layers {
		for _, r := range l.Records {
			clear(r.Value)
		}
	}
}

// CheckPassphrase enforces the export passphrase floor: not blank, at least
// MinPassphraseChars characters.
func CheckPassphrase(pass secret.Secret) error {
	b := pass.Reveal()
	defer clear(b)
	if len(bytes.TrimSpace(b)) == 0 || utf8.RuneCount(b) < MinPassphraseChars {
		return ErrShort
	}
	return nil
}

func (k KDF) checkBounds() error {
	if k.Alg != algArgon2id || k.T < 1 || k.T > maxT || k.MKiB < minMKiB || k.MKiB > maxMKiB || k.P < 1 || k.P > maxP {
		return ErrOpen
	}
	return nil
}

func derive(pass secret.Secret, salt []byte, k KDF) secret.Secret {
	pb := pass.Reveal()
	defer clear(pb)
	dk := argon2.IDKey(pb, salt, k.T, k.MKiB, k.P, keySize)
	defer clear(dk)
	return secret.New("export", dk)
}

// Seal encrypts p under pass and returns the file bytes. The caller checks
// the passphrase with CheckPassphrase first and keeps ownership of both.
func Seal(pass secret.Secret, p Payload, at time.Time) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("exportfile: random source failed")
	}
	k := kdfParams
	k.Salt = base64.StdEncoding.EncodeToString(salt)
	h := header{Format: Format, Cipher: envelope.CipherName, CreatedAt: at.UTC().Format(time.RFC3339), KDF: k}
	aad, err := json.Marshal(h)
	if err != nil {
		return nil, errors.New("exportfile: header encoding failed")
	}
	pt, err := json.Marshal(p)
	if err != nil {
		return nil, errors.New("exportfile: payload encoding failed")
	}
	defer clear(pt)
	key := derive(pass, salt, k)
	defer key.Wipe()
	nonce, ct, err := envelope.SealRaw(key, aad, pt)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(fileJSON{
		Format: h.Format, Cipher: h.Cipher, CreatedAt: h.CreatedAt, KDF: k,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	})
	if err != nil {
		return nil, errors.New("exportfile: file encoding failed")
	}
	if len(out)+1 > maxFileBytes {
		return nil, ErrTooLarge
	}
	return append(out, '\n'), nil
}

// Open verifies and decrypts a file. Every failure to trust it is ErrOpen,
// rejected before Argon2 runs when the header is malformed or out of bounds.
// The caller wipes the payload (Payload.Wipe).
func Open(pass secret.Secret, data []byte) (Payload, error) {
	var f fileJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || dec.More() {
		return Payload{}, ErrOpen
	}
	if f.Format != Format || f.Cipher != envelope.CipherName {
		return Payload{}, ErrOpen
	}
	if err := f.KDF.checkBounds(); err != nil {
		return Payload{}, err
	}
	salt, err := base64.StdEncoding.DecodeString(f.KDF.Salt)
	if err != nil || len(salt) != saltSize {
		return Payload{}, ErrOpen
	}
	nonce, err := base64.StdEncoding.DecodeString(f.Nonce)
	if err != nil {
		return Payload{}, ErrOpen
	}
	ct, err := base64.StdEncoding.DecodeString(f.CT)
	if err != nil {
		return Payload{}, ErrOpen
	}
	aad, err := json.Marshal(header{Format: f.Format, Cipher: f.Cipher, CreatedAt: f.CreatedAt, KDF: f.KDF})
	if err != nil {
		return Payload{}, ErrOpen
	}
	key := derive(pass, salt, f.KDF)
	defer key.Wipe()
	pt, err := envelope.OpenRaw(key, aad, nonce, ct)
	if err != nil {
		return Payload{}, ErrOpen
	}
	defer clear(pt)
	var p Payload
	pdec := json.NewDecoder(bytes.NewReader(pt))
	pdec.DisallowUnknownFields()
	if err := pdec.Decode(&p); err != nil || pdec.More() {
		p.Wipe()
		return Payload{}, ErrOpen
	}
	for _, l := range p.Layers {
		if l.Project && l.Root == "" {
			p.Wipe()
			return Payload{}, ErrOpen
		}
	}
	return p, nil
}

// Read reads the file at path, bounded by MaxFileBytes.
func Read(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, ErrRead
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, int64(maxFileBytes)+1))
	if err != nil || len(data) > maxFileBytes {
		return nil, ErrRead
	}
	return data, nil
}

// ErrRead means the export file could not be read (or is far too large).
var ErrRead = errors.New("cannot read the export file")

// Exists reports whether something is at path, a dangling link included.
func Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Write stores data at path atomically: a temp file in the same directory,
// owner-only, fsynced, then renamed over the target. Without force an
// existing target is ErrExists and nothing is written. The temp file is
// removed on every failure.
func Write(path string, data []byte, force bool) error {
	if !force && Exists(path) {
		return ErrExists
	}
	dir := filepath.Dir(path)
	var sfx [4]byte
	if _, err := rand.Read(sfx[:]); err != nil {
		return ErrWrite
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.tmp.%d.%x", filepath.Base(path), os.Getpid(), sfx))
	fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrWrite
	}
	fail := func() error {
		_ = fh.Close()
		_ = os.Remove(tmp)
		return ErrWrite
	}
	if _, err := fh.Write(data); err != nil {
		return fail()
	}
	if err := fh.Sync(); err != nil {
		return fail()
	}
	if err := fh.Close(); err != nil {
		_ = os.Remove(tmp)
		return ErrWrite
	}
	if err := perm.EnsureFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return ErrWrite
	}
	if !force && Exists(path) {
		_ = os.Remove(tmp)
		return ErrExists
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return ErrWrite
	}
	if runtime.GOOS != "windows" {
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}
