// Package keychain holds the vault master key: in the OS keychain when one is
// reachable, otherwise wrapped by a passphrase in key.enc (docs/STORAGE.md
// § Master key). The mode is implied by the files: key.enc present means
// passphrase mode, otherwise the OS keychain.
package keychain

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/secret"
)

const (
	keySize     = 32
	keyFileName = "key.enc"
	// DefaultCacheTTL is how long an unlocked passphrase key stays cached.
	DefaultCacheTTL = 8 * time.Hour
)

// Mode names how the master key is held. The values match the capabilities
// enum of the broker contract.
type Mode string

const (
	ModeMacOS      Mode = "macos-keychain"
	ModeWindows    Mode = "windows-credential-manager"
	ModeSecretSvc  Mode = "secret-service"
	ModePassphrase Mode = "passphrase-file"
)

var (
	// ErrNoKey means no master key is stored for the vault id.
	ErrNoKey = errors.New("keychain: no master key stored for this vault")
	// ErrKeyExists means Setup found a master key already stored for the id.
	ErrKeyExists = errors.New("keychain: a master key already exists for this vault")
	// ErrUnavailable means no OS keychain is reachable and no passphrase
	// source was supplied.
	ErrUnavailable = errors.New("keychain: no keychain available and no passphrase source")
	// ErrBadPassphrase is the fixed answer for a wrong passphrase or a key
	// file that fails authentication. It never carries input.
	ErrBadPassphrase = errors.New("keychain: wrong passphrase or key file altered")
	// ErrEmptyPassphrase means the passphrase was blank.
	ErrEmptyPassphrase = errors.New("keychain: passphrase must not be empty")
	// ErrCorrupt means stored key material is malformed or out of bounds.
	ErrCorrupt = errors.New("keychain: stored key material is corrupt")
)

// Backend stores one master key per vault id.
type Backend interface {
	Name() string
	Get(vaultID string) (secret.Secret, error)
	Set(vaultID string, key secret.Secret) error
	Delete(vaultID string) error
}

// PassphraseFunc asks the user for the passphrase out of band. With confirm
// true (first setup) the implementation asks twice and checks both match.
// The caller owns and wipes the returned secret.
type PassphraseFunc func(confirm bool) (secret.Secret, error)

// Options configures Setup, Unlock and Lock. The zero value uses the real OS
// keychain, no passphrase source, the real environment and an 8 h cache.
type Options struct {
	Passphrase      PassphraseFunc
	ForcePassphrase bool
	CacheTTL        time.Duration

	backend Backend // test seam: replaces the OS backend
	getenv  func(string) string
	now     func() time.Time
	goos    string // test seam: replaces runtime.GOOS
}

func (o Options) env(k string) string {
	if o.getenv != nil {
		return o.getenv(k)
	}
	return os.Getenv(k)
}

func (o Options) platform() string {
	if o.goos != "" {
		return o.goos
	}
	return runtime.GOOS
}

func (o Options) clock() time.Time {
	if o.now != nil {
		return o.now()
	}
	return time.Now()
}

func (o Options) ttl() time.Duration {
	if o.CacheTTL > 0 {
		return o.CacheTTL
	}
	return DefaultCacheTTL
}

func (o Options) os() Backend {
	if o.backend != nil {
		return o.backend
	}
	return NewOS()
}

// available reports whether the OS backend is usable. A backend without a
// probe is assumed reachable.
func available(b Backend) bool {
	if p, ok := b.(interface{ Available() bool }); ok {
		return p.Available()
	}
	return true
}

var idRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// checkID guards the vault id, which becomes part of an account name and of
// a cache file name.
func checkID(id string) error {
	if !idRE.MatchString(id) {
		return errors.New("keychain: vault id must be a lowercase uuid")
	}
	return nil
}

func newKey() (secret.Secret, error) {
	b := make([]byte, keySize)
	defer clear(b)
	if _, err := rand.Read(b); err != nil {
		return secret.Secret{}, errors.New("keychain: random source failed")
	}
	return secret.New("master", b), nil
}

func keyFilePath(home string) string { return filepath.Join(home, keyFileName) }

func fileExists(p string) (bool, error) {
	_, err := os.Stat(p)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("keychain: stat key file: %w", bare(err))
	}
}

// bare drops the path from a filesystem error.
func bare(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// Setup generates the master key and stores it: in the OS keychain when one
// is reachable (unless ForcePassphrase), otherwise in key.enc wrapped by a
// passphrase asked with confirm=true. It refuses if a key already exists for
// the id. The caller owns the returned key and must wipe it.
func Setup(home, vaultID string, opts Options) (secret.Secret, Mode, error) {
	if err := checkID(vaultID); err != nil {
		return secret.Secret{}, "", err
	}
	exists, err := fileExists(keyFilePath(home))
	if err != nil {
		return secret.Secret{}, "", err
	}
	if exists {
		return secret.Secret{}, "", ErrKeyExists
	}
	osb := opts.os()
	osUp := available(osb)
	if osUp && !opts.ForcePassphrase {
		return setupOS(osb, vaultID)
	}
	// Passphrase mode. An OS entry for this id also counts as an existing key.
	if osUp {
		k, err := osb.Get(vaultID)
		switch {
		case err == nil:
			k.Wipe()
			return secret.Secret{}, "", ErrKeyExists
		case !errors.Is(err, ErrNoKey):
			// Not "no key": an entry may exist behind a keychain we could
			// not read, so do not create a second key next to it.
			return secret.Secret{}, "", err
		}
	}
	if opts.Passphrase == nil {
		return secret.Secret{}, "", ErrUnavailable
	}
	return setupPassphrase(home, vaultID, opts)
}

func setupOS(b Backend, vaultID string) (secret.Secret, Mode, error) {
	if k, err := b.Get(vaultID); err == nil {
		k.Wipe()
		return secret.Secret{}, "", ErrKeyExists
	} else if !errors.Is(err, ErrNoKey) {
		return secret.Secret{}, "", err
	}
	key, err := newKey()
	if err != nil {
		return secret.Secret{}, "", err
	}
	if err := b.Set(vaultID, key); err != nil {
		key.Wipe()
		return secret.Secret{}, "", err
	}
	return key, Mode(b.Name()), nil
}

func setupPassphrase(home, vaultID string, opts Options) (secret.Secret, Mode, error) {
	pass, err := askPassphrase(opts.Passphrase, true)
	if err != nil {
		return secret.Secret{}, "", err
	}
	defer pass.Wipe()
	key, err := newKey()
	if err != nil {
		return secret.Secret{}, "", err
	}
	if err := writeKeyFile(home, key, pass); err != nil {
		key.Wipe()
		return secret.Secret{}, "", err
	}
	cachePut(opts, vaultID, key)
	return key, ModePassphrase, nil
}

// Unlock returns the master key. With key.enc present it uses passphrase
// mode: the runtime cache first, then the passphrase prompt. Otherwise it
// reads the OS keychain. The caller owns the key and must wipe it.
func Unlock(home, vaultID string, opts Options) (secret.Secret, Mode, error) {
	if err := checkID(vaultID); err != nil {
		return secret.Secret{}, "", err
	}
	exists, err := fileExists(keyFilePath(home))
	if err != nil {
		return secret.Secret{}, "", err
	}
	if !exists {
		b := opts.os()
		key, err := b.Get(vaultID)
		if err != nil {
			return secret.Secret{}, "", err
		}
		return key, Mode(b.Name()), nil
	}
	if key, ok := cacheGet(opts, vaultID); ok {
		return key, ModePassphrase, nil
	}
	if opts.Passphrase == nil {
		return secret.Secret{}, "", ErrUnavailable
	}
	pass, err := askPassphrase(opts.Passphrase, false)
	if err != nil {
		return secret.Secret{}, "", err
	}
	defer pass.Wipe()
	key, err := readKeyFile(home, pass)
	if err != nil {
		return secret.Secret{}, "", err
	}
	cachePut(opts, vaultID, key)
	return key, ModePassphrase, nil
}

// ModeOf reports how the master key of home is held, from the files alone:
// key.enc present means passphrase mode, otherwise the OS keychain. It reads
// no key.
func ModeOf(home string, opts Options) (Mode, error) {
	exists, err := fileExists(keyFilePath(home))
	if err != nil {
		return "", err
	}
	if exists {
		return ModePassphrase, nil
	}
	return Mode(opts.os().Name()), nil
}

// Refresh is Unlock for `qbit-vault unlock`: in passphrase mode it always
// asks the passphrase (it never trusts the cache), verifies it against
// key.enc and caches the key where a cache exists. cached reports whether the
// key is now cached, until exp. A wrong passphrase leaves the cache as it
// was. In keychain mode it reads the OS keychain and caches nothing. The
// caller owns the key and must wipe it.
func Refresh(home, vaultID string, opts Options) (key secret.Secret, mode Mode, cached bool, exp time.Time, err error) {
	if err := checkID(vaultID); err != nil {
		return secret.Secret{}, "", false, time.Time{}, err
	}
	if mode, err = ModeOf(home, opts); err != nil {
		return secret.Secret{}, "", false, time.Time{}, err
	}
	if mode != ModePassphrase {
		b := opts.os()
		key, err := b.Get(vaultID)
		return key, Mode(b.Name()), false, time.Time{}, err
	}
	if opts.Passphrase == nil {
		return secret.Secret{}, "", false, time.Time{}, ErrUnavailable
	}
	pass, err := askPassphrase(opts.Passphrase, false)
	if err != nil {
		return secret.Secret{}, "", false, time.Time{}, err
	}
	defer pass.Wipe()
	if key, err = readKeyFile(home, pass); err != nil {
		return secret.Secret{}, "", false, time.Time{}, err
	}
	if cacheDir(opts) == "" {
		return key, ModePassphrase, false, time.Time{}, nil
	}
	exp = opts.clock().Add(opts.ttl())
	cachePutUntil(opts, vaultID, key, exp)
	if k, ok := cacheGet(opts, vaultID); ok {
		k.Wipe()
		return key, ModePassphrase, true, exp, nil
	}
	return key, ModePassphrase, false, time.Time{}, nil
}

// Lock deletes the unlock cache for the vault. It is a no-op when there is
// no cache.
func Lock(vaultID string, opts Options) error {
	if err := checkID(vaultID); err != nil {
		return err
	}
	return cacheDelete(opts, vaultID)
}
