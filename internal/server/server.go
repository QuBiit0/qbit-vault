// Package server is gentle-vault-server (docs/REMOTE_SYNC.md § 5-6, 10): a
// zero-knowledge store for vaults sealed on the devices. It authenticates
// devices by signature, keeps versions with compare-and-swap, and stores
// only ciphertext, public keys, counters and timestamps. It never sees a key
// that opens anything, and never logs bodies, tokens or codes.
package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/remote"
)

const (
	// API is the major version every response carries.
	API = 1
	// MaxBlob bounds one sealed vault version.
	MaxBlob    = 8 << 20
	maxBody    = 9 << 20
	tokenTTL   = 15 * time.Minute
	nonceTTL   = 60 * time.Second
	maxDevices = 20
)

var (
	accountRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	deviceRE  = regexp.MustCompile(`^[0-9a-f]{32}$|^[a-z0-9]{1,64}$`)
)

// Config configures a server.
type Config struct {
	Data       string           // data directory
	PublicURL  string           // the origin clients sign (auth binds it)
	Now        func() time.Time // clock; time.Now when nil
	Log        io.Writer        // request log; discarded when nil
	TrustProxy bool             // take the client IP from X-Forwarded-For
	Version    string
}

// Server is one instance over one data directory.
type Server struct {
	cfg   Config
	st    *store
	mu    sync.Mutex
	locks map[string]*sync.Mutex

	nonces map[string]nonceRec
	tokens map[string]tokenRec

	authLimit, pairLimit, recoveryLimit, recoveryDaily *limiter
}

type nonceRec struct {
	device  string
	expires time.Time
}

type tokenRec struct {
	account, device string
	recovery        bool
	expires         time.Time
}

// New opens a server over cfg.Data.
func New(cfg Config) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	if !strings.HasPrefix(cfg.PublicURL, "https://") && !strings.HasPrefix(cfg.PublicURL, "http://") {
		return nil, errors.New("server: the public URL must be http(s)://host")
	}
	if err := os.MkdirAll(cfg.Data, 0o700); err != nil {
		return nil, fmt.Errorf("server: data directory: %w", err)
	}
	return &Server{cfg: cfg, st: &store{dir: cfg.Data}, locks: map[string]*sync.Mutex{},
		nonces: map[string]nonceRec{}, tokens: map[string]tokenRec{},
		authLimit: newLimiter(30, time.Minute), pairLimit: newLimiter(5, time.Minute),
		recoveryLimit: newLimiter(5, time.Minute), recoveryDaily: newLimiter(20, 24*time.Hour)}, nil
}

// AuthMessage is what a device signs to get a token (remote.AuthMessage).
func AuthMessage(origin string, nonce []byte) []byte { return remote.AuthMessage(origin, nonce) }

// Invite creates a single-use account invite valid for ttl; only its hash
// is stored. The code is an operator credential, not a vault secret.
func (s *Server) Invite(ttl time.Duration) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b[:])
	exp := s.cfg.Now().Add(ttl).UTC().Format(time.RFC3339Nano)
	return code, writeJSON(s.st.path("invites", hash(code)), map[string]string{"expires_at": exp})
}

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func (s *Server) lock(account string) func() {
	s.mu.Lock()
	m := s.locks[account]
	if m == nil {
		m = &sync.Mutex{}
		s.locks[account] = m
	}
	s.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// Handler routes the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, map[string]any{"ok": true}) })
	mux.HandleFunc("GET /v1/info", s.info)
	mux.HandleFunc("POST /v1/accounts", s.createAccount)
	mux.HandleFunc("POST /v1/auth/challenge", s.challenge)
	mux.HandleFunc("POST /v1/auth/token", s.token)
	mux.HandleFunc("GET /v1/vault", s.authed(s.getVault))
	mux.HandleFunc("GET /v1/vault/versions", s.authed(s.listVersions))
	mux.HandleFunc("PUT /v1/vault", s.authed(s.putVault))
	mux.HandleFunc("GET /v1/devices", s.authed(s.listDevices))
	mux.HandleFunc("DELETE /v1/devices/self", s.authed(s.deleteSelf))
	s.routesS5(mux)
	return s.logged(mux)
}

// ---- plumbing ----

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

// logged writes one line per request: method, route pattern, status,
// duration. Never bodies, tokens, codes or the client address.
func (s *Server) logged(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.cfg.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		h.ServeHTTP(sw, r)
		pattern := r.Pattern
		if pattern == "" {
			pattern = r.Method + " (unrouted)"
		}
		fmt.Fprintf(s.cfg.Log, "%s %s %d %dms\n", start.UTC().Format(time.RFC3339), pattern, sw.code, s.cfg.Now().Sub(start).Milliseconds())
	})
}

func reply(w http.ResponseWriter, code int, body map[string]any) {
	body["api"] = API
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	reply(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			fail(w, 413, "too_large", "request too large")
		} else {
			fail(w, 400, "invalid", "malformed request")
		}
		return false
	}
	return true
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			ip, _, _ := strings.Cut(f, ",")
			return strings.TrimSpace(ip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func unb64(s string, n int) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	return b, err == nil && (n == 0 || len(b) == n)
}

func newToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

type caller struct {
	account, device string
	token           string
}

// authed requires a device token.
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		t, found := s.tokens[tok]
		if found && !s.cfg.Now().Before(t.expires) {
			delete(s.tokens, tok)
			found = false
		}
		s.mu.Unlock()
		if !ok || !found || t.recovery {
			fail(w, 401, "unauthorized", "a device token is required")
			return
		}
		h(w, r, caller{account: t.account, device: t.device, token: tok})
	}
}

// ---- handlers ----

func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	reply(w, 200, map[string]any{"version": s.cfg.Version, "limits": map[string]any{
		"max_blob": MaxBlob, "max_devices": maxDevices, "versions_kept": keepVersions}})
}

// blobAAD reads the cleartext AAD of a sealed vault version: the server
// cannot open it, but it checks that the client labelled it consistently.
func blobAAD(blob string) (acct string, gen int, version int64, ok bool) {
	var o struct {
		Format string `json:"format"`
		AAD    struct {
			AccountID  string `json:"account_id"`
			Generation int    `json:"generation"`
			Version    int64  `json:"version"`
		} `json:"aad"`
	}
	if json.Unmarshal([]byte(blob), &o) != nil || o.Format != "gentle-vault-remote/1" {
		return "", 0, 0, false
	}
	return o.AAD.AccountID, o.AAD.Generation, o.AAD.Version, true
}

type deviceIn struct {
	ID      string `json:"id"`
	SignPub string `json:"sign_pub"`
	BoxPub  string `json:"box_pub"`
}

func (d deviceIn) valid() bool {
	_, ok1 := unb64(d.SignPub, ed25519.PublicKeySize)
	_, ok2 := unb64(d.BoxPub, 32)
	return deviceRE.MatchString(d.ID) && ok1 && ok2
}

type recoveryIn struct {
	LookupID string `json:"lookup_id"`
	Auth     string `json:"auth"`
	Envelope string `json:"envelope"`
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Invite      string     `json:"invite"`
		AccountID   string     `json:"account_id"`
		Device      deviceIn   `json:"device"`
		Recovery    recoveryIn `json:"recovery"`
		KeyEnvelope string     `json:"key_envelope"`
		Vault       string     `json:"vault"`
	}
	if !decode(w, r, &in) {
		return
	}
	invitePath := s.st.path("invites", hash(in.Invite))
	var inv struct {
		ExpiresAt string `json:"expires_at"`
	}
	if readJSON(invitePath, &inv) != nil {
		fail(w, 401, "unauthorized", "invalid invite")
		return
	}
	if exp, err := time.Parse(time.RFC3339Nano, inv.ExpiresAt); err != nil || !s.cfg.Now().Before(exp) {
		_ = os.Remove(invitePath)
		fail(w, 401, "unauthorized", "invalid invite")
		return
	}
	acctID, gen, ver, ok := blobAAD(in.Vault)
	if !accountRE.MatchString(in.AccountID) || !in.Device.valid() || in.Recovery.LookupID == "" || in.Recovery.Auth == "" ||
		!ok || acctID != in.AccountID || gen != 1 || ver != 1 || len(in.Vault) > MaxBlob {
		fail(w, 400, "invalid", "malformed account")
		return
	}
	defer s.lock(in.AccountID)()
	if _, err := os.Stat(s.st.path("accounts", in.AccountID)); err == nil {
		fail(w, 409, "conflict", "account exists")
		return
	}
	if _, err := s.st.accountOfDevice(in.Device.ID); err == nil {
		fail(w, 409, "conflict", "device exists")
		return
	}
	now := s.cfg.Now().UTC().Format(time.RFC3339)
	a := &account{ID: in.AccountID, CreatedAt: now, Version: 1, Generation: 1,
		Recovery: recoveryRec{LookupID: in.Recovery.LookupID, AuthHash: hash(in.Recovery.Auth), Envelope: in.Recovery.Envelope},
		Devices:  map[string]deviceRec{in.Device.ID: {SignPub: in.Device.SignPub, BoxPub: in.Device.BoxPub, CreatedAt: now, KeyEnvelope: in.KeyEnvelope, Generation: 1}}}
	if err := s.st.putVersion(a.ID, 1, in.Vault); err != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	if err := s.st.saveAccount(a); err != nil || s.st.indexDevice(in.Device.ID, a.ID) != nil ||
		writeFile(s.st.path("recovery", hash(in.Recovery.LookupID)), []byte(a.ID)) != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	_ = os.Remove(invitePath) // single use
	reply(w, 200, map[string]any{"account_id": a.ID, "version": 1})
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.authLimit.allow("dev:"+in.DeviceID, s.cfg.Now()) || !s.authLimit.allow("ip:"+s.clientIP(r), s.cfg.Now()) {
		fail(w, 429, "rate_limited", "too many attempts")
		return
	}
	if _, err := s.st.accountOfDevice(in.DeviceID); err != nil || !deviceRE.MatchString(in.DeviceID) {
		fail(w, 401, "unauthorized", "unknown device")
		return
	}
	var n [32]byte
	_, _ = rand.Read(n[:])
	nonce := base64.StdEncoding.EncodeToString(n[:])
	s.mu.Lock()
	s.nonces[nonce] = nonceRec{device: in.DeviceID, expires: s.cfg.Now().Add(nonceTTL)}
	s.mu.Unlock()
	reply(w, 200, map[string]any{"nonce": nonce, "expires_in": int(nonceTTL.Seconds())})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DeviceID string `json:"device_id"`
		Nonce    string `json:"nonce"`
		Sig      string `json:"sig"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	n, ok := s.nonces[in.Nonce]
	delete(s.nonces, in.Nonce) // single use, success or not
	s.mu.Unlock()
	if !ok || n.device != in.DeviceID || !s.cfg.Now().Before(n.expires) {
		fail(w, 401, "unauthorized", "invalid challenge")
		return
	}
	acctID, err := s.st.accountOfDevice(in.DeviceID)
	if err != nil {
		fail(w, 401, "unauthorized", "unknown device")
		return
	}
	defer s.lock(acctID)()
	a, err := s.st.loadAccount(acctID)
	if err != nil {
		fail(w, 401, "unauthorized", "unknown device")
		return
	}
	d, ok := a.Devices[in.DeviceID]
	pub, okPub := unb64(d.SignPub, ed25519.PublicKeySize)
	nonce, _ := base64.StdEncoding.DecodeString(in.Nonce)
	sig, _ := base64.StdEncoding.DecodeString(in.Sig)
	if !ok || !okPub || !ed25519.Verify(pub, AuthMessage(s.cfg.PublicURL, nonce), sig) {
		fail(w, 401, "unauthorized", "invalid signature")
		return
	}
	d.LastSeen = s.cfg.Now().UTC().Format(time.RFC3339)
	a.Devices[in.DeviceID] = d
	_ = s.st.saveAccount(a)
	tok := newToken()
	s.mu.Lock()
	s.tokens[tok] = tokenRec{account: acctID, device: in.DeviceID, expires: s.cfg.Now().Add(tokenTTL)}
	s.mu.Unlock()
	reply(w, 200, map[string]any{"token": tok, "expires_in": int(tokenTTL.Seconds())})
}

func (s *Server) getVault(w http.ResponseWriter, r *http.Request, c caller) {
	a, err := s.st.loadAccount(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	v := a.Version
	if q := r.URL.Query().Get("version"); q != "" {
		n, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			fail(w, 400, "invalid", "bad version")
			return
		}
		v = n
	} else if r.Header.Get("If-None-Match") == strconv.FormatInt(a.Version, 10) {
		w.WriteHeader(304)
		return
	}
	blob, err := s.st.getVersion(c.account, v)
	if err != nil {
		fail(w, 404, "not_found", "no such version")
		return
	}
	reply(w, 200, map[string]any{"version": v, "generation": a.Generation, "blob": blob})
}

func (s *Server) listVersions(w http.ResponseWriter, _ *http.Request, c caller) {
	vs, err := s.st.versions(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	out := []any{}
	for _, v := range vs {
		blob, _ := s.st.getVersion(c.account, v)
		var o struct {
			AAD struct {
				Writer    string `json:"writer"`
				CreatedAt string `json:"created_at"`
			} `json:"aad"`
		}
		_ = json.Unmarshal([]byte(blob), &o)
		out = append(out, map[string]any{"version": v, "writer": o.AAD.Writer, "created_at": o.AAD.CreatedAt})
	}
	reply(w, 200, map[string]any{"versions": out})
}

func (s *Server) putVault(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		BaseVersion int64  `json:"base_version"`
		Blob        string `json:"blob"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Blob) > MaxBlob {
		fail(w, 413, "too_large", "vault version too large")
		return
	}
	defer s.lock(c.account)()
	a, err := s.st.loadAccount(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	if in.BaseVersion != a.Version {
		reply(w, 409, map[string]any{"version": a.Version, "error": map[string]any{"code": "conflict", "message": "a newer version exists"}})
		return
	}
	acct, gen, ver, ok := blobAAD(in.Blob)
	if !ok || acct != c.account || gen != a.Generation || ver != a.Version+1 {
		fail(w, 400, "invalid", "the version is not labelled for this account and version")
		return
	}
	if err := s.st.putVersion(c.account, ver, in.Blob); err != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	a.Version = ver
	if err := s.st.saveAccount(a); err != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	reply(w, 200, map[string]any{"version": ver})
}

func (s *Server) listDevices(w http.ResponseWriter, _ *http.Request, c caller) {
	a, err := s.st.loadAccount(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	out := []any{}
	for id, d := range a.Devices {
		out = append(out, map[string]any{"id": id, "sign_pub": d.SignPub, "box_pub": d.BoxPub, "created_at": d.CreatedAt, "last_seen": d.LastSeen})
	}
	reply(w, 200, map[string]any{"devices": out})
}

func (s *Server) deleteSelf(w http.ResponseWriter, _ *http.Request, c caller) {
	defer s.lock(c.account)()
	a, err := s.st.loadAccount(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	delete(a.Devices, c.device)
	if err := s.st.saveAccount(a); err != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	s.st.unindexDevice(c.device)
	s.dropTokens(c.device)
	reply(w, 200, map[string]any{"deleted": true})
}

// dropTokens ends every session of device.
func (s *Server) dropTokens(device string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.tokens {
		if t.device == device {
			delete(s.tokens, k)
		}
	}
}

// constantEq compares secrets' hashes in constant time.
func constantEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
