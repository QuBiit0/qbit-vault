package server

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/remote"
)

const (
	pairingTTL     = 10 * time.Minute
	recoveryTTL    = 10 * time.Minute
	keepAnchors    = 100
	maxAnchorBytes = 4096
)

// routesS5 registers pairing, recovery, rekey and anchors (REMOTE_SYNC.md §
// 4-6, 8).
func (s *Server) routesS5(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/pairings", s.createPairing)
	mux.HandleFunc("GET /v1/pairings/{code}", s.readPairing)
	mux.HandleFunc("POST /v1/pairings/{code}/approve", s.authed(s.approvePairing))
	mux.HandleFunc("POST /v1/recovery/token", s.recoveryToken)
	mux.HandleFunc("GET /v1/recovery/envelope", s.recoveryAuthed(s.recoveryEnvelope))
	mux.HandleFunc("POST /v1/devices", s.recoveryAuthed(s.recoveryDevice))
	mux.HandleFunc("GET /v1/keys/self", s.authed(s.keysSelf))
	mux.HandleFunc("POST /v1/rekey", s.authed(s.rekey))
	mux.HandleFunc("PUT /v1/anchors", s.authed(s.putAnchor))
	mux.HandleFunc("GET /v1/anchors", s.authed(s.getAnchors))
}

type pairing struct {
	DeviceID      string `json:"device_id"`
	SignPub       string `json:"sign_pub"`
	BoxPub        string `json:"box_pub"`
	PollHash      string `json:"poll_hash"`
	ExpiresAt     string `json:"expires_at"`
	Status        string `json:"status"`
	AccountID     string `json:"account_id,omitempty"`
	Envelope      string `json:"envelope,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	IssuerSignPub string `json:"issuer_sign_pub,omitempty"`
}

func (s *Server) pairingPath(code string) string { return s.st.path("pairings", hash(code)) }

func (s *Server) loadPairing(code string) (*pairing, bool) {
	var p pairing
	if readJSON(s.pairingPath(code), &p) != nil {
		return nil, false
	}
	if exp, err := time.Parse(time.RFC3339Nano, p.ExpiresAt); err != nil || !s.cfg.Now().Before(exp) {
		_ = os.Remove(s.pairingPath(code))
		return nil, false
	}
	return &p, true
}

// createPairing: a new device announces its keys under the code that
// fingerprints them; the server checks the fingerprint so a pairing can only
// ever carry the keys its code names.
func (s *Server) createPairing(w http.ResponseWriter, r *http.Request) {
	if !s.pairLimit.allow(s.clientIP(r), s.cfg.Now()) {
		fail(w, 429, "rate_limited", "too many pairings")
		return
	}
	var in struct {
		Code     string `json:"code"`
		DeviceID string `json:"device_id"`
		SignPub  string `json:"sign_pub"`
		BoxPub   string `json:"box_pub"`
	}
	if !decode(w, r, &in) {
		return
	}
	d := deviceIn{ID: in.DeviceID, SignPub: in.SignPub, BoxPub: in.BoxPub}
	sp, _ := unb64(in.SignPub, 0)
	bp, _ := unb64(in.BoxPub, 0)
	if !d.valid() || remote.PairingCode(sp, bp) != in.Code {
		fail(w, 400, "invalid", "the code does not fingerprint these keys")
		return
	}
	if _, err := s.st.accountOfDevice(in.DeviceID); err == nil {
		fail(w, 409, "conflict", "device exists")
		return
	}
	secret := newToken()
	p := pairing{DeviceID: in.DeviceID, SignPub: in.SignPub, BoxPub: in.BoxPub, PollHash: hash(secret),
		ExpiresAt: s.cfg.Now().Add(pairingTTL).UTC().Format(time.RFC3339Nano), Status: "pending"}
	if err := writeJSON(s.pairingPath(in.Code), p); err != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	reply(w, 200, map[string]any{"pairing_id": in.Code, "poll_secret": secret, "expires_at": p.ExpiresAt})
}

// readPairing is the new device's poll (?poll=<secret>) or, with a device
// token, the approver reading the keys to verify.
func (s *Server) readPairing(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if poll := r.URL.Query().Get("poll"); poll != "" {
		p, ok := s.loadPairing(code)
		if !ok {
			fail(w, 404, "not_found", "no such pairing")
			return
		}
		if !constantEq(hash(poll), p.PollHash) {
			fail(w, 401, "unauthorized", "wrong poll secret")
			return
		}
		out := map[string]any{"status": p.Status}
		if p.Status == "approved" {
			out["account_id"], out["envelope"], out["issuer"], out["issuer_sign_pub"] = p.AccountID, p.Envelope, p.Issuer, p.IssuerSignPub
			_ = os.Remove(s.pairingPath(code)) // answered once
		}
		reply(w, 200, out)
		return
	}
	s.authed(func(w http.ResponseWriter, _ *http.Request, _ caller) {
		p, ok := s.loadPairing(code)
		if !ok || p.Status != "pending" {
			fail(w, 404, "not_found", "no such pairing")
			return
		}
		reply(w, 200, map[string]any{"device_id": p.DeviceID, "sign_pub": p.SignPub, "box_pub": p.BoxPub, "expires_at": p.ExpiresAt})
	})(w, r)
}

func (s *Server) approvePairing(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		Envelope string `json:"envelope"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Envelope == "" {
		fail(w, 400, "invalid", "an envelope is required")
		return
	}
	code := r.PathValue("code")
	defer s.lock(c.account)()
	p, ok := s.loadPairing(code)
	if !ok || p.Status != "pending" {
		fail(w, 404, "not_found", "no such pairing")
		return
	}
	a, err := s.st.loadAccount(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	if len(a.Devices) >= maxDevices {
		fail(w, 409, "conflict", "device limit reached")
		return
	}
	if _, err := s.st.accountOfDevice(p.DeviceID); err == nil {
		fail(w, 409, "conflict", "device exists")
		return
	}
	now := s.cfg.Now().UTC().Format(time.RFC3339)
	a.Devices[p.DeviceID] = deviceRec{SignPub: p.SignPub, BoxPub: p.BoxPub, CreatedAt: now, KeyEnvelope: in.Envelope, Generation: a.Generation}
	if s.st.saveAccount(a) != nil || s.st.indexDevice(p.DeviceID, a.ID) != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	p.Status, p.AccountID, p.Envelope, p.Issuer, p.IssuerSignPub = "approved", a.ID, in.Envelope, c.device, a.Devices[c.device].SignPub
	if err := writeJSON(s.pairingPath(code), p); err != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	reply(w, 200, map[string]any{"approved": true})
}

// ---- recovery ----

func (s *Server) recoveryToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		LookupID string `json:"lookup_id"`
		Auth     string `json:"auth"`
	}
	if !decode(w, r, &in) {
		return
	}
	now := s.cfg.Now()
	if !s.recoveryLimit.allow(s.clientIP(r), now) || !s.recoveryDaily.allow(in.LookupID, now) {
		fail(w, 429, "rate_limited", "too many attempts")
		return
	}
	raw, err := os.ReadFile(s.st.path("recovery", hash(in.LookupID)))
	if err != nil {
		fail(w, 401, "unauthorized", "recovery key not recognized")
		return
	}
	a, err := s.st.loadAccount(string(raw))
	if err != nil || !constantEq(hash(in.Auth), a.Recovery.AuthHash) {
		fail(w, 401, "unauthorized", "recovery key not recognized")
		return
	}
	tok := newToken()
	s.mu.Lock()
	s.tokens[tok] = tokenRec{account: a.ID, recovery: true, expires: now.Add(recoveryTTL)}
	s.mu.Unlock()
	reply(w, 200, map[string]any{"account_id": a.ID, "token": tok})
}

// recoveryAuthed requires a recovery token, which can only read the recovery
// envelope and register one device.
func (s *Server) recoveryAuthed(h func(http.ResponseWriter, *http.Request, caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		s.mu.Lock()
		t, ok := s.tokens[tok]
		if ok && !s.cfg.Now().Before(t.expires) {
			delete(s.tokens, tok)
			ok = false
		}
		s.mu.Unlock()
		if !ok || !t.recovery {
			fail(w, 401, "unauthorized", "a recovery token is required")
			return
		}
		h(w, r, caller{account: t.account, token: tok})
	}
}

func bearer(r *http.Request) string {
	const p = "Bearer "
	if h := r.Header.Get("Authorization"); len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

func (s *Server) recoveryEnvelope(w http.ResponseWriter, _ *http.Request, c caller) {
	a, err := s.st.loadAccount(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	reply(w, 200, map[string]any{"generation": a.Generation, "envelope": a.Recovery.Envelope})
}

func (s *Server) recoveryDevice(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		Device      deviceIn `json:"device"`
		KeyEnvelope string   `json:"key_envelope"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !in.Device.valid() || in.KeyEnvelope == "" {
		fail(w, 400, "invalid", "malformed device")
		return
	}
	defer s.lock(c.account)()
	a, err := s.st.loadAccount(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	if _, err := s.st.accountOfDevice(in.Device.ID); err == nil || len(a.Devices) >= maxDevices {
		fail(w, 409, "conflict", "device exists or limit reached")
		return
	}
	a.Devices[in.Device.ID] = deviceRec{SignPub: in.Device.SignPub, BoxPub: in.Device.BoxPub,
		CreatedAt: s.cfg.Now().UTC().Format(time.RFC3339), KeyEnvelope: in.KeyEnvelope, Generation: a.Generation}
	if s.st.saveAccount(a) != nil || s.st.indexDevice(in.Device.ID, a.ID) != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	s.mu.Lock()
	delete(s.tokens, c.token) // one device per recovery token
	s.mu.Unlock()
	reply(w, 200, map[string]any{"registered": true})
}

func (s *Server) keysSelf(w http.ResponseWriter, _ *http.Request, c caller) {
	a, err := s.st.loadAccount(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	d := a.Devices[c.device]
	reply(w, 200, map[string]any{"generation": d.Generation, "envelope": d.KeyEnvelope})
}

// rekey replaces the master key in one transaction (REMOTE_SYNC.md § 4.5):
// a new vault version under the next generation, one envelope per remaining
// device, a new recovery envelope, and the revoked devices gone.
func (s *Server) rekey(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		BaseVersion int64             `json:"base_version"`
		Generation  int               `json:"generation"`
		Blob        string            `json:"blob"`
		Envelopes   map[string]string `json:"envelopes"`
		Recovery    recoveryIn        `json:"recovery"`
		Revoke      []string          `json:"revoke"`
	}
	if !decode(w, r, &in) {
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
	revoked := map[string]bool{}
	for _, id := range in.Revoke {
		if id == c.device {
			fail(w, 400, "invalid", "a device cannot revoke itself")
			return
		}
		if _, ok := a.Devices[id]; !ok {
			fail(w, 400, "invalid", "unknown device to revoke")
			return
		}
		revoked[id] = true
	}
	remaining := 0
	for id := range a.Devices {
		if revoked[id] {
			continue
		}
		remaining++
		if in.Envelopes[id] == "" {
			fail(w, 400, "invalid", "every remaining device needs an envelope")
			return
		}
	}
	acct, gen, ver, ok := blobAAD(in.Blob)
	if remaining != len(in.Envelopes) || in.Generation != a.Generation+1 || !ok || acct != a.ID || gen != in.Generation ||
		ver != a.Version+1 || len(in.Blob) > MaxBlob || in.Recovery.LookupID == "" || in.Recovery.Auth == "" {
		fail(w, 400, "invalid", "malformed rekey")
		return
	}
	if err := s.st.putVersion(a.ID, ver, in.Blob); err != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	for id := range revoked {
		delete(a.Devices, id)
	}
	for id, env := range in.Envelopes {
		d := a.Devices[id]
		d.KeyEnvelope, d.Generation = env, in.Generation
		a.Devices[id] = d
	}
	oldLookup := a.Recovery.LookupID
	a.Recovery = recoveryRec{LookupID: in.Recovery.LookupID, AuthHash: hash(in.Recovery.Auth), Envelope: in.Recovery.Envelope}
	a.Version, a.Generation = ver, in.Generation
	if s.st.saveAccount(a) != nil || writeFile(s.st.path("recovery", hash(in.Recovery.LookupID)), []byte(a.ID)) != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	if oldLookup != in.Recovery.LookupID {
		_ = os.Remove(s.st.path("recovery", hash(oldLookup)))
	}
	for id := range revoked {
		s.st.unindexDevice(id)
		s.dropTokens(id)
	}
	reply(w, 200, map[string]any{"version": ver, "generation": in.Generation})
}

// ---- anchors (§ 8) ----

func (s *Server) anchorsPath(acct, device string) string {
	return s.st.path("accounts", acct, "anchors", hash(device)+".json")
}

func (s *Server) putAnchor(w http.ResponseWriter, r *http.Request, c caller) {
	var in struct {
		Blob string `json:"blob"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Blob) > maxAnchorBytes {
		fail(w, 413, "too_large", "anchor too large")
		return
	}
	defer s.lock(c.account)()
	var list []string
	_ = readJSON(s.anchorsPath(c.account, c.device), &list)
	list = append(list, in.Blob)
	if len(list) > keepAnchors {
		list = list[len(list)-keepAnchors:]
	}
	if err := writeJSON(s.anchorsPath(c.account, c.device), list); err != nil {
		fail(w, 500, "internal", "store failed")
		return
	}
	reply(w, 200, map[string]any{"stored": len(list)})
}

func (s *Server) getAnchors(w http.ResponseWriter, r *http.Request, c caller) {
	dev := r.URL.Query().Get("device")
	a, err := s.st.loadAccount(c.account)
	if err != nil {
		fail(w, 404, "not_found", "no account")
		return
	}
	if _, ok := a.Devices[dev]; !ok {
		fail(w, 404, "not_found", "no such device")
		return
	}
	var list []string
	_ = readJSON(s.anchorsPath(c.account, dev), &list)
	if list == nil {
		list = []string{}
	}
	raw, _ := json.Marshal(list)
	var anchors []any
	_ = json.Unmarshal(raw, &anchors)
	reply(w, 200, map[string]any{"anchors": anchors})
}
