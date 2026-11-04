// Command proxy is the recording TLS reverse proxy of the sync e2e battery
// (docs/TESTING.md § Tier 2 item 7). It sits between the client containers
// and gentle-vault-server, writes every exchange to a volume the driver
// scans for leaks, and can replay an older recorded vault response to play a
// server that rolls back.
//
// It generates a throwaway CA and a server certificate for E2E_HOSTS at
// start and writes the CA to E2E_CERTS/ca.pem, which the clients pass with
// --ca-file. Test tooling only; it is not part of any release.
//
// Each exchange N is three files under E2E_REC: N.meta (method, URL, status,
// headers), N.req and N.resp (the bodies). When E2E_REC/control/replay holds
// the number of a recorded GET /v1/vault exchange, that response is served
// instead of asking the server.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "health" {
		c := http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get("http://127.0.0.1:8081/health")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	p := &proxy{
		upstream: strings.TrimRight(env("E2E_UPSTREAM", "http://server:8080"), "/"),
		rec:      env("E2E_REC", "/rec"),
		client:   &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	if err := os.MkdirAll(filepath.Join(p.rec, "control"), 0o755); err != nil {
		log.Fatal(err)
	}
	cert, err := makeCerts(env("E2E_CERTS", "/certs"), strings.Split(env("E2E_HOSTS", "proxy"), ","))
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
		log.Fatal(http.ListenAndServe(":8081", mux))
	}()
	srv := &http.Server{Addr: env("E2E_LISTEN", ":8443"), Handler: p, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

type proxy struct {
	upstream string
	rec      string
	client   *http.Client
	seq      atomic.Int64
}

func (p *proxy) write(n int64, ext string, data []byte) {
	if err := os.WriteFile(filepath.Join(p.rec, fmt.Sprintf("%06d.%s", n, ext)), data, 0o644); err != nil {
		log.Printf("record: %v", err)
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := p.seq.Add(1)
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	p.write(n, "req", body)

	status, header, out := 0, http.Header(nil), []byte(nil)
	replayed := ""
	if r.Method == "GET" && r.URL.Path == "/v1/vault" && r.URL.Query().Get("version") == "" {
		if id := p.replayTarget(); id != "" {
			if st, h, b, ok := p.loadRecorded(id); ok {
				status, header, out, replayed = st, h, b, id
			}
		}
	}
	if replayed == "" {
		status, header, out, err = p.forward(r, body)
		if err != nil {
			status, header, out = 502, http.Header{}, nil
		}
	}
	p.write(n, "resp", out)

	var m bytes.Buffer
	fmt.Fprintf(&m, "%s %s\nstatus %d\n", r.Method, r.URL.RequestURI(), status)
	if replayed != "" {
		fmt.Fprintf(&m, "replayed %s\n", replayed)
	}
	for _, h := range []http.Header{r.Header, header} {
		keys := make([]string, 0, len(h))
		for k := range h {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&m, "%s: %s\n", k, strings.Join(h[k], ","))
		}
		m.WriteString("--\n")
	}
	p.write(n, "meta", m.Bytes())

	for k, vs := range header {
		if hopByHop[http.CanonicalHeaderKey(k)] || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

var hopByHop = map[string]bool{"Connection": true, "Keep-Alive": true, "Proxy-Connection": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true}

func (p *proxy) forward(r *http.Request, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, p.upstream+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, vs := range r.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		req.Header.Set("X-Forwarded-For", host)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, resp.Header, out, err
}

// replayTarget is the exchange number named by control/replay, or "".
func (p *proxy) replayTarget() string {
	b, err := os.ReadFile(filepath.Join(p.rec, "control", "replay"))
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(b))
	if _, err := strconv.Atoi(id); err != nil {
		return ""
	}
	return id
}

// loadRecorded reads a recorded exchange; only a 200 GET /v1/vault is served.
func (p *proxy) loadRecorded(id string) (int, http.Header, []byte, bool) {
	meta, err := os.ReadFile(filepath.Join(p.rec, id+".meta"))
	if err != nil || !strings.HasPrefix(string(meta), "GET /v1/vault\nstatus 200\n") {
		return 0, nil, nil, false
	}
	b, err := os.ReadFile(filepath.Join(p.rec, id+".resp"))
	if err != nil {
		return 0, nil, nil, false
	}
	return 200, http.Header{"Content-Type": {"application/json"}}, b, true
}

// makeCerts writes ca.pem and returns a leaf certificate for hosts.
func makeCerts(dir string, hosts []string) (tls.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gentle-vault e2e CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}, nil
}
