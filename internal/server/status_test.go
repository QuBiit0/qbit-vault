package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func statusServer(t *testing.T, version string) *httptest.Server {
	t.Helper()
	s, err := New(Config{Data: t.TempDir(), PublicURL: origin, Now: time.Now, Version: version})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// S9.2: GET / answers the branded status page with the fixed headers.
func TestStatusPageServesBrandedHTMLWithHardenedHeaders(t *testing.T) {
	ts := statusServer(t, "v9.8.7-test")
	res, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	body := string(raw)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("content type = %q", ct)
	}
	for k, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	} {
		if got := res.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	for _, want := range []string{
		"QBit Vault",
		"This QBit Vault sync server is running",
		"v9.8.7-test",
		"API v1",
		"only stores data sealed on your devices",
		"https://github.com/QuBiit0/qbit-vault",
		"<svg",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, c := range []string{"#000204", "#07121B", "#2E9BE0", "#2FBF78", "#C7D9DE"} {
		if !strings.Contains(strings.ToUpper(body), c) {
			t.Errorf("page lacks design color %s", c)
		}
	}
}

// S9.2: no script, no external request, no account or device data.
func TestStatusPageHasNoScriptNoExternalRequestsNoAccountData(t *testing.T) {
	s, cl := newServer(t)
	_ = s
	res, err := http.Get(cl.base + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	body := strings.ToLower(string(raw))
	for _, bad := range []string{"<script", "javascript:", "onload=", "onclick=", "<link", "<iframe", "src=\"http", "src='http", "url(http", "@import", "account_id", "device_id", "sign_pub", "accounts:", "devices:", "vault.example.test"} {
		if strings.Contains(body, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
}

func TestStatusPageDevVersionWhenUnset(t *testing.T) {
	ts := statusServer(t, "")
	res, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(raw), "dev") {
		t.Error("an unset version should read dev")
	}
}

func TestStatusPageEscapesTheVersion(t *testing.T) {
	ts := statusServer(t, `<img src=x onerror=1>`)
	res, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if strings.Contains(string(raw), "<img src=x") {
		t.Error("version was not escaped")
	}
}

func TestStatusPageAnswersHEADWithoutBody(t *testing.T) {
	ts := statusServer(t, "v1")
	res, err := http.Head(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("HEAD / = %d, CSP %q", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
	if b, _ := io.ReadAll(res.Body); len(b) != 0 {
		t.Errorf("HEAD body has %d bytes", len(b))
	}
}

// S9.2: every other unknown path keeps the JSON 404; POST / is not the page.
func TestUnknownPathsKeepTheJSONNotFound(t *testing.T) {
	ts := statusServer(t, "v1")
	for _, p := range []string{"/nope", "/index.html", "/v1", "/v1/nope"} {
		res, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Errorf("GET %s = %d, want 404", p, res.StatusCode)
		}
		if strings.Contains(string(raw), "<html") {
			t.Errorf("GET %s served HTML", p)
		}
	}
	res, err := http.Post(ts.URL+"/", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == 200 {
		t.Error("POST / answered 200")
	}
}

// The request log keeps method, route, status and duration only.
func TestStatusPageLogLineHasNoAddress(t *testing.T) {
	var log strings.Builder
	s, err := New(Config{Data: t.TempDir(), PublicURL: origin, Log: &log})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	s.Handler().ServeHTTP(rec, req)
	if strings.Contains(log.String(), "203.0.113.9") || !strings.Contains(log.String(), "GET /{$} 200") {
		t.Errorf("log = %q", log.String())
	}
}
