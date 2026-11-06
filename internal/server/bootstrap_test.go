package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A server with no account yet can be given its first invite through the
// environment (QBV_SERVER_BOOTSTRAP_INVITE), for hosts where the operator
// cannot run `invite` inside the container. The code is never written or
// logged in clear, it is ignored once an account exists, and a weak code is
// refused.

const bootCode = "TESTSECRET_bootstrap-invite-1234"

func TestBootstrapInviteOnAnEmptyServer(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{Data: dir, PublicURL: "https://vault.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	made, err := s.BootstrapInvite(bootCode, 24*time.Hour)
	if err != nil || !made {
		t.Fatalf("made=%v err=%v", made, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "invites", hash(bootCode)))
	if err != nil {
		t.Fatalf("invite not stored: %v", err)
	}
	if bytes.Contains(b, []byte(bootCode)) {
		t.Fatal("the bootstrap code is stored in clear")
	}
}

func TestBootstrapInviteIsIgnoredOnceAnAccountExists(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "accounts", "acct1"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Data: dir, PublicURL: "https://vault.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	made, err := s.BootstrapInvite(bootCode, 24*time.Hour)
	if err != nil || made {
		t.Fatalf("made=%v err=%v", made, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "invites", hash(bootCode))); !os.IsNotExist(err) {
		t.Fatal("an invite was stored on a server that already has an account")
	}
}

func TestBootstrapInviteRefusesAWeakCode(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{Data: dir, PublicURL: "https://vault.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BootstrapInvite("short-code", 24*time.Hour); !errors.Is(err, ErrWeakInvite) {
		t.Fatalf("err = %v, want ErrWeakInvite", err)
	}
	var out, errb bytes.Buffer
	e := env(map[string]string{"QBV_SERVER_DATA": dir, "QBV_SERVER_PUBLIC_URL": "https://vault.example.test", "QBV_SERVER_BOOTSTRAP_INVITE": "TESTSECRET_short"})
	if code := Main(context.Background(), []string{"serve"}, e, &out, &errb); code != 2 ||
		errb.String() != "error: QBV_SERVER_BOOTSTRAP_INVITE must be at least 24 characters\n" {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestServeRegistersTheBootstrapInviteAndNeverLogsIt(t *testing.T) {
	dir, addr := t.TempDir(), freePort(t)
	e := env(map[string]string{"QBV_SERVER_DATA": dir, "QBV_SERVER_LISTEN": addr, "QBV_SERVER_PUBLIC_URL": "https://vault.example.test", "QBV_SERVER_BOOTSTRAP_INVITE": bootCode})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var logs bytes.Buffer
	go func() { done <- Main(ctx, []string{"serve"}, e, &bytes.Buffer{}, &logs) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if res, err := http.Get("http://" + addr + "/healthz"); err == nil {
			res.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if _, err := os.Stat(filepath.Join(dir, "invites", hash(bootCode))); err != nil {
		t.Fatalf("bootstrap invite not registered: %v", err)
	}
	if !strings.Contains(logs.String(), "bootstrap invite registered (single use, expires in 24h)") || strings.Contains(logs.String(), bootCode) {
		t.Fatalf("logs=%q", logs.String())
	}
}
