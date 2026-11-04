package server

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestMainInvite(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	code := Main(context.Background(), []string{"invite", "--ttl", "2h"}, env(map[string]string{"GV_SERVER_DATA": dir}), &out, &errb)
	if code != 0 || !regexp.MustCompile(`^[0-9a-f]{32}\n$`).MatchString(out.String()) || errb.String() != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "invites", "*"))
	if len(files) != 1 {
		t.Fatalf("invites=%v", files)
	}
	if b, _ := os.ReadFile(files[0]); bytes.Contains(b, bytes.TrimSpace(out.Bytes())) {
		t.Fatal("the invite code is stored in clear")
	}
	for _, args := range [][]string{{"invite", "--ttl", "nope"}, {"invite", "--ttl", "0s"}, {"frobnicate"}, {}} {
		var o, e bytes.Buffer
		if code := Main(context.Background(), args, env(map[string]string{"GV_SERVER_DATA": dir}), &o, &e); code != 2 || o.Len() != 0 || e.Len() == 0 {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, o.String(), e.String())
		}
	}
}

func TestMainServeNeedsPublicURL(t *testing.T) {
	var out, errb bytes.Buffer
	code := Main(context.Background(), []string{"serve"}, env(map[string]string{"GV_SERVER_DATA": t.TempDir()}), &out, &errb)
	if code != 2 || errb.String() != "error: GV_SERVER_PUBLIC_URL is required (the https:// origin clients use)\n" {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestMainServeAndHealth(t *testing.T) {
	addr := freePort(t)
	e := env(map[string]string{"GV_SERVER_DATA": t.TempDir(), "GV_SERVER_LISTEN": addr, "GV_SERVER_PUBLIC_URL": "https://vault.example.test"})
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
	var out, errb bytes.Buffer
	if code := Main(context.Background(), []string{"health"}, e, &out, &errb); code != 0 || out.String() != "ok\n" {
		t.Fatalf("health: code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d: %s", code, logs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop on cancel")
	}
	if !strings.Contains(logs.String(), "GET /healthz 200") {
		t.Fatalf("access log=%q", logs.String())
	}
	if code := Main(context.Background(), []string{"health"}, e, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("health with the server down: %d", code)
	}
}
