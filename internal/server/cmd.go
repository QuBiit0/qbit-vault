package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Main is the qbit-vault-server command line (REMOTE_SYNC.md § 10):
//
//	serve              run the API (QBV_SERVER_DATA, QBV_SERVER_LISTEN,
//	                   QBV_SERVER_PUBLIC_URL, QBV_SERVER_TLS_CERT/KEY,
//	                   QBV_SERVER_TRUST_PROXY=N, QBV_SERVER_BOOTSTRAP_INVITE)
//	invite [--ttl D]   print one single-use account invite (default 24h)
//	health             exit 0 when /healthz answers on the listen address
//
// It returns the process exit code: 0 ok, 1 failure, 2 usage.
func Main(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	usage := func(msg string) int {
		fmt.Fprintf(stderr, "error: %s\nusage: qbit-vault-server serve | invite [--ttl 24h] | health\n", msg)
		return 2
	}
	if len(args) == 0 {
		return usage("no command given")
	}
	data := or(getenv("QBV_SERVER_DATA"), "/data")
	listen := or(getenv("QBV_SERVER_LISTEN"), ":8080")
	switch args[0] {
	case "invite":
		ttl := 24 * time.Hour
		if len(args) == 3 && args[1] == "--ttl" {
			d, err := time.ParseDuration(args[2])
			if err != nil || d <= 0 || d > 30*24*time.Hour {
				return usage("--ttl must be a duration between 1s and 720h")
			}
			ttl = d
		} else if len(args) != 1 {
			return usage("invite takes only --ttl")
		}
		s, err := New(Config{Data: data, PublicURL: "https://invite.local"})
		if err != nil {
			fmt.Fprintln(stderr, "error: cannot open the data directory")
			return 1
		}
		code, err := s.Invite(ttl)
		if err != nil {
			fmt.Fprintln(stderr, "error: cannot store the invite")
			return 1
		}
		fmt.Fprintln(stdout, code)
		return 0
	case "health":
		host := listen
		if strings.HasPrefix(host, ":") {
			host = "127.0.0.1" + host
		}
		c := http.Client{Timeout: 3 * time.Second}
		res, err := c.Get("http://" + host + "/healthz")
		if err != nil {
			fmt.Fprintln(stderr, "unhealthy: no answer")
			return 1
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			fmt.Fprintf(stderr, "unhealthy: status %d\n", res.StatusCode)
			return 1
		}
		fmt.Fprintln(stdout, "ok")
		return 0
	case "serve":
		if len(args) != 1 {
			return usage("serve takes no arguments")
		}
		public := getenv("QBV_SERVER_PUBLIC_URL")
		if public == "" {
			fmt.Fprintln(stderr, "error: QBV_SERVER_PUBLIC_URL is required (the https:// origin clients use)")
			return 2
		}
		trust, ok := parseTrustProxy(getenv("QBV_SERVER_TRUST_PROXY"))
		if !ok {
			fmt.Fprintln(stderr, "error: QBV_SERVER_TRUST_PROXY must be a number of proxies (0, 1, 2...)")
			return 2
		}
		s, err := New(Config{Data: data, PublicURL: strings.TrimRight(public, "/"), Log: stderr, TrustProxy: trust, Version: getenv("QBV_SERVER_VERSION")})
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		// The first invite of a server with no account, for operators who
		// cannot exec `invite` in the container. Never logged.
		if code := getenv("QBV_SERVER_BOOTSTRAP_INVITE"); code != "" {
			made, err := s.BootstrapInvite(code, 24*time.Hour)
			switch {
			case errors.Is(err, ErrWeakInvite):
				fmt.Fprintf(stderr, "error: QBV_SERVER_BOOTSTRAP_INVITE must be at least %d characters with at least %d different ones\n", MinBootstrapInvite, MinBootstrapDistinct)
				return 2
			case err != nil:
				fmt.Fprintln(stderr, "error: cannot store the bootstrap invite")
				return 1
			case made:
				fmt.Fprintln(stderr, "bootstrap invite registered (single use, expires in 24h)")
			default:
				fmt.Fprintln(stderr, "bootstrap invite ignored: an account already exists; remove QBV_SERVER_BOOTSTRAP_INVITE")
			}
		}
		return serve(ctx, s, listen, getenv("QBV_SERVER_TLS_CERT"), getenv("QBV_SERVER_TLS_KEY"), stderr)
	}
	return usage("unknown command")
}

func serve(ctx context.Context, s *Server, listen, cert, key string, stderr io.Writer) int {
	srv := &http.Server{Addr: listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: time.Minute, WriteTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(stderr, "error: cannot listen on QBV_SERVER_LISTEN")
		return 1
	}
	errc := make(chan error, 1)
	go func() {
		if cert != "" || key != "" {
			errc <- srv.ServeTLS(ln, cert, key)
		} else {
			errc <- srv.Serve(ln) // TLS terminates at the reverse proxy
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "error: server stopped")
			return 1
		}
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}
	return 0
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// parseTrustProxy reads QBV_SERVER_TRUST_PROXY: the number of trusted proxies
// in front of the server; empty or 0 trusts none.
func parseTrustProxy(v string) (int, bool) {
	if v == "" {
		return 0, true
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(v)
	return n, err == nil
}
