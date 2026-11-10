package cli

import (
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/mcp"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/secret"
)

// dialogState is what the blocking backend shares between the copies that
// Bind makes of it.
type dialogState struct {
	mu                    sync.Mutex
	active, maxActive     int
	opened                chan string   // the name of every Secret dialog that opened
	release               chan struct{} // closed: the user types the value
	ended                 chan struct{} // closed when a bound context ended a dialog
	endedOnce             sync.Once
	answerDespiteCancel   bool // the user answers in the same instant the call is cancelled
	boundContextsReceived int
}

// blockingBackend is a prompt backend whose Secret dialog stays open until
// the test releases it or the context it was bound to ends.
type blockingBackend struct {
	st  *dialogState
	ctx context.Context
}

func newBlocking() blockingBackend {
	return blockingBackend{st: &dialogState{opened: make(chan string, 16), release: make(chan struct{}), ended: make(chan struct{})}}
}

func (blockingBackend) Name() string { return "fake" }

func (b blockingBackend) WithContext(ctx context.Context) prompt.Backend {
	b.st.mu.Lock()
	b.st.boundContextsReceived++
	b.st.mu.Unlock()
	b.ctx = ctx
	return b
}

func (b blockingBackend) Secret(req prompt.SecretRequest) (secret.Secret, error) {
	st := b.st
	st.mu.Lock()
	st.active++
	st.maxActive = max(st.maxActive, st.active)
	st.mu.Unlock()
	defer func() { st.mu.Lock(); st.active--; st.mu.Unlock() }()
	st.opened <- req.Name
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-st.release:
	case <-ctx.Done():
		st.endedOnce.Do(func() { close(st.ended) })
		if !st.answerDespiteCancel {
			return secret.Secret{}, prompt.ErrCancelled
		}
	}
	return secret.New(req.Name, []byte("TESTSECRET_mcp_dialog_"+req.Name)), nil
}

func (blockingBackend) Choose(string, []string, int) (int, error) { return 0, nil }
func (blockingBackend) Confirm(string) (bool, error)              { return true, nil }
func (blockingBackend) Passphrase(prompt.PassphraseRequest) (secret.Secret, error) {
	return secret.Secret{}, prompt.ErrNoTerminal
}

func useBlocking(t *testing.T, b blockingBackend) {
	t.Helper()
	old := newPrompt
	newPrompt = func(*globals) (prompt.Backend, error) { return b, nil }
	t.Cleanup(func() { newPrompt = old })
}

// mcpConn is a running `mcp` server the test talks to line by line.
type mcpConn struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *syncBuf
	errb *syncBuf
	done chan int
}

func (w *world) startMCP() *mcpConn {
	w.t.Helper()
	pr, pw := io.Pipe()
	stdinOverride = pr
	w.t.Cleanup(func() { stdinOverride = nil })
	s := &mcpConn{t: w.t, in: pw, out: &syncBuf{}, errb: &syncBuf{}, done: make(chan int, 1)}
	go func() {
		s.done <- execute([]string{"--home", w.home, "--session", "claude:mcp12345", "mcp"}, s.out, s.errb, envFrom(nil))
	}()
	s.send(rpcInit, rpcInited)
	s.waitFor(`"id":1`)
	return s
}

func (s *mcpConn) send(lines ...string) {
	s.t.Helper()
	if _, err := io.WriteString(s.in, rpc(lines...)); err != nil {
		s.t.Fatal(err)
	}
}

func (s *mcpConn) waitFor(sub string) {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(s.out.String(), sub) {
		if time.Now().After(deadline) {
			s.t.Fatalf("no %q on stdout after 10s; out=%q err=%q", sub, s.out.String(), s.errb.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// finish closes the stream as a host does and returns what the server wrote.
func (s *mcpConn) finish() (string, string) {
	s.t.Helper()
	_ = s.in.Close()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		s.t.Fatal("the server did not stop after stdin closed")
	}
	return s.out.String(), s.errb.String()
}

func requestCall(id int, name, extra string) string {
	return `{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"secret_request","arguments":{"name":"` + name +
		`","reason":"` + reqReason + `"}` + extra + `}}`
}

func itoa(i int) string { return strconv.Itoa(i) }

func cancelCall(id int) string {
	return `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":` + itoa(id) + `,"reason":"client gave up"}}`
}

func waitChan[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: nothing after 5s", what)
		panic("unreachable")
	}
}

func notClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s", what)
	case <-time.After(200 * time.Millisecond):
	}
}

// S6.1: a client that cancels the call closes the dialog, and nothing is
// stored, granted or audited as a capture or a grant afterwards.
func TestMCPCancelClosesTheDialogAndStoresNothing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers bool
	}{{"dialog ends with the call", false}, {"user answers as the call is cancelled", true}} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			t.Chdir(w.outside)
			before := w.snapshot()
			grantsBefore := w.grantsState()
			b := newBlocking()
			b.st.answerDespiteCancel = tc.answers
			useBlocking(t, b)
			s := w.startMCP()

			s.send(requestCall(10, "A", ""))
			if got := waitChan(t, b.st.opened, "the dialog"); got != "A" {
				t.Fatalf("dialog for %q", got)
			}
			s.send(cancelCall(10))
			waitChan(t, b.st.ended, "the dialog ending with the call")
			time.Sleep(300 * time.Millisecond) // let a wrong handler finish storing
			out, errs := s.finish()

			if w.snapshot() != before {
				t.Fatal("a cancelled request stored a value")
			}
			if w.grantsState() != grantsBefore {
				t.Fatal("a cancelled request created a grant")
			}
			if w.auditHas(`"event":"capture"`) || w.auditHas(`"event":"grant"`) {
				t.Fatalf("a cancelled request was audited as a capture or grant: %s", w.auditText())
			}
			if w.auditHas(`"outcome":"issued"`) {
				t.Fatalf("a cancelled request was audited as issued: %s", w.auditText())
			}
			noFixtures(t, "mcp output", out+errs)
			if errs != "" {
				t.Fatalf("stderr = %q", errs)
			}
		})
	}
}

// S6.2: two requests at once open one dialog at a time; the second waits for
// the first, and a waiting call that is cancelled never opens its dialog.
func TestMCPOneDialogAtATime(t *testing.T) {
	w := newWorld(t)
	t.Chdir(w.outside)
	b := newBlocking()
	useBlocking(t, b)
	s := w.startMCP()

	s.send(requestCall(10, "A", ""), requestCall(11, "B", ""), requestCall(12, "C", ""))
	first := waitChan(t, b.st.opened, "the first dialog")
	time.Sleep(300 * time.Millisecond)
	if n := len(b.st.opened); n != 0 {
		t.Fatalf("%d more dialogs opened while the first was open", n)
	}
	// Cancel the call that is not showing: it must never get a dialog.
	waiting := map[string]int{"A": 10, "B": 11, "C": 12}
	var cancelled string
	for _, n := range []string{"C", "B", "A"} {
		if n != first {
			cancelled = n
			break
		}
	}
	s.send(cancelCall(waiting[cancelled]))
	time.Sleep(100 * time.Millisecond)
	close(b.st.release) // the user answers whatever is open
	var opened []string
	opened = append(opened, first)
	deadline := time.After(5 * time.Second)
	for len(opened) < 2 {
		select {
		case n := <-b.st.opened:
			opened = append(opened, n)
		case <-deadline:
			t.Fatalf("the second dialog never opened; opened=%v", opened)
		}
	}
	for _, n := range opened {
		if n == cancelled {
			t.Fatalf("the cancelled call %s got a dialog", cancelled)
		}
	}
	for _, id := range []int{10, 11, 12} {
		if id == waiting[cancelled] {
			continue
		}
		s.waitFor(`"id":` + itoa(id) + `,`)
	}
	out, errs := s.finish()
	if b.st.maxActive != 1 {
		t.Fatalf("%d dialogs were open at once", b.st.maxActive)
	}
	if errs != "" {
		t.Fatalf("stderr on the happy path = %q", errs)
	}
	noFixtures(t, "mcp output", out+errs)
	snap := w.snapshot()
	for _, n := range opened {
		if !strings.Contains(snap, `"name":"`+n+`"`) {
			t.Fatalf("%s was not stored", n)
		}
	}
	if strings.Contains(snap, `"name":"`+cancelled+`"`) {
		t.Fatalf("%s was stored although its call was cancelled", cancelled)
	}
}

// S6.1: a call with a progress token that waits for a dialog gets progress
// notifications over the real stdio server; one without a token gets none.
func TestMCPProgressWhileTheDialogIsOpen(t *testing.T) {
	old := mcp.ProgressInterval
	mcp.ProgressInterval = 30 * time.Millisecond
	t.Cleanup(func() { mcp.ProgressInterval = old })
	w := newWorld(t)
	t.Chdir(w.outside)
	b := newBlocking()
	useBlocking(t, b)
	s := w.startMCP()

	s.send(requestCall(10, "A", `,"_meta":{"progressToken":"tok-A"}`))
	waitChan(t, b.st.opened, "the dialog")
	s.waitFor(`"method":"notifications/progress"`)
	s.waitFor(`"progressToken":"tok-A"`)
	close(b.st.release)
	s.waitFor(`"id":10,`)

	s.send(requestCall(11, "B", ""))
	waitChan(t, b.st.opened, "the second dialog")
	time.Sleep(200 * time.Millisecond)
	s.waitFor(`"id":11,`)
	out, errs := s.finish()
	if strings.Contains(out, `"progressToken":"tok-B"`) || strings.Count(out, "notifications/progress") == 0 {
		t.Fatalf("progress out=%q", out)
	}
	for _, r := range responses(t, out) {
		if r["error"] != nil {
			t.Fatalf("protocol error: %v", r["error"])
		}
	}
	if errs != "" {
		t.Fatalf("stderr = %q", errs)
	}
	noFixtures(t, "mcp output", out+errs)
}
