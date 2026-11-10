package prompt

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: still blocked after 5s", what)
	}
}

// A native dialog bound to a context ends when that context ends: the runner
// (which kills the helper) sees it, and the call is a cancel, not a failure.
func TestBoundNativeDialogEndsWithItsContext(t *testing.T) {
	seen := make(chan struct{})
	run := func(ctx context.Context, c command) (result, error) {
		close(seen)
		<-ctx.Done()
		return result{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := Bind(ctx, newNative(zenityTool{}, "zenity", run, time.Hour))
	errc := make(chan error, 1)
	go func() { _, err := b.Secret(req); errc <- err }()
	<-seen
	cancel()
	within(t, "native secret", func() {
		if err := <-errc; !errors.Is(err, ErrCancelled) || errors.Is(err, ErrTimeout) || errors.Is(err, ErrUnavailable) {
			t.Errorf("err = %v, want ErrCancelled", err)
		}
	})
}

// The terminal prompt takes its context from the binding too.
func TestBoundTerminalPromptEndsWithItsContext(t *testing.T) {
	term := &memTerm{block: true}
	ctx, cancel := context.WithCancel(context.Background())
	b := Bind(ctx, New(func() (Terminal, error) { return term, nil }, Timeout(time.Hour)))
	errc := make(chan error, 1)
	go func() { _, err := b.Secret(req); errc <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	within(t, "terminal secret", func() {
		if err := <-errc; !errors.Is(err, ErrCancelled) {
			t.Errorf("err = %v, want ErrCancelled", err)
		}
	})
	if !term.closed {
		t.Error("terminal not closed")
	}
}

// An unbound backend keeps its own timeout and ignores nobody's context.
func TestBindKeepsTheTimeout(t *testing.T) {
	term := &memTerm{block: true}
	b := Bind(context.Background(), New(func() (Terminal, error) { return term, nil }, Timeout(30*time.Millisecond)))
	within(t, "timeout", func() {
		if _, err := b.Secret(req); !errors.Is(err, ErrTimeout) {
			t.Errorf("err = %v, want ErrTimeout", err)
		}
	})
}

type plain struct{ Backend }

// A backend that cannot take a context is returned as it is.
func TestBindLeavesOtherBackendsAlone(t *testing.T) {
	p := plain{}
	if got := Bind(context.Background(), p); got != Backend(p) {
		t.Fatal("Bind changed a backend that has no context support")
	}
}

// One dialog at a time: the second waits for the first to be released.
func TestAcquireDialogSerializes(t *testing.T) {
	ctx := context.Background()
	release, err := AcquireDialog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got atomic.Bool
	done := make(chan struct{})
	go func() {
		r2, err := AcquireDialog(ctx)
		if err != nil {
			t.Error(err)
		} else {
			got.Store(true)
			r2()
		}
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	if got.Load() {
		t.Fatal("a second dialog was admitted while the first was open")
	}
	release()
	release() // releasing twice is harmless
	within(t, "second dialog", func() { <-done })
	if !got.Load() {
		t.Fatal("the second dialog never got its turn")
	}
}

// A waiter whose context ends gives up and does not take the turn.
func TestAcquireDialogHonoursTheWaitersContext(t *testing.T) {
	release, err := AcquireDialog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := AcquireDialog(ctx); errc <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	within(t, "waiter", func() {
		if err := <-errc; !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
	release()
	r3, err := AcquireDialog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r3()
}
