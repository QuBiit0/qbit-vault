package server

import (
	"sync"
	"time"
)

// limiter is a fixed-window counter per key, in memory: enough to bound
// brute force on one instance (REMOTE_SYNC.md § 6 Limits).
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	seen   map[string]*bucket
}

type bucket struct {
	start time.Time
	count int
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, seen: map[string]*bucket{}}
}

// allow counts one event for key and reports whether it is within the limit.
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.seen[key]
	if b == nil || now.Sub(b.start) >= l.window {
		if len(l.seen) > 100000 {
			l.seen = map[string]*bucket{} // bound memory under a flood
		}
		b = &bucket{start: now}
		l.seen[key] = b
	}
	b.count++
	return b.count <= l.n
}
