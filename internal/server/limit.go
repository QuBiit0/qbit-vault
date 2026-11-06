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
	max    int       // keys held at once
	swept  time.Time // last eviction scan
}

type bucket struct {
	start time.Time
	count int
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, seen: map[string]*bucket{}, max: 100000}
}

// allow counts one event for key and reports whether it is within the limit.
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.seen[key]
	if b == nil || now.Sub(b.start) >= l.window {
		if b == nil && len(l.seen) >= l.max {
			l.evict(now)
			if len(l.seen) >= l.max {
				// A flood of live keys: drop one at random (map order) rather
				// than refuse everyone or reset every counter.
				for k := range l.seen {
					delete(l.seen, k)
					break
				}
			}
		}
		b = &bucket{start: now}
		l.seen[key] = b
	}
	b.count++
	return b.count <= l.n
}

// evict drops the buckets whose window is over, at most once a second (a scan
// is linear; a flood must not turn it into the cost of every request).
func (l *limiter) evict(now time.Time) {
	if now.Sub(l.swept) < time.Second {
		return
	}
	l.swept = now
	for k, b := range l.seen {
		if now.Sub(b.start) >= l.window {
			delete(l.seen, k)
		}
	}
}
