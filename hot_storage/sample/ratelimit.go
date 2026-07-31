package main

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Per-user request limits. Every endpoint behind this either hands out or accepts
// a key share, so the ceiling is set low enough that scripted enumeration or bulk
// device creation is throttled, but high enough not to interfere with a client
// walking its own accounts and devices.
const (
	rateLimitPerSecond = 10
	rateLimitBurst     = 20

	// A visitor is dropped once idle for this long, bounding memory against an
	// attacker who authenticates as many distinct subjects.
	rateLimitVisitorTTL = 10 * time.Minute
	rateLimitSweepEvery = time.Minute
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
}

// newRateLimiter builds a limiter without starting the sweep goroutine; the
// serving path starts it explicitly so tests can drive eviction directly.
func newRateLimiter() *rateLimiter {
	return &rateLimiter{visitors: make(map[string]*visitor)}
}

// sweep periodically evicts idle visitors. Without it the map grows for the
// lifetime of the process, which turns a rate limiter into a memory-exhaustion
// vector.
func (rl *rateLimiter) sweep() {
	ticker := time.NewTicker(rateLimitSweepEvery)
	defer ticker.Stop()
	for range ticker.C {
		rl.evictIdle(time.Now().Add(-rateLimitVisitorTTL))
	}
}

func (rl *rateLimiter) evictIdle(cutoff time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for key, v := range rl.visitors {
		if v.lastSeen.Before(cutoff) {
			delete(rl.visitors, key)
		}
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, ok := rl.visitors[key]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(rate.Limit(rateLimitPerSecond), rateLimitBurst)}
		rl.visitors[key] = v
	}
	v.lastSeen = time.Now()
	return v.limiter.Allow()
}

// rateLimitMiddleware throttles per authenticated subject. It must sit inside
// authMiddleware so the bucket key is the verified user id, not a spoofable or
// NAT-shared client address.
func rateLimitMiddleware(rl *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId, ok := r.Context().Value(fieldUserId).(string)
		if !ok || userId == "" {
			unauthorized(w)
			return
		}

		if !rl.allow(userId) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
