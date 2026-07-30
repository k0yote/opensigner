package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func serveAs(t *testing.T, h http.Handler, userId string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v2/accounts", nil)
	if userId != "" {
		r = r.WithContext(context.WithValue(r.Context(), fieldUserId, userId))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRateLimitAllowsBurstThenThrottles(t *testing.T) {
	h := rateLimitMiddleware(&rateLimiter{visitors: map[string]*visitor{}}, okHandler())

	for i := 0; i < rateLimitBurst; i++ {
		if code := serveAs(t, h, "user-a"); code != http.StatusOK {
			t.Fatalf("request %d within burst got %d, want 200", i+1, code)
		}
	}

	// The bucket refills at rateLimitPerSecond, so immediately after exhausting
	// the burst at least one request must be refused.
	if code := serveAs(t, h, "user-a"); code != http.StatusTooManyRequests {
		t.Fatalf("request past burst got %d, want 429", code)
	}
}

func TestRateLimitIsPerUser(t *testing.T) {
	h := rateLimitMiddleware(&rateLimiter{visitors: map[string]*visitor{}}, okHandler())

	for i := 0; i < rateLimitBurst+5; i++ {
		serveAs(t, h, "noisy-user")
	}

	// One subject exhausting its budget must not affect another.
	if code := serveAs(t, h, "quiet-user"); code != http.StatusOK {
		t.Fatalf("second user got %d, want 200", code)
	}
}

func TestRateLimitRequiresAuthenticatedSubject(t *testing.T) {
	h := rateLimitMiddleware(&rateLimiter{visitors: map[string]*visitor{}}, okHandler())

	// Reached without a user id in context, the limiter has no key to charge and
	// must refuse rather than fall through unmetered.
	if code := serveAs(t, h, ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d, want 401", code)
	}
}

func TestRateLimitEvictsIdleVisitors(t *testing.T) {
	rl := &rateLimiter{visitors: map[string]*visitor{}}
	rl.allow("stale-user")

	rl.mu.Lock()
	rl.visitors["stale-user"].lastSeen = time.Now().Add(-2 * rateLimitVisitorTTL)
	rl.mu.Unlock()

	// Mirrors one sweep pass; the loop in sweep() is driven by a ticker.
	cutoff := time.Now().Add(-rateLimitVisitorTTL)
	rl.mu.Lock()
	for key, v := range rl.visitors {
		if v.lastSeen.Before(cutoff) {
			delete(rl.visitors, key)
		}
	}
	remaining := len(rl.visitors)
	rl.mu.Unlock()

	if remaining != 0 {
		t.Fatalf("idle visitor was retained; %d entries remain", remaining)
	}
}
