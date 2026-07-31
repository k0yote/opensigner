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
	h := rateLimitMiddleware(newRateLimiter(), okHandler())

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
	h := rateLimitMiddleware(newRateLimiter(), okHandler())

	for i := 0; i < rateLimitBurst+5; i++ {
		serveAs(t, h, "noisy-user")
	}

	// One subject exhausting its budget must not affect another.
	if code := serveAs(t, h, "quiet-user"); code != http.StatusOK {
		t.Fatalf("second user got %d, want 200", code)
	}
}

func TestRateLimitRequiresAuthenticatedSubject(t *testing.T) {
	h := rateLimitMiddleware(newRateLimiter(), okHandler())

	// Reached without a user id in context, the limiter has no key to charge and
	// must refuse rather than fall through unmetered.
	if code := serveAs(t, h, ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d, want 401", code)
	}
}

func TestRateLimitEvictsIdleVisitors(t *testing.T) {
	rl := newRateLimiter()
	rl.allow("stale-user")
	rl.allow("active-user")

	rl.mu.Lock()
	rl.visitors["stale-user"].lastSeen = time.Now().Add(-2 * rateLimitVisitorTTL)
	rl.mu.Unlock()

	// One sweep pass at the TTL cutoff, exactly as the ticker drives it.
	rl.evictIdle(time.Now().Add(-rateLimitVisitorTTL))

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, ok := rl.visitors["stale-user"]; ok {
		t.Fatal("idle visitor was retained past its TTL")
	}
	if _, ok := rl.visitors["active-user"]; !ok {
		t.Fatal("an active visitor was evicted")
	}
}

func TestRateLimitRefillsAfterWait(t *testing.T) {
	rl := newRateLimiter()
	for i := 0; i < rateLimitBurst; i++ {
		rl.allow("refill-user")
	}
	if rl.allow("refill-user") {
		t.Fatal("bucket should be empty immediately after the burst")
	}

	// At rateLimitPerSecond tokens/s, 250ms is enough for at least one token.
	time.Sleep(250 * time.Millisecond)
	if !rl.allow("refill-user") {
		t.Fatal("bucket did not refill after waiting")
	}
}
