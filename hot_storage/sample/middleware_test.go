package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func serveCORS(t *testing.T, method, origin string) *httptest.ResponseRecorder {
	t.Helper()
	h := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	r := httptest.NewRequest(method, "/v2/accounts", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCORSReflectsOnlyAllowedOrigins(t *testing.T) {
	t.Run("allowed origin is reflected", func(t *testing.T) {
		w := serveCORS(t, http.MethodGet, "http://localhost:7050")
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:7050" {
			t.Fatalf("got Access-Control-Allow-Origin %q, want the request origin", got)
		}
	})

	// Reflecting an untrusted origin next to Allow-Credentials: true would hand
	// any site credentialed access to the API; the header must be absent.
	t.Run("disallowed origin gets no allow-origin header", func(t *testing.T) {
		w := serveCORS(t, http.MethodGet, "https://evil.example")
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("Access-Control-Allow-Origin %q leaked for a disallowed origin", got)
		}
	})

	t.Run("no origin header gets no allow-origin header", func(t *testing.T) {
		w := serveCORS(t, http.MethodGet, "")
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("Access-Control-Allow-Origin %q emitted without an Origin header", got)
		}
	})
}

func TestCORSPreflightShortCircuits(t *testing.T) {
	w := serveCORS(t, http.MethodOptions, "http://localhost:7050")
	if w.Code != http.StatusOK {
		t.Fatalf("preflight got %d, want 200", w.Code)
	}
	// The inner handler writes 418; reaching it would mean OPTIONS fell through.
}

func TestCORSSetsVaryOrigin(t *testing.T) {
	w := serveCORS(t, http.MethodGet, "http://localhost:7050")
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("got Vary %q, want Origin: cached responses must not leak across origins", got)
	}
}
