package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

func corsMiddleware(next http.Handler) http.Handler {
	allowedOrigins := getAllowedOrigins()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if isOriginAllowed(origin, allowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		// Every header a client sends must be listed here, or the preflight fails
		// and the browser reports an opaque network error. The official iframe
		// client sends traceparent and the x-openfort-* tracing headers;
		// x-token-type accompanies third-party provider tokens.
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-auth-provider, x-request-id, x-player-token, x-cookie-field, "+
			"x-token-type, traceparent, x-openfort-user-id, x-openfort-chain-id, x-openfort-flow-name")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getAllowedOrigins() []string {
	originsEnv := os.Getenv("ALLOWED_ORIGINS")
	if originsEnv == "" {
		return []string{"http://localhost:7050", "http://localhost:7051"}
	}
	return strings.Split(originsEnv, ",")
}

func isOriginAllowed(origin string, allowed []string) bool {
	if origin == "" {
		return false
	}
	for _, a := range allowed {
		if strings.TrimSpace(a) == origin {
			return true
		}
	}
	return false
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId, authProvider, err := validateAuth(r)
		if err != nil || userId == "" {
			unauthorized(w)
			return
		}
		slog.Debug("authenticated request", slog.String("userId", userId))
		ctx := context.WithValue(r.Context(), fieldUserId, userId)
		ctx = context.WithValue(ctx, fieldAuthProvider, authProvider)
		authenticatedRequest := r.WithContext(ctx)
		next.ServeHTTP(w, authenticatedRequest)
	})
}
