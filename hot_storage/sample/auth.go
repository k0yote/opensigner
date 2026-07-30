package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const (
	headerAuth            = "Authorization"
	headerAuthPrefix      = "Bearer "
	headerAuthProvider    = "X-Auth-Provider"
	headerCookieFieldName = "X-Cookie-Field"

	authProviderDefault = "default"
	authProviderGoogle  = "google"
	authProviderPlayFab = "playfab"

	authProviderGoogleUrl    = "https://www.googleapis.com/oauth2/v3/certs"
	authProviderGoogleIssuer = "https://accounts.google.com"
)

var (
	ErrDuplicateToken = errors.New("only one token delivery method (header or cookie) is allowed")
	ErrMissingToken   = errors.New("missing token")
	ErrInvalidToken   = errors.New("invalid token")

	allowedCookieFields = map[string]bool{
		"better-auth.session_token":             true,
		"better-auth.session_token.ct":          true,
		"__Secure-better-auth.session_token":    true,
		"__Secure-better-auth.session_token.ct": true,
	}
)

func validateAuth(r *http.Request) (string, string, error) {
	token, err := getToken(r)
	if err != nil {
		return "", "", err
	}

	authProvider := r.Header.Get(headerAuthProvider)
	if authProvider == "" {
		authProvider = authProviderDefault
	}

	var userId string
	switch authProvider {
	case authProviderDefault:
		userId, err = validateDefaultAuth(token)
	default:
		userId, err = validateThirdPartyAuth(token, authProvider)
	}
	return userId, authProvider, err
}

func validateThirdPartyAuth(token string, authProvider string) (string, error) {
	switch authProvider {
	case authProviderGoogle:
		// googleAudience is this deployment's OAuth client ID. Without it any
		// Google-signed ID token -- including one minted for an unrelated
		// application -- would authenticate as whatever subject it carries.
		if googleAudience == "" {
			return "", errors.New("google auth provider is not configured")
		}
		return validate(token, authProviderGoogleUrl, authProviderGoogleIssuer, googleAudience)
	case authProviderPlayFab:
		return "", errors.New("playfab third party authentication is unimplemented")
	default:
		return "", errors.New("unsupported auth provider")
	}
}

func validateDefaultAuth(token string) (string, error) {
	jwkUrl := fmt.Sprintf("%s/.well-known/jwks.json", authServerURL)
	userId, err := validate(token, jwkUrl, expectedIssuer, expectedAudience)
	if err != nil {
		slog.Info(fmt.Sprintf("failed to authenticate user: '%v'", err))
		return "", err
	}
	slog.Info("authenticated user", slog.String("externalUserId", userId))
	return userId, nil
}

func unauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"unauthorized"}`))
}

func getToken(r *http.Request) (string, error) {
	headerToken, err := getTokenFromHeader(r)
	if err != nil && !errors.Is(err, ErrMissingToken) {
		return "", err
	}

	cookieToken, err := getTokenFromCookie(r)
	if err != nil && !errors.Is(err, ErrMissingToken) {
		return "", err
	}

	if cookieToken != "" && headerToken != "" {
		return "", ErrDuplicateToken
	}

	if cookieToken == "" && headerToken == "" {
		return "", ErrMissingToken
	}

	var token string
	if headerToken != "" {
		token = headerToken
	} else {
		token = cookieToken
	}
	return token, nil
}

func getTokenFromHeader(r *http.Request) (string, error) {
	raw := r.Header.Get(headerAuth)
	if raw == "" {
		return "", ErrMissingToken
	}
	// The scheme is required, not optional: a header that omits it is malformed
	// and must be rejected rather than treated as a bare token.
	if !strings.HasPrefix(raw, headerAuthPrefix) {
		return "", ErrInvalidToken
	}
	token := strings.TrimSpace(strings.TrimPrefix(raw, headerAuthPrefix))
	if token == "" {
		return "", ErrMissingToken
	}
	return token, nil
}

func getTokenFromCookie(r *http.Request) (string, error) {
	cookieFieldName := r.Header.Get(headerCookieFieldName)
	if cookieFieldName == "" {
		return "", ErrMissingToken
	}

	if !allowedCookieFields[cookieFieldName] {
		return "", ErrInvalidToken
	}

	cookie, err := r.Cookie(cookieFieldName)
	if err != nil {
		if err == http.ErrNoCookie {
			return "", ErrMissingToken
		}
		return "", ErrInvalidToken
	}
	token := cookie.Value
	if token == "" {
		return "", ErrMissingToken
	}
	return token, nil
}
