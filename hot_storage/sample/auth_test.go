package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGetTokenFromHeader(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantErr   error
	}{
		{name: "valid bearer token", header: "Bearer abc.def.ghi", wantToken: "abc.def.ghi"},
		{name: "bearer with padding", header: "Bearer   abc.def.ghi  ", wantToken: "abc.def.ghi"},
		{name: "absent header", header: "", wantErr: ErrMissingToken},
		{name: "bearer with no token", header: "Bearer ", wantErr: ErrMissingToken},
		// A token offered without its scheme must be refused, not inferred.
		{name: "bare token without scheme", header: "abc.def.ghi", wantErr: ErrInvalidToken},
		{name: "wrong scheme", header: "Basic some-other-scheme-value", wantErr: ErrInvalidToken},
		{name: "lowercase scheme is rejected", header: "bearer abc.def.ghi", wantErr: ErrInvalidToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v2/accounts", nil)
			if tt.header != "" {
				r.Header.Set(headerAuth, tt.header)
			}

			got, err := getTokenFromHeader(r)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("got error %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantToken {
				t.Fatalf("got token %q, want %q", got, tt.wantToken)
			}
		})
	}
}

func TestGetTokenFromCookieRejectsUnknownField(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v2/accounts", nil)
	r.Header.Set(headerCookieFieldName, "attacker-chosen-cookie")
	r.AddCookie(&http.Cookie{Name: "attacker-chosen-cookie", Value: "token"})

	if _, err := getTokenFromCookie(r); err != ErrInvalidToken {
		t.Fatalf("got %v, want ErrInvalidToken for a non-allow-listed cookie field", err)
	}
}

func TestGetTokenRejectsBothHeaderAndCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v2/accounts", nil)
	r.Header.Set(headerAuth, "Bearer abc.def.ghi")
	r.Header.Set(headerCookieFieldName, "better-auth.session_token")
	r.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "cookie-token"})

	if _, err := getToken(r); err != ErrDuplicateToken {
		t.Fatalf("got %v, want ErrDuplicateToken", err)
	}
}

func TestGetTokenFromCookie(t *testing.T) {
	t.Run("allow-listed field returns the token", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v2/accounts", nil)
		r.Header.Set(headerCookieFieldName, "better-auth.session_token")
		r.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "session-token"})

		got, err := getTokenFromCookie(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "session-token" {
			t.Fatalf("got %q, want %q", got, "session-token")
		}
	})

	t.Run("named cookie absent", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v2/accounts", nil)
		r.Header.Set(headerCookieFieldName, "better-auth.session_token")

		if _, err := getTokenFromCookie(r); err != ErrMissingToken {
			t.Fatalf("got %v, want ErrMissingToken", err)
		}
	})

	t.Run("empty cookie value", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v2/accounts", nil)
		r.Header.Set(headerCookieFieldName, "better-auth.session_token")
		r.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: ""})

		if _, err := getTokenFromCookie(r); err != ErrMissingToken {
			t.Fatalf("got %v, want ErrMissingToken", err)
		}
	})
}

func TestGetTokenRejectsMalformedHeaderDespiteValidCookie(t *testing.T) {
	// A malformed Authorization header must fail the request outright, not fall
	// back to the cookie as if the header had never been sent.
	r := httptest.NewRequest(http.MethodGet, "/v2/accounts", nil)
	r.Header.Set(headerAuth, "Basic not-a-bearer-token")
	r.Header.Set(headerCookieFieldName, "better-auth.session_token")
	r.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "cookie-token"})

	if _, err := getToken(r); err != ErrInvalidToken {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestValidateThirdPartyRejectsUnconfiguredGoogle(t *testing.T) {
	original := googleAudience
	googleAudience = ""
	t.Cleanup(func() { googleAudience = original })

	_, err := validateThirdPartyAuth("some.google.token", authProviderGoogle)
	if err == nil {
		t.Fatal("expected Google tokens to be rejected while no audience is configured")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateThirdPartyRejectsUnknownProvider(t *testing.T) {
	if _, err := validateThirdPartyAuth("token", "made-up-provider"); err == nil {
		t.Fatal("expected an unknown provider to be rejected")
	}
}

func TestContentTypeMiddleware(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		contentType string
		wantStatus  int
	}{
		{name: "json accepted", method: http.MethodPost, contentType: "application/json", wantStatus: http.StatusOK},
		{name: "json with charset accepted", method: http.MethodPost, contentType: "application/json; charset=utf-8", wantStatus: http.StatusOK},
		// Both are CORS-safelisted, so a browser sends them cross-origin without a
		// preflight; both must be refused.
		{name: "text/plain smuggling rejected", method: http.MethodPost, contentType: "text/plain; x=application/json", wantStatus: http.StatusUnsupportedMediaType},
		{name: "absent content type rejected", method: http.MethodPost, contentType: "", wantStatus: http.StatusUnsupportedMediaType},
		{name: "form encoded rejected", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", wantStatus: http.StatusUnsupportedMediaType},
		{name: "PUT is guarded too", method: http.MethodPut, contentType: "text/plain", wantStatus: http.StatusUnsupportedMediaType},
		{name: "PATCH is guarded too", method: http.MethodPatch, contentType: "", wantStatus: http.StatusUnsupportedMediaType},
		{name: "GET needs no content type", method: http.MethodGet, contentType: "", wantStatus: http.StatusOK},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "/v1/devices/init", strings.NewReader("{}"))
			if tt.contentType != "" {
				r.Header.Set(contentTypeHeader, tt.contentType)
			}
			w := httptest.NewRecorder()

			contentTypeMiddleware(next).ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Fatalf("got status %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestIsOriginAllowed(t *testing.T) {
	allowed := []string{"http://localhost:7050", " http://localhost:7051 "}
	tests := []struct {
		origin string
		want   bool
	}{
		{"http://localhost:7050", true},
		{"http://localhost:7051", true}, // entries are trimmed
		{"", false},
		{"https://evil.example", false},
		{"http://localhost:7050.evil.example", false}, // no suffix matching
		{"http://localhost:705", false},               // no prefix matching
		{"null", false},
	}

	for _, tt := range tests {
		if got := isOriginAllowed(tt.origin, allowed); got != tt.want {
			t.Errorf("isOriginAllowed(%q) = %v, want %v", tt.origin, got, tt.want)
		}
	}
}

func TestValidateThirdPartyRejectsPlayFab(t *testing.T) {
	if _, err := validateThirdPartyAuth("token", authProviderPlayFab); err == nil {
		t.Fatal("expected the unimplemented playfab provider to be rejected")
	}
}

func TestGoogleProviderAcceptsRS256Only(t *testing.T) {
	const aud = "test-google-client-id"
	originalURL, originalAud := authProviderGoogleUrl, googleAudience
	t.Cleanup(func() { authProviderGoogleUrl, googleAudience = originalURL, originalAud })

	claims := jwt.MapClaims{
		"iss": authProviderGoogleIssuer,
		"aud": aud,
		"sub": "google-user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Each subtest sets the package variables it needs itself.
	rsServer, rsKey := startRS256JWKS(t)
	rsToken := signRS256Token(t, rsKey, testKid, claims)

	t.Run("RS256 accepted", func(t *testing.T) {
		authProviderGoogleUrl, googleAudience = rsServer.URL, aud
		sub, err := validateThirdPartyAuth(rsToken, authProviderGoogle)
		if err != nil {
			t.Fatalf("a valid RS256 Google token was rejected: %v", err)
		}
		if sub != "google-user-1" {
			t.Fatalf("got sub %q, want %q", sub, "google-user-1")
		}
	})

	t.Run("non-canonical RS256 variants rejected", func(t *testing.T) {
		authProviderGoogleUrl, googleAudience = rsServer.URL, aud
		variants := nonCanonicalVariants(rsToken)
		if len(variants) != 15 {
			t.Fatalf("got %d variants, want 15", len(variants))
		}
		for i, v := range variants {
			if _, err := validateThirdPartyAuth(v, authProviderGoogle); err == nil {
				t.Fatalf("variant %d with non-canonical trailing bits was accepted", i)
			}
		}
	})

	t.Run("EdDSA rejected", func(t *testing.T) {
		edServer, edKey := startJWKS(t)
		authProviderGoogleUrl, googleAudience = edServer.URL, aud
		token := signToken(t, edKey, testKid, claims)
		if _, err := validateThirdPartyAuth(token, authProviderGoogle); err == nil {
			t.Fatal("an EdDSA token was accepted by the Google provider; only RS256 is allowed")
		}
	})

	t.Run("ES256 rejected", func(t *testing.T) {
		esServer, esKey := startES256JWKS(t)
		authProviderGoogleUrl, googleAudience = esServer.URL, aud
		token := signES256Token(t, esKey, testKid, claims)
		if _, err := validateThirdPartyAuth(token, authProviderGoogle); err == nil {
			t.Fatal("an ES256 token was accepted by the Google provider; only RS256 is allowed")
		}
	})
}
