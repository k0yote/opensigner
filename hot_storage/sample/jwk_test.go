package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "http://auth.test:7052"
	testAudience = "http://auth.test:7052"
	testKid      = "test-key-1"
)

// startJWKS serves a JWKS containing the public half of a fresh ES256 key.
// Each server gets a unique URL, so the keyfunc cache in jwk.go cannot leak
// keys between tests.
func startJWKS(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	jwks := fmt.Sprintf(
		`{"keys":[{"kty":"EC","crv":"P-256","kid":%q,"alg":"ES256","use":"sig","x":%q,"y":%q}]}`,
		testKid,
		b64(key.PublicKey.X.FillBytes(make([]byte, 32))),
		b64(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	t.Cleanup(server.Close)
	return server, key
}

func signToken(t *testing.T, key *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testIssuer,
		"aud": testAudience,
		"sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

func TestValidateAcceptsAValidToken(t *testing.T) {
	server, key := startJWKS(t)
	token := signToken(t, key, testKid, validClaims())

	sub, err := validate(token, server.URL, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("valid token was rejected: %v", err)
	}
	if sub != "user-123" {
		t.Fatalf("got sub %q, want %q", sub, "user-123")
	}
}

func TestValidateRejectsBadClaims(t *testing.T) {
	server, key := startJWKS(t)

	mutate := func(fn func(jwt.MapClaims)) jwt.MapClaims {
		claims := validClaims()
		fn(claims)
		return claims
	}

	tests := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{"wrong issuer", mutate(func(c jwt.MapClaims) { c["iss"] = "http://evil.test" })},
		{"missing issuer", mutate(func(c jwt.MapClaims) { delete(c, "iss") })},
		{"wrong audience", mutate(func(c jwt.MapClaims) { c["aud"] = "some-other-app" })},
		{"missing audience", mutate(func(c jwt.MapClaims) { delete(c, "aud") })},
		{"expired", mutate(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })},
		{"no expiry at all", mutate(func(c jwt.MapClaims) { delete(c, "exp") })},
		{"missing sub", mutate(func(c jwt.MapClaims) { delete(c, "sub") })},
		{"empty sub", mutate(func(c jwt.MapClaims) { c["sub"] = "" })},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signToken(t, key, testKid, tt.claims)
			if _, err := validate(token, server.URL, testIssuer, testAudience); err == nil {
				t.Fatal("expected the token to be rejected")
			}
		})
	}
}

// A correctly signed, unexpired token must still be refused when the service
// has no expected issuer/audience configured. jwt.WithIssuer("") skips the
// check entirely, so only the guard in validate stands between an empty config
// and accepting any token the key set can verify.
func TestValidateRejectsEmptyIssuerAudienceConfig(t *testing.T) {
	server, key := startJWKS(t)
	token := signToken(t, key, testKid, validClaims())

	for _, tc := range []struct{ iss, aud string }{
		{"", ""},
		{testIssuer, ""},
		{"", testAudience},
	} {
		if _, err := validate(token, server.URL, tc.iss, tc.aud); err == nil {
			t.Fatalf("a valid token was accepted with iss=%q aud=%q configured", tc.iss, tc.aud)
		}
	}
}

func TestValidateRejectsForgedSignatures(t *testing.T) {
	server, key := startJWKS(t)

	t.Run("alg none", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims())
		token.Header["kid"] = testKid
		unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("failed to build unsigned token: %v", err)
		}
		if _, err := validate(unsigned, server.URL, testIssuer, testAudience); err == nil {
			t.Fatal("an unsigned (alg=none) token was accepted")
		}
	})

	t.Run("HS256 alg confusion", func(t *testing.T) {
		// A symmetric signature must be refused even if an attacker guesses at
		// key material; only the asymmetric methods in WithValidMethods count.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
		token.Header["kid"] = testKid
		signed, err := token.SignedString([]byte("attacker-chosen-secret"))
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}
		if _, err := validate(signed, server.URL, testIssuer, testAudience); err == nil {
			t.Fatal("an HMAC-signed token was accepted")
		}
	})

	t.Run("unknown kid", func(t *testing.T) {
		token := signToken(t, key, "some-other-kid", validClaims())
		if _, err := validate(token, server.URL, testIssuer, testAudience); err == nil {
			t.Fatal("a token signed under an unknown kid was accepted")
		}
	})

	t.Run("signature from a different key", func(t *testing.T) {
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		token := signToken(t, otherKey, testKid, validClaims())
		if _, err := validate(token, server.URL, testIssuer, testAudience); err == nil {
			t.Fatal("a token signed by a key outside the set was accepted")
		}
	})
}
