package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "http://auth.test:7052"
	testAudience = "http://auth.test:7052"
	testKid      = "test-key-1"
)

// startJWKS serves a JWKS containing the public half of a fresh Ed25519 key.
// Each server gets a unique URL, so the keyfunc cache in jwk.go cannot leak
// keys between tests.
func startJWKS(t *testing.T) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	jwks := fmt.Sprintf(
		`{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":%q,"x":%q}]}`,
		testKid,
		base64.RawURLEncoding.EncodeToString(pub),
	)
	return serveJWKS(t, jwks), key
}

func serveJWKS(t *testing.T, jwks string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	t.Cleanup(server.Close)
	return server
}

func signToken(t *testing.T, key ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

// startES256JWKS serves a JWKS containing the public half of a fresh ES256 key.
func startES256JWKS(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey) {
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
	return serveJWKS(t, jwks), key
}

func signES256Token(t *testing.T, key *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

// startRS256JWKS serves a JWKS containing the public half of a fresh 2048-bit RSA key.
func startRS256JWKS(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	jwks := fmt.Sprintf(
		`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`,
		testKid,
		b64(key.PublicKey.N.Bytes()),
		b64(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	)
	return serveJWKS(t, jwks), key
}

func signRS256Token(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

// nonCanonicalVariants returns tokens whose signature differs from the original
// only in the unused trailing bits of the last base64url character. This applies
// when the unpadded signature length mod 4 is 2 (64-byte and 256-byte signatures):
// the last character then carries 2 real bits and 4 unused bits, so the 15 other
// characters sharing the same top 2 bits decode to the same bytes in a lenient
// decoder. It returns nil when the signature has a different length.
func nonCanonicalVariants(token string) []string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	dot := strings.LastIndexByte(token, '.')
	if dot < 0 || (len(token)-dot-1)%4 != 2 {
		return nil
	}
	orig := strings.IndexByte(alphabet, token[len(token)-1])
	if orig < 0 {
		return nil
	}
	var variants []string
	for i := 0; i < len(alphabet); i++ {
		if i == orig || i>>4 != orig>>4 {
			continue
		}
		variants = append(variants, token[:len(token)-1]+string(alphabet[i]))
	}
	return variants
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
		_, otherKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		token := signToken(t, otherKey, testKid, validClaims())
		if _, err := validate(token, server.URL, testIssuer, testAudience); err == nil {
			t.Fatal("a token signed by a key outside the set was accepted")
		}
	})
}

func TestValidateRejectsES256(t *testing.T) {
	server, key := startES256JWKS(t)
	token := signES256Token(t, key, testKid, validClaims())
	if _, err := validate(token, server.URL, testIssuer, testAudience); err == nil {
		t.Fatal("an ES256 token was accepted; only EdDSA is allowed (D15)")
	}
}

func TestValidateRejectsRS256(t *testing.T) {
	server, key := startRS256JWKS(t)
	token := signRS256Token(t, key, testKid, validClaims())
	if _, err := validate(token, server.URL, testIssuer, testAudience); err == nil {
		t.Fatal("an RS256 token was accepted by the default provider; only EdDSA is allowed (D15)")
	}
}

func TestValidateRejectsNonCanonicalSignatureEncoding(t *testing.T) {
	server, key := startJWKS(t)
	token := signToken(t, key, testKid, validClaims())
	if _, err := validate(token, server.URL, testIssuer, testAudience); err != nil {
		t.Fatalf("the canonical token was rejected: %v", err)
	}
	variants := nonCanonicalVariants(token)
	if len(variants) != 15 {
		t.Fatalf("got %d variants, want 15", len(variants))
	}
	for i, v := range variants {
		if _, err := validate(v, server.URL, testIssuer, testAudience); err == nil {
			t.Fatalf("variant %d with non-canonical trailing bits was accepted", i)
		}
	}
}
