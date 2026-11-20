package main

// Prototype tests for commit-reveal (verification branch, not for merge).

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// sessionProofTestKey signs the tokens accepted by the JWKS that
// setupSessionProofTest serves. Use sessionToken rather than reading it.
var sessionProofTestKey ed25519.PrivateKey

// setupSessionProofTest gives a test the in-memory schema plus the session
// table, points the default auth provider at a fresh test JWKS (iss/aud are
// testIssuer/testAudience), sets the proof mode, and returns the composed
// chain contentTypeMiddleware(authMiddleware(apiMux())).
func setupSessionProofTest(t *testing.T, mode string) http.Handler {
	t.Helper()
	if _, err := parseSessionProofMode(mode); err != nil {
		t.Fatalf("setupSessionProofTest: %v", err)
	}
	setupHandlerTest(t)
	if err := db.AutoMigrate(&CommitSession{}); err != nil {
		t.Fatalf("failed to migrate CommitSession: %v", err)
	}
	// Every pooled connection to ":memory:" opens its own empty database, so
	// concurrent requests must share the one connection that holds the schema.
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	server, key := startJWKS(t)
	origURL, origIss, origAud := authServerURL, expectedIssuer, expectedAudience
	origMode, origKey := sessionProofMode, sessionProofTestKey
	authServerURL, expectedIssuer, expectedAudience = server.URL, testIssuer, testAudience
	sessionProofMode, sessionProofTestKey = mode, key
	t.Cleanup(func() {
		authServerURL, expectedIssuer, expectedAudience = origURL, origIss, origAud
		sessionProofMode, sessionProofTestKey = origMode, origKey
	})
	return contentTypeMiddleware(authMiddleware(apiMux()))
}

// sessionToken signs claims with the key behind setupSessionProofTest's JWKS.
func sessionToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if sessionProofTestKey == nil {
		t.Fatal("sessionToken called before setupSessionProofTest")
	}
	return signToken(t, sessionProofTestKey, testKid, claims)
}

// proofClient plays the client side of commit-reveal: it holds an ephemeral
// key pair and, after a successful commit, the session it was given.
type proofClient struct {
	alg       string
	publicKey []byte // raw 32 bytes (Ed25519) or 65-byte uncompressed point (ES256)
	edKey     ed25519.PrivateKey
	ecKey     *ecdsa.PrivateKey
	sessionID string // set by commit on 201
	expiresAt int64  // set by commit on 201, unix seconds
}

func newProofClient(t *testing.T, alg string) *proofClient {
	t.Helper()
	c := &proofClient{alg: alg}
	switch alg {
	case algEd25519:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}
		c.publicKey, c.edKey = pub, key
	case algES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate P-256 key: %v", err)
		}
		pub, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatalf("failed to encode P-256 public key: %v", err)
		}
		c.publicKey, c.ecKey = pub, key
	default:
		t.Fatalf("newProofClient: unsupported alg %q", alg)
	}
	return c
}

// sign produces the proof signature over msg: Ed25519 over msg directly, or
// ECDSA P-256 over SHA-256(msg) encoded as 64 bytes r||s.
func (c *proofClient) sign(t *testing.T, msg []byte) []byte {
	t.Helper()
	sig, err := c.signRaw(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// signRaw is sign for helpers that have no *testing.T.
func (c *proofClient) signRaw(msg []byte) ([]byte, error) {
	switch c.alg {
	case algEd25519:
		return ed25519.Sign(c.edKey, msg), nil
	case algES256:
		digest := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, c.ecKey, digest[:])
		if err != nil {
			return nil, fmt.Errorf("failed to sign: %w", err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	}
	return nil, fmt.Errorf("unsupported alg %q", c.alg)
}

// commit posts this client's public key to /v2/sessions/commit with token. On
// 201 it records the returned session id and expiry on the client.
func (c *proofClient) commit(h http.Handler, token string) *httptest.ResponseRecorder {
	w := postCommit(h, token, commitBody(c.alg, base64.RawURLEncoding.EncodeToString(c.publicKey)))
	if w.Code == http.StatusCreated {
		var resp commitSessionResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err == nil {
			c.sessionID, c.expiresAt = resp.SessionID, resp.ExpiresAt
		}
	}
	return w
}

func commitBody(alg, publicKey string) string {
	b, _ := json.Marshal(map[string]string{"alg": alg, "publicKey": publicKey})
	return string(b)
}

// postCommit sends a raw body to the commit endpoint with token as the bearer.
func postCommit(h http.Handler, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v2/sessions/commit", strings.NewReader(body))
	r.Header.Set(contentTypeHeader, contentTypeJSON)
	if token != "" {
		r.Header.Set(headerAuth, headerAuthPrefix+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// The JavaScript client in lab/p2-v5 is the other half of this contract; these
// are the four entries of lab/p2-v5/vectors.json, copied verbatim.
func TestSigningInputVectors(t *testing.T) {
	vectors := []struct {
		name        string
		method      string
		path        string
		deviceID    string
		bodyUTF8    string
		counter     uint64
		sessionID   string
		expectedHex string
	}{
		{
			name:        "get-device",
			method:      "GET",
			path:        "/v1/devices/dev_123",
			deviceID:    "dev_123",
			bodyUTF8:    "",
			counter:     1,
			sessionID:   "0b9f7c1e-5a52-4f0e-9d53-2f6f1c1d7a11",
			expectedHex: "0000001b6f70656e7369676e65722f636f6d6d69742d72657665616c2f763100000003474554000000132f76312f646576696365732f6465765f313233000000076465765f31323300000020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550000000800000000000000010000002430623966376331652d356135322d346630652d396435332d326636663163316437613131",
		},
		{
			name:        "recover",
			method:      "POST",
			path:        "/v2/devices/recover",
			deviceID:    "",
			bodyUTF8:    `{"account":"acc_1"}`,
			counter:     2,
			sessionID:   "0b9f7c1e-5a52-4f0e-9d53-2f6f1c1d7a11",
			expectedHex: "0000001b6f70656e7369676e65722f636f6d6d69742d72657665616c2f763100000004504f5354000000132f76322f646576696365732f7265636f7665720000000000000020a1f33c88c18211b116c26b6ec3cbd05b00abd09ba07e1ff39b4fc6c79131526d0000000800000000000000020000002430623966376331652d356135322d346630652d396435332d326636663163316437613131",
		},
		{
			name:        "primary-large-counter",
			method:      "GET",
			path:        "/v1/devices/primary",
			deviceID:    "primary",
			bodyUTF8:    "",
			counter:     9007199254740993,
			sessionID:   "0b9f7c1e-5a52-4f0e-9d53-2f6f1c1d7a11",
			expectedHex: "0000001b6f70656e7369676e65722f636f6d6d69742d72657665616c2f763100000003474554000000132f76312f646576696365732f7072696d617279000000077072696d61727900000020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550000000800200000000000010000002430623966376331652d356135322d346630652d396435332d326636663163316437613131",
		},
		{
			// Lengths are UTF-8 byte lengths, not character counts.
			name:        "utf8-fields",
			method:      "POST",
			path:        "/v2/devices/recover",
			deviceID:    "端末-é",
			bodyUTF8:    `{"account":"口座_1"}`,
			counter:     3,
			sessionID:   "0b9f7c1e-5a52-4f0e-9d53-2f6f1c1d7a11",
			expectedHex: "0000001b6f70656e7369676e65722f636f6d6d69742d72657665616c2f763100000004504f5354000000132f76322f646576696365732f7265636f76657200000009e7abafe69cab2dc3a90000002087e9be548522c9ef95209c756b69de9857ae15df318820801cf22c84a7ac33a40000000800000000000000030000002430623966376331652d356135322d346630652d396435332d326636663163316437613131",
		},
	}
	if len(vectors) != 4 {
		t.Fatalf("got %d vectors, want all 4 from vectors.json", len(vectors))
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got := signingInput(proofFields{
				Method:     v.method,
				Path:       v.path,
				DeviceID:   v.deviceID,
				BodySHA256: sha256.Sum256([]byte(v.bodyUTF8)),
				Counter:    v.counter,
				SessionID:  v.sessionID,
			})
			if gotHex := hex.EncodeToString(got); gotHex != v.expectedHex {
				t.Fatalf("signing input mismatch\n got  %s\n want %s", gotHex, v.expectedHex)
			}
		})
	}
}

func TestJwtBindingIgnoresSignature(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	claims := validClaims()
	token := signToken(t, key, testKid, claims)

	binding, err := jwtBinding(token)
	if err != nil {
		t.Fatalf("jwtBinding(valid token): %v", err)
	}
	parts := strings.Split(token, ".")
	want := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if binding != hex.EncodeToString(want[:]) {
		t.Fatalf("got binding %s, want lowercase hex SHA-256 of header.payload", binding)
	}

	t.Run("signature-only differences give the same binding", func(t *testing.T) {
		variants := nonCanonicalVariants(token)
		if len(variants) != 15 {
			t.Fatalf("got %d variants, want 15", len(variants))
		}
		_, otherKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		resigned := signToken(t, otherKey, testKid, claims)
		if resigned == token || !strings.HasPrefix(resigned, parts[0]+"."+parts[1]+".") {
			t.Fatal("test setup: re-signed token should differ only in its signature")
		}
		for i, other := range append(variants, resigned) {
			got, err := jwtBinding(other)
			if err != nil {
				t.Fatalf("token %d: %v", i, err)
			}
			if got != binding {
				t.Fatalf("token %d differs only in its signature but got a different binding", i)
			}
		}
	})

	t.Run("a different payload gives a different binding", func(t *testing.T) {
		otherClaims := validClaims()
		otherClaims["sub"] = "user-456"
		got, err := jwtBinding(signToken(t, key, testKid, otherClaims))
		if err != nil {
			t.Fatalf("jwtBinding: %v", err)
		}
		if got == binding {
			t.Fatal("tokens with different payloads got the same binding")
		}
	})

	t.Run("malformed tokens are errors", func(t *testing.T) {
		for _, bad := range []string{
			parts[0] + "." + parts[1], // two segments
			"",
			"no-dots",
			token + ".extra", // four segments
			"." + parts[1] + "." + parts[2],
			parts[0] + ".." + parts[2],
		} {
			if got, err := jwtBinding(bad); err == nil {
				t.Fatalf("jwtBinding(%d segments) = %q, want an error", strings.Count(bad, ".")+1, got)
			}
		}
	})
}

func TestVerifyProofBothAlgs(t *testing.T) {
	msg := signingInput(proofFields{
		Method:     http.MethodGet,
		Path:       "/v1/devices/primary",
		DeviceID:   "primary",
		BodySHA256: sha256.Sum256(nil),
		Counter:    1,
		SessionID:  "0b9f7c1e-5a52-4f0e-9d53-2f6f1c1d7a11",
	})

	for _, alg := range []string{algEd25519, algES256} {
		t.Run(alg, func(t *testing.T) {
			c := newProofClient(t, alg)
			sig := c.sign(t, msg)
			if len(sig) != 64 {
				t.Fatalf("got a %d-byte signature, want 64", len(sig))
			}
			if !verifyProof(alg, c.publicKey, msg, sig) {
				t.Fatal("a correct signature was rejected")
			}

			for bit := 0; bit < len(sig)*8; bit++ {
				flipped := append([]byte(nil), sig...)
				flipped[bit/8] ^= 1 << (bit % 8)
				if verifyProof(alg, c.publicKey, msg, flipped) {
					t.Fatalf("a signature with bit %d flipped was accepted", bit)
				}
			}

			other := newProofClient(t, alg)
			if verifyProof(alg, other.publicKey, msg, sig) {
				t.Fatal("a signature was accepted under a different key")
			}

			tampered := append([]byte(nil), msg...)
			tampered[len(tampered)-1] ^= 0x01
			if verifyProof(alg, c.publicKey, tampered, sig) {
				t.Fatal("a signature was accepted over a different message")
			}
		})
	}

	t.Run("cross-alg and malformed inputs are false and never panic", func(t *testing.T) {
		ed := newProofClient(t, algEd25519)
		es := newProofClient(t, algES256)
		edSig := ed.sign(t, msg)
		esSig := es.sign(t, msg)
		zeroRS := make([]byte, 64)
		orderRS := make([]byte, 64)
		elliptic.P256().Params().N.FillBytes(orderRS[:32])
		new(big.Int).SetInt64(1).FillBytes(orderRS[32:])

		cases := []struct {
			name           string
			alg            string
			publicKey, sig []byte
		}{
			{"Ed25519 sig checked as ES256", algES256, ed.publicKey, edSig},
			{"ES256 sig checked as Ed25519", algEd25519, es.publicKey, esSig},
			{"unknown alg", "RS256", ed.publicKey, edSig},
			{"empty alg", "", ed.publicKey, edSig},
			{"nil Ed25519 key", algEd25519, nil, edSig},
			{"31-byte Ed25519 key", algEd25519, ed.publicKey[:31], edSig},
			{"33-byte Ed25519 key", algEd25519, append(append([]byte(nil), ed.publicKey...), 0), edSig},
			{"63-byte Ed25519 sig", algEd25519, ed.publicKey, edSig[:63]},
			{"nil ES256 key", algES256, nil, esSig},
			{"64-byte ES256 key", algES256, es.publicKey[1:], esSig},
			{"63-byte ES256 sig", algES256, es.publicKey, esSig[:63]},
			{"65-byte ES256 sig", algES256, es.publicKey, append(append([]byte(nil), esSig...), 0)},
			{"DER-length ES256 sig", algES256, es.publicKey, make([]byte, 72)},
			{"ES256 r=s=0", algES256, es.publicKey, zeroRS},
			{"ES256 r=N", algES256, es.publicKey, orderRS},
		}
		for _, tc := range cases {
			if verifyProof(tc.alg, tc.publicKey, msg, tc.sig) {
				t.Fatalf("%s: verifyProof returned true", tc.name)
			}
		}
	})
}

// This documents a known limitation of the prototype, not a desired property.
// checkPublicKey only checks the Ed25519 key length, so a client can commit a
// small-order key. Under the identity point (01 followed by 31 zero bytes) the
// signature R = identity, S = 0 verifies for every message, so anyone can
// forge proofs for such a session.
func TestVerifyProofAcceptsForgeryUnderSmallOrderKey(t *testing.T) {
	identityKey := make([]byte, ed25519.PublicKeySize)
	identityKey[0] = 0x01
	trivialSig := make([]byte, ed25519.SignatureSize)
	trivialSig[0] = 0x01

	if err := checkPublicKey(algEd25519, identityKey); err != nil {
		t.Fatalf("checkPublicKey rejected the identity key (%v); update this record", err)
	}
	for _, f := range []proofFields{
		{Method: http.MethodGet, Path: "/v1/devices/primary", DeviceID: "primary", BodySHA256: sha256.Sum256(nil), Counter: 1, SessionID: "s1"},
		{Method: http.MethodPost, Path: "/v2/devices/recover", BodySHA256: sha256.Sum256([]byte(`{"account":"acc_1"}`)), Counter: 2, SessionID: "s2"},
	} {
		if !verifyProof(algEd25519, identityKey, signingInput(f), trivialSig) {
			t.Fatalf("%s %s: the trivial signature did not verify under the identity key; update this record", f.Method, f.Path)
		}
	}
	t.Log("known limitation: an Ed25519 small-order public key is accepted at commit, and proofs under it can be forged by anyone")
}

func TestCommitOncePerJWT(t *testing.T) {
	h := setupSessionProofTest(t, sessionProofOff)
	claims := validClaims()
	// An expiry no fixed TTL would produce, so ExpiresAt must come from exp.
	claims["exp"] = time.Now().Add(2*time.Hour + 17*time.Minute).Unix()
	token := sessionToken(t, claims)
	exp := claims["exp"].(int64)

	first := newProofClient(t, algEd25519)
	w := first.commit(h, token)
	if w.Code != http.StatusCreated {
		t.Fatalf("first commit got %d, want 201: %s", w.Code, w.Body.String())
	}
	if first.sessionID == "" {
		t.Fatalf("201 response carried no session id: %s", w.Body.String())
	}
	if first.expiresAt != exp {
		t.Fatalf("response expiresAt %d, want the JWT exp %d", first.expiresAt, exp)
	}

	// V5-E6: one session per JWT, whatever key the second caller offers.
	second := newProofClient(t, algES256)
	if w := second.commit(h, token); w.Code != http.StatusConflict {
		t.Fatalf("second commit with the same JWT got %d, want 409", w.Code)
	}

	// V5-E6: the 15 signature encodings that decode to the same bytes are not
	// a second JWT; strict decoding refuses them before the handler.
	variants := nonCanonicalVariants(token)
	if len(variants) != 15 {
		t.Fatalf("got %d variants, want 15", len(variants))
	}
	for i, v := range variants {
		c := newProofClient(t, algEd25519)
		if w := c.commit(h, v); w.Code != http.StatusUnauthorized {
			t.Fatalf("variant %d got %d, want 401", i, w.Code)
		}
	}

	var rows []CommitSession
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("load sessions: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d session rows, want 1", len(rows))
	}
	row := rows[0]
	wantBinding, err := jwtBinding(token)
	if err != nil {
		t.Fatalf("jwtBinding: %v", err)
	}
	if row.ID != first.sessionID || row.JwtBinding != wantBinding {
		t.Fatalf("stored row id=%s binding=%s, want the first commit's session and the token's binding", row.ID, row.JwtBinding)
	}
	// spec §4.3 (4): the session ends when the JWT does.
	if row.ExpiresAt.Unix() != exp {
		t.Fatalf("stored ExpiresAt %d, want the JWT exp %d", row.ExpiresAt.Unix(), exp)
	}
	if row.Alg != algEd25519 || string(row.PublicKey) != string(first.publicKey) || row.Counter != 0 {
		t.Fatalf("stored alg=%s counter=%d, want the first committer's key with counter 0", row.Alg, row.Counter)
	}
	if row.Username != "user-123" || row.AuthProvider != authProviderDefault {
		t.Fatalf("stored subject %s@%s, want user-123@default", row.Username, row.AuthProvider)
	}

	// The binding is per JWT, not per user: a freshly issued token commits. Its
	// short expiry catches a fixed TTL or a cap from the other side.
	fresh := validClaims()
	fresh["jti"] = "second-token"
	fresh["exp"] = time.Now().Add(7 * time.Minute).Unix()
	freshExp := fresh["exp"].(int64)
	third := newProofClient(t, algEd25519)
	if w := third.commit(h, sessionToken(t, fresh)); w.Code != http.StatusCreated {
		t.Fatalf("commit with a different JWT for the same user got %d, want 201", w.Code)
	}
	if third.expiresAt != freshExp {
		t.Fatalf("short-lived token: response expiresAt %d, want the JWT exp %d", third.expiresAt, freshExp)
	}
	var freshRow CommitSession
	if err := db.First(&freshRow, "id = ?", third.sessionID).Error; err != nil {
		t.Fatalf("load short-lived session: %v", err)
	}
	if freshRow.ExpiresAt.Unix() != freshExp {
		t.Fatalf("short-lived token: stored ExpiresAt %d, want the JWT exp %d", freshRow.ExpiresAt.Unix(), freshExp)
	}
}

// V5-E8 is a record of what the prototype does, not a requirement; the codes
// are still asserted so a change in behaviour shows up.
func TestCommitFirstWins(t *testing.T) {
	h := setupSessionProofTest(t, sessionProofShare)
	token := sessionToken(t, validClaims())

	attacker := newProofClient(t, algEd25519)
	legit := newProofClient(t, algES256)
	attackerCode := attacker.commit(h, token).Code
	legitCode := legit.commit(h, token).Code

	t.Logf("V5-E8 observation: the party that commits a JWT first owns its session. "+
		"Attacker (stolen JWT, committed first) got %d; legitimate client (same JWT, second) got %d.",
		attackerCode, legitCode)
	if attackerCode != http.StatusCreated {
		t.Fatalf("attacker's first commit got %d, want 201", attackerCode)
	}
	if legitCode != http.StatusConflict {
		t.Fatalf("legitimate client's later commit got %d, want 409", legitCode)
	}
}

func TestCommitRejectsMalformedKeys(t *testing.T) {
	h := setupSessionProofTest(t, sessionProofAll)
	token := sessionToken(t, validClaims())

	edPub := newProofClient(t, algEd25519).publicKey
	ecPub := newProofClient(t, algES256).publicKey
	clone := func(b []byte) []byte { return append([]byte(nil), b...) }

	offCurve := clone(ecPub)
	offCurve[64] ^= 0x01
	compressed := append([]byte{0x02 | (ecPub[64] & 1)}, ecPub[1:33]...)
	badPrefix := clone(ecPub)
	badPrefix[0] = 0x05
	infinity := make([]byte, 65)
	infinity[0] = 0x04

	b64 := base64.RawURLEncoding.EncodeToString
	// 32 bytes encode to 43 characters; the last carries 2 unused bits, so
	// flipping its lowest bit decodes to the same key in a lenient decoder.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	canonical := b64(edPub)
	last := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	nonCanonical := canonical[:len(canonical)-1] + string(alphabet[last^1])

	cases := []struct{ name, body string }{
		{"Ed25519 key of 31 bytes", commitBody(algEd25519, b64(edPub[:31]))},
		{"Ed25519 key of 33 bytes", commitBody(algEd25519, b64(append(clone(edPub), 0)))},
		{"Ed25519 with a P-256 point", commitBody(algEd25519, b64(ecPub))},
		{"empty key", commitBody(algEd25519, "")},
		{"ES256 key of 64 bytes", commitBody(algES256, b64(ecPub[1:]))},
		{"ES256 compressed point", commitBody(algES256, b64(compressed))},
		{"ES256 point not on the curve", commitBody(algES256, b64(offCurve))},
		{"ES256 unknown point prefix", commitBody(algES256, b64(badPrefix))},
		{"ES256 all-zero point", commitBody(algES256, b64(infinity))},
		{"ES256 with an Ed25519 key", commitBody(algES256, b64(edPub))},
		{"unknown alg", commitBody("RS256", b64(edPub))},
		{"alg in another case", commitBody("ed25519", b64(edPub))},
		{"empty alg", commitBody("", b64(edPub))},
		{"padded base64url", commitBody(algEd25519, base64.URLEncoding.EncodeToString(edPub))},
		{"non-canonical trailing bits", commitBody(algEd25519, nonCanonical)},
		{"not base64url", commitBody(algEd25519, "not+base64/url")},
		{"missing publicKey", `{"alg":"Ed25519"}`},
		{"unknown field", `{"alg":"Ed25519","publicKey":"` + canonical + `","extra":1}`},
	}
	for _, tc := range cases {
		if w := postCommit(h, token, tc.body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", tc.name, w.Code)
		}
	}

	var n int64
	db.Model(&CommitSession{}).Count(&n)
	if n != 0 {
		t.Fatalf("rejected commits created %d session row(s), want 0", n)
	}
	// A rejected commit does not use up the JWT.
	if w := postCommit(h, token, commitBody(algEd25519, canonical)); w.Code != http.StatusCreated {
		t.Fatalf("well-formed commit after the rejected ones got %d, want 201", w.Code)
	}
}

// The binding is only placed in the context for the default provider, so a
// request without it -- injected identity, or a Google token -- cannot commit.
func TestCommitWithoutBindingIsUnauthorized(t *testing.T) {
	h := setupSessionProofTest(t, sessionProofOff)
	body := commitBody(algEd25519, base64.RawURLEncoding.EncodeToString(newProofClient(t, algEd25519).publicKey))

	t.Run("identity injected without a binding", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v2/sessions/commit", strings.NewReader(body))
		w := httptest.NewRecorder()
		apiMux().ServeHTTP(w, asUser(r, "user-123", authProviderDefault))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got %d, want 401", w.Code)
		}
	})

	t.Run("google provider", func(t *testing.T) {
		const aud = "test-google-client-id"
		originalURL, originalAud := authProviderGoogleUrl, googleAudience
		t.Cleanup(func() { authProviderGoogleUrl, googleAudience = originalURL, originalAud })
		server, key := startRS256JWKS(t)
		authProviderGoogleUrl, googleAudience = server.URL, aud
		token := signRS256Token(t, key, testKid, jwt.MapClaims{
			"iss": authProviderGoogleIssuer,
			"aud": aud,
			"sub": "google-user-1",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		send := func(method, path, body string) int {
			r := httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set(contentTypeHeader, contentTypeJSON)
			r.Header.Set(headerAuth, headerAuthPrefix+token)
			r.Header.Set(headerAuthProvider, authProviderGoogle)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w.Code
		}
		// The token authenticates, so the commit's 401 is the missing binding.
		if code := send(http.MethodGet, "/v2/accounts", ""); code != http.StatusOK {
			t.Fatalf("test setup: the Google token got %d on /v2/accounts, want 200", code)
		}
		if code := send(http.MethodPost, "/v2/sessions/commit", body); code != http.StatusUnauthorized {
			t.Fatalf("got %d, want 401", code)
		}
	})

	t.Run("no token", func(t *testing.T) {
		if w := postCommit(h, "", body); w.Code != http.StatusUnauthorized {
			t.Fatalf("got %d, want 401", w.Code)
		}
	})

	var n int64
	db.Model(&CommitSession{}).Count(&n)
	if n != 0 {
		t.Fatalf("unauthorized commits created %d session row(s), want 0", n)
	}
}

// The unique index on jwt_binding and ON CONFLICT DO NOTHING decide the race,
// not a read before the write. The test database serialises statements on
// one connection, so this pins the outcome rather than the interleaving.
func TestCommitConcurrentSameJWTCreatesOneSession(t *testing.T) {
	h := setupSessionProofTest(t, sessionProofOff)
	token := sessionToken(t, validClaims())

	const n = 8
	clients := make([]*proofClient, n)
	for i := range clients {
		clients[i] = newProofClient(t, algEd25519)
	}
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Go(func() { codes[i] = c.commit(h, token).Code })
	}
	wg.Wait()

	created, conflicts := 0, 0
	for _, code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicts++
		}
	}
	if created != 1 || conflicts != n-1 {
		t.Fatalf("got codes %v, want exactly one 201 and %d 409s", codes, n-1)
	}
	var rows int64
	db.Model(&CommitSession{}).Count(&rows)
	if rows != 1 {
		t.Fatalf("got %d session rows, want 1", rows)
	}
}

func TestModeOffKeepsExistingBehaviour(t *testing.T) {
	for _, mode := range []string{"", sessionProofOff} {
		t.Run("mode="+mode, func(t *testing.T) {
			h := setupSessionProofTest(t, mode)
			_, device := seedAccount(t, "user-123", authProviderDefault, "0xoff1")
			token := sessionToken(t, validClaims())

			for _, path := range []string{"/v1/devices/" + device.ID, "/v1/devices/primary"} {
				r := httptest.NewRequest(http.MethodGet, path, nil)
				r.Header.Set(headerAuth, headerAuthPrefix+token)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusOK {
					t.Fatalf("GET %s without proof headers got %d, want 200: %s", path, w.Code, w.Body.String())
				}
				var resp DeviceResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if resp.Share != "share-of-user-123" {
					t.Fatalf("GET %s: got share %q, want the seeded share", path, resp.Share)
				}
			}

			var n int64
			db.Model(&CommitSession{}).Count(&n)
			if n != 0 {
				t.Fatalf("share reads created %d session row(s), want 0", n)
			}
		})
	}
}

func TestModeIsValidatedByConfig(t *testing.T) {
	const iss = "https://auth.example"
	original := sessionProofMode
	t.Cleanup(func() { sessionProofMode = original })

	for _, tc := range []struct {
		mode    string
		wantErr bool
	}{
		{mode: ""},
		{mode: "off"},
		{mode: "share"},
		{mode: "all"},
		{mode: "OFF", wantErr: true},
		{mode: " off", wantErr: true},
		{mode: "on", wantErr: true},
		{mode: "strict", wantErr: true},
	} {
		withConfig(t, "https://auth.internal:3000", iss, iss, false)
		sessionProofMode = tc.mode
		err := validateConfig()
		if tc.wantErr && err == nil {
			t.Fatalf("SESSION_PROOF_MODE=%q was accepted", tc.mode)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("SESSION_PROOF_MODE=%q was rejected: %v", tc.mode, err)
		}
	}
}

func TestParseVerifiedHonoursNowFunc(t *testing.T) {
	server, key := startJWKS(t)
	token := signToken(t, key, testKid, validClaims())

	claims, err := parseVerified(token, server.URL, testIssuer, testAudience, []string{"EdDSA"})
	if err != nil {
		t.Fatalf("valid token was rejected: %v", err)
	}
	if claims["sub"] != "user-123" {
		t.Fatalf("got sub %v, want user-123", claims["sub"])
	}

	original := nowFunc
	t.Cleanup(func() { nowFunc = original })
	nowFunc = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := parseVerified(token, server.URL, testIssuer, testAudience, []string{"EdDSA"}); err == nil {
		t.Fatal("parseVerified accepted a token that has expired by nowFunc")
	}
	if _, err := validate(token, server.URL, testIssuer, testAudience); err == nil {
		t.Fatal("validate accepted a token that has expired by nowFunc")
	}
}

// --- The proof check on share-returning routes (V5-E5, E7 to E10, E12) ---

// aliceShare is the share seedAccount stores for alice. Every accepted share
// request must return it, and no rejected one may.
const aliceShare = "share-of-alice"

// shareRoute is one share-returning request as the proof tests send it.
type shareRoute = struct{ name, method, path, body, deviceID string }

// shareRoutes lists the four share-returning requests for alice's seeded
// account and device: /v1/devices/{deviceId} with a device id and with
// primary, /v2/devices/recover and /v1/devices/init.
func shareRoutes(account Account, device Device) []struct{ name, method, path, body, deviceID string } {
	return []shareRoute{
		{"get-device", http.MethodGet, "/v1/devices/" + device.ID, "", device.ID},
		{"get-primary", http.MethodGet, "/v1/devices/primary", "", "primary"},
		{"recover", http.MethodPost, "/v2/devices/recover", fmt.Sprintf(`{"account":%q}`, account.ID), ""},
		{"init", http.MethodPost, "/v1/devices/init", fmt.Sprintf(`{"chainId":%d}`, account.ChainId), ""},
	}
}

type proofFixture struct {
	h       http.Handler
	account Account
	device  Device
}

// newProofFixture is setupSessionProofTest plus alice's seeded account.
func newProofFixture(t *testing.T, mode string) proofFixture {
	t.Helper()
	h := setupSessionProofTest(t, mode)
	account, device := seedAccount(t, "alice", authProviderDefault, "0xa11ce")
	return proofFixture{h: h, account: account, device: device}
}

// forEachShareRoute runs fn as one subtest per share route, each with its own
// database, JWKS and seeded account, so one route's sessions and counters
// cannot affect another's.
func forEachShareRoute(t *testing.T, mode string, fn func(t *testing.T, f proofFixture, rt shareRoute)) {
	t.Helper()
	for i, probe := range shareRoutes(Account{}, Device{}) {
		t.Run(probe.name, func(t *testing.T) {
			f := newProofFixture(t, mode)
			fn(t, f, shareRoutes(f.account, f.device)[i])
		})
	}
}

// userToken signs a token for sub that expires at exp. jti keeps it distinct
// from the user's other tokens: EdDSA is deterministic, so equal claims give
// the same token, the same binding, and a 409 on the second commit.
func userToken(t *testing.T, sub, jti string, exp time.Time) string {
	t.Helper()
	claims := validClaims()
	claims["sub"], claims["jti"], claims["exp"] = sub, jti, exp.Unix()
	return sessionToken(t, claims)
}

func aliceToken(t *testing.T, jti string) string {
	t.Helper()
	return userToken(t, "alice", jti, time.Now().Add(time.Hour))
}

func mustCommit(t *testing.T, h http.Handler, c *proofClient, token string) {
	t.Helper()
	if w := c.commit(h, token); w.Code != http.StatusCreated {
		t.Fatalf("commit got %d, want 201", w.Code)
	}
}

func storedCounter(t *testing.T, sessionID string) int64 {
	t.Helper()
	var s CommitSession
	if err := db.First(&s, "id = ?", sessionID).Error; err != nil {
		t.Fatalf("load session: %v", err)
	}
	return s.Counter
}

// fakeClock makes nowFunc return the time the returned pointer holds, for JWT
// validation and the session expiry check alike, until the test ends.
func fakeClock(t *testing.T, start time.Time) *time.Time {
	t.Helper()
	now := start
	original := nowFunc
	nowFunc = func() time.Time { return now }
	t.Cleanup(func() { nowFunc = original })
	return &now
}

// routeDeviceID is the {deviceId} path value the server's route table gives
// method and path, or "" when the matched pattern has none. The client signs
// this value, so it is derived with the real patterns and ServeMux rules.
func routeDeviceID(method, path string) string {
	var got string
	mux := http.NewServeMux()
	for _, rt := range apiRoutes() {
		mux.HandleFunc(rt.pattern, func(_ http.ResponseWriter, r *http.Request) { got = r.PathValue(fieldDeviceId) })
	}
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))
	return got
}

// proof is the X-Session-Signature value c sends for these request facts.
func (c *proofClient) proof(method, path, deviceID, body string, counter uint64) string {
	sig, err := c.signRaw(signingInput(proofFields{
		Method:     method,
		Path:       path,
		DeviceID:   deviceID,
		BodySHA256: sha256.Sum256([]byte(body)),
		Counter:    counter,
		SessionID:  c.sessionID,
	}))
	if err != nil {
		panic("proofClient.proof: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}

// do sends a request with token as the bearer (none when empty) and a proof
// for counter, signed with c's key for c's session over the request exactly as
// built. Each mutate then runs on the request before it is served, so a
// mutation is a change made after signing.
func (c *proofClient) do(h http.Handler, token, method, path, body string, counter uint64, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	// Always JSON, so a case that switches the method to POST reaches the
	// proof check rather than contentTypeMiddleware's 415.
	r.Header.Set(contentTypeHeader, contentTypeJSON)
	if token != "" {
		r.Header.Set(headerAuth, headerAuthPrefix+token)
	}
	r.Header.Set(headerSessionID, c.sessionID)
	r.Header.Set(headerSessionCounter, strconv.FormatUint(counter, 10))
	r.Header.Set(headerSessionSignature, c.proof(r.Method, r.URL.Path, routeDeviceID(r.Method, r.URL.Path), body, counter))
	for _, m := range mutate {
		m(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// jwtOnly sends a request with the JWT and no proof headers.
func jwtOnly(h http.Handler, token, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set(contentTypeHeader, contentTypeJSON)
	r.Header.Set(headerAuth, headerAuthPrefix+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func withHeader(name, value string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

func addHeader(name, value string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Add(name, value) }
}

func withoutHeader(name string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Del(name) }
}

func withMethod(method string) func(*http.Request) {
	return func(r *http.Request) { r.Method = method }
}

func withPath(path string) func(*http.Request) {
	return func(r *http.Request) { r.URL.Path, r.URL.RawPath = path, "" }
}

func withBody(body string) func(*http.Request) {
	return func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
	}
}

func hasShare(w *httptest.ResponseRecorder) bool {
	return strings.Contains(w.Body.String(), aliceShare)
}

// wantShare fails unless w is a 200 that carries alice's share, so "accepted"
// always means the share was returned.
func wantShare(t *testing.T, w *httptest.ResponseRecorder, what string) {
	t.Helper()
	if w.Code != http.StatusOK || !hasShare(w) {
		t.Fatalf("%s: got %d (share returned: %t), want 200 with the share", what, w.Code, hasShare(w))
	}
}

// wantRejected fails unless w has status code and does not carry the share.
// Bodies are not printed, since a wrongly accepted one would hold the share.
func wantRejected(t *testing.T, w *httptest.ResponseRecorder, code int, what string) {
	t.Helper()
	if hasShare(w) {
		t.Fatalf("%s: got %d and the response carried the share, want %d", what, w.Code, code)
	}
	if w.Code != code {
		t.Fatalf("%s: got %d, want %d", what, w.Code, code)
	}
}

// V5-E5: counters 1, 2 and 3 each return the share. Replaying the counter-2
// request as it was sent, signature included, is refused, and the stored
// counter stays at 3.
func TestProofAllowsIncreasingCountersAndRejectsReplay(t *testing.T) {
	for _, alg := range []string{algEd25519, algES256} {
		t.Run(alg, func(t *testing.T) {
			forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
				token := aliceToken(t, "e5")
				c := newProofClient(t, alg)
				mustCommit(t, f.h, c, token)

				var second string
				capture := func(r *http.Request) { second = r.Header.Get(headerSessionSignature) }
				wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, 1), "counter 1")
				wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, 2, capture), "counter 2")
				wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, 3), "counter 3")

				replay := c.do(f.h, token, rt.method, rt.path, rt.body, 2, withHeader(headerSessionSignature, second))
				wantRejected(t, replay, http.StatusConflict, "replay of the counter-2 request")
				if got := storedCounter(t, c.sessionID); got != 3 {
					t.Fatalf("stored counter %d after the replay, want 3", got)
				}
			})
		})
	}
}

// V5-E7 (a) and (b): the right JWT, session id and counter are not enough.
// Without a signature, or with one made by another key, nothing is returned
// and the counter does not move.
func TestProofRejectsMissingOrForeignSignature(t *testing.T) {
	for _, alg := range []string{algEd25519, algES256} {
		t.Run(alg, func(t *testing.T) {
			forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
				token := aliceToken(t, "e7ab")
				c := newProofClient(t, alg)
				mustCommit(t, f.h, c, token)

				w := c.do(f.h, token, rt.method, rt.path, rt.body, 1, withoutHeader(headerSessionSignature))
				wantRejected(t, w, http.StatusUnauthorized, "(a) no signature header")

				foreign := newProofClient(t, alg)
				foreign.sessionID = c.sessionID
				w = foreign.do(f.h, token, rt.method, rt.path, rt.body, 1)
				wantRejected(t, w, http.StatusUnauthorized, "(b) signature by another key")

				if got := storedCounter(t, c.sessionID); got != 0 {
					t.Fatalf("stored counter %d after the rejected requests, want 0", got)
				}
				// Counter 1 is still unused, so the session itself was sound.
				wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, 1), "the session's own key, counter 1")
			})
		})
	}
}

// V5-E8, second half. A record, not a requirement: with a stolen JWT, whoever
// commits first owns the session. The codes this prototype produces are still
// asserted, so a change in behaviour shows up.
func TestFirstCommitterCanFetch(t *testing.T) {
	forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
		token := aliceToken(t, "e8")
		attacker := newProofClient(t, algEd25519)
		legit := newProofClient(t, algES256)

		attackerCommit := attacker.commit(f.h, token).Code
		legitCommit := legit.commit(f.h, token).Code
		attackerFetch := attacker.do(f.h, token, rt.method, rt.path, rt.body, 1)
		legitPlain := jwtOnly(f.h, token, rt.method, rt.path, rt.body)
		// The legitimate client may learn the session id, but not the key.
		// Counter 2 is fresh, so only the signature can refuse this.
		legit.sessionID = attacker.sessionID
		legitOnAttackers := legit.do(f.h, token, rt.method, rt.path, rt.body, 2)

		t.Logf("V5-E8 record (%s %s): attacker (stolen JWT, committed first) got commit %d, fetch %d (share returned: %t); "+
			"legitimate client got commit %d, then %d with the JWT alone and %d with the attacker's session id under its own key",
			rt.method, rt.name, attackerCommit, attackerFetch.Code, hasShare(attackerFetch),
			legitCommit, legitPlain.Code, legitOnAttackers.Code)
		if attackerCommit != http.StatusCreated || legitCommit != http.StatusConflict {
			t.Fatalf("commits got attacker %d and legitimate %d, want 201 and 409", attackerCommit, legitCommit)
		}
		wantShare(t, attackerFetch, "the first committer's fetch")
		wantRejected(t, legitPlain, http.StatusUnauthorized, "the legitimate client with the JWT alone")
		wantRejected(t, legitOnAttackers, http.StatusUnauthorized, "the legitimate client on the attacker's session")
	})
}

// V5-E7 (c) and (d): a session is usable only with the JWT it was committed
// with, whoever holds the session's key.
func TestProofRejectsSessionFromAnotherJWT(t *testing.T) {
	t.Run("c-other-users-session", func(t *testing.T) {
		forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
			aliceJWT := aliceToken(t, "e7c")
			alice := newProofClient(t, algEd25519)
			mustCommit(t, f.h, alice, aliceJWT)
			bob := newProofClient(t, algEd25519)
			mustCommit(t, f.h, bob, userToken(t, "bob", "e7c", time.Now().Add(time.Hour)))

			// Bob has stolen alice's JWT, which alice has already committed, and
			// attaches his own session id and a signature by his own key.
			w := bob.do(f.h, aliceJWT, rt.method, rt.path, rt.body, 1)
			wantRejected(t, w, http.StatusUnauthorized, "(c) alice's JWT with bob's session and key")
			if got := storedCounter(t, bob.sessionID); got != 0 {
				t.Fatalf("bob's stored counter %d after the rejected request, want 0", got)
			}
			wantShare(t, alice.do(f.h, aliceJWT, rt.method, rt.path, rt.body, 1), "alice's JWT with her own session")
		})
	})

	t.Run("d-same-user-other-jwt", func(t *testing.T) {
		forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
			jwt1, jwt2 := aliceToken(t, "e7d-1"), aliceToken(t, "e7d-2")
			if jwt1 == jwt2 {
				t.Fatal("test setup: the two JWTs are identical")
			}
			c1, c2 := newProofClient(t, algEd25519), newProofClient(t, algEd25519)
			mustCommit(t, f.h, c1, jwt1)
			mustCommit(t, f.h, c2, jwt2)

			w := c1.do(f.h, jwt2, rt.method, rt.path, rt.body, 1)
			wantRejected(t, w, http.StatusUnauthorized, "(d) JWT 2 with session 1 and key 1")
			if got := storedCounter(t, c1.sessionID); got != 0 {
				t.Fatalf("session 1's stored counter %d after the rejected request, want 0", got)
			}
			wantShare(t, c1.do(f.h, jwt1, rt.method, rt.path, rt.body, 1), "JWT 1 with session 1")
			wantShare(t, c2.do(f.h, jwt2, rt.method, rt.path, rt.body, 1), "JWT 2 with session 2")
		})
	})
}

// V5-E9. Every case sends the route's own share request with a proof signed
// for a request that differs from it in exactly one signed field; were that
// field not covered, the case would return the share. Method, path, body and
// counter are changed on the request after signing. The deviceId cannot be
// changed on its own on the wire, since it is a segment of the path (or empty),
// so for it the signature is made over another deviceId instead.
func TestProofRejectsAnyTamperedField(t *testing.T) {
	forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
		token := aliceToken(t, "e9")
		c := newProofClient(t, algEd25519)
		mustCommit(t, f.h, c, token)

		otherMethod := http.MethodPost
		if rt.method == http.MethodPost {
			otherMethod = http.MethodGet
		}
		// A path whose route gives the same deviceId, so only the path differs.
		signedPath := "/v2/devices/" + rt.deviceID
		switch rt.path {
		case "/v2/devices/recover":
			signedPath = "/v1/devices/init"
		case "/v1/devices/init":
			signedPath = "/v2/devices/recover"
		}
		otherBody := "{}"
		if rt.body != "" {
			// The same JSON in different bytes: the handler would accept it.
			otherBody = strings.Replace(rt.body, ":", ": ", 1)
		}
		otherDevice := rt.deviceID + "-other"
		if got := routeDeviceID(rt.method, rt.path); got != rt.deviceID {
			t.Fatalf("test setup: the route gives deviceId %q, want %q", got, rt.deviceID)
		}
		if got := routeDeviceID(rt.method, signedPath); got != rt.deviceID {
			t.Fatalf("test setup: %s gives deviceId %q, want %q", signedPath, got, rt.deviceID)
		}

		cases := []struct {
			field string
			send  func() *httptest.ResponseRecorder
		}{
			{"method", func() *httptest.ResponseRecorder {
				return c.do(f.h, token, otherMethod, rt.path, rt.body, 1, withMethod(rt.method))
			}},
			{"path", func() *httptest.ResponseRecorder {
				return c.do(f.h, token, rt.method, signedPath, rt.body, 1, withPath(rt.path))
			}},
			{"deviceId", func() *httptest.ResponseRecorder {
				return c.do(f.h, token, rt.method, rt.path, rt.body, 1,
					withHeader(headerSessionSignature, c.proof(rt.method, rt.path, otherDevice, rt.body, 1)))
			}},
			{"body", func() *httptest.ResponseRecorder {
				return c.do(f.h, token, rt.method, rt.path, otherBody, 1, withBody(rt.body))
			}},
			{"counter", func() *httptest.ResponseRecorder {
				return c.do(f.h, token, rt.method, rt.path, rt.body, 1, withHeader(headerSessionCounter, "2"))
			}},
		}
		for _, tc := range cases {
			t.Run(tc.field, func(t *testing.T) {
				wantRejected(t, tc.send(), http.StatusUnauthorized, "tampered "+tc.field)
			})
		}

		if got := storedCounter(t, c.sessionID); got != 0 {
			t.Fatalf("stored counter %d after the tampered requests, want 0", got)
		}
		wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, 1), "the untampered request")
	})
}

// Review Focus 2: the query string is not in the signing input, so a request
// that carries one is refused before the session is looked at.
func TestProofRejectsQueryString(t *testing.T) {
	forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
		token := aliceToken(t, "query")
		c := newProofClient(t, algEd25519)
		mustCommit(t, f.h, c, token)

		// The proof is valid for the path; only the query string is extra.
		wantRejected(t, c.do(f.h, token, rt.method, rt.path+"?x=1", rt.body, 1), http.StatusBadRequest, "?x=1")
		if got := storedCounter(t, c.sessionID); got != 0 {
			t.Fatalf("stored counter %d after the rejected request, want 0", got)
		}
		wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, 1), "the same request without the query string")
	})
}

// Review Focus 3. A correctly signed counter at or below the last accepted
// one is refused with 409. A header that is not a canonical decimal below
// 2^63 is refused with 400 before anything is looked up.
func TestProofRejectsBadCounters(t *testing.T) {
	forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
		token := aliceToken(t, "counters")
		c := newProofClient(t, algEd25519)
		mustCommit(t, f.h, c, token)
		wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, 5), "counter 5")

		for _, n := range []uint64{0, 5, 4} {
			wantRejected(t, c.do(f.h, token, rt.method, rt.path, rt.body, n), http.StatusConflict,
				fmt.Sprintf("counter %d after 5", n))
		}
		for _, raw := range []string{"1e3", "-1", "9223372036854775808", "18446744073709551616", "01", "+1", "0x10", ""} {
			wantRejected(t, c.do(f.h, token, rt.method, rt.path, rt.body, 6, withHeader(headerSessionCounter, raw)),
				http.StatusBadRequest, fmt.Sprintf("counter header %q", raw))
		}
		if got := storedCounter(t, c.sessionID); got != 5 {
			t.Fatalf("stored counter %d after the rejected requests, want 5", got)
		}
		wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, 6), "counter 6")
		wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, math.MaxInt64), "counter 2^63-1, the largest accepted")
	})
}

// V5-E10, on a fake clock: a session lasts as long as the JWT it was committed
// with, and is usable only with that JWT.
func TestSessionLifetimeFollowsJWT(t *testing.T) {
	t.Run("a-to-d", func(t *testing.T) {
		forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
			base := time.Now().Truncate(time.Second)
			clock := fakeClock(t, base)
			jwt1 := userToken(t, "alice", "e10-1", base.Add(10*time.Minute))
			c1 := newProofClient(t, algEd25519)
			mustCommit(t, f.h, c1, jwt1)
			wantShare(t, c1.do(f.h, jwt1, rt.method, rt.path, rt.body, 1), "session 1 with JWT 1 before JWT 1 expires")

			*clock = base.Add(10*time.Minute + time.Second)
			wantRejected(t, c1.do(f.h, jwt1, rt.method, rt.path, rt.body, 2), http.StatusUnauthorized,
				"(a) session 1 with JWT 1 after JWT 1 expired")

			jwt2 := userToken(t, "alice", "e10-2", base.Add(40*time.Minute))
			c2 := newProofClient(t, algEd25519)
			mustCommit(t, f.h, c2, jwt2)
			wantShare(t, c2.do(f.h, jwt2, rt.method, rt.path, rt.body, 1), "(b) session 2 with JWT 2")

			wantRejected(t, c1.do(f.h, jwt2, rt.method, rt.path, rt.body, 2), http.StatusUnauthorized,
				"(c) session 1's id and key with JWT 2 after JWT 1 expired")
			if got := storedCounter(t, c1.sessionID); got != 1 {
				t.Fatalf("session 1's stored counter %d after the rejected requests, want 1", got)
			}

			// (d) A reload: a fresh key, the same JWT 2.
			c3 := newProofClient(t, algEd25519)
			recommit := c3.commit(f.h, jwt2).Code
			c3.sessionID = c2.sessionID
			stuck := c3.do(f.h, jwt2, rt.method, rt.path, rt.body, 2)
			c3.sessionID = ""
			jwt3 := userToken(t, "alice", "e10-3", base.Add(70*time.Minute))
			nextCommit := c3.commit(f.h, jwt3).Code
			afterNext := c3.do(f.h, jwt3, rt.method, rt.path, rt.body, 1)
			t.Logf("V5-E10 (d) record (%s): after a reload, the new key's commit with JWT 2 got %d and the new key on session 2 got %d; "+
				"with the next JWT the commit got %d and the fetch %d (share returned: %t)",
				rt.name, recommit, stuck.Code, nextCommit, afterNext.Code, hasShare(afterNext))
			if recommit != http.StatusConflict {
				t.Fatalf("(d) commit with a fresh key and the same JWT 2 got %d, want 409", recommit)
			}
			wantRejected(t, stuck, http.StatusUnauthorized, "(d) the reloaded key on session 2")
			if nextCommit != http.StatusCreated {
				t.Fatalf("(d) commit with the next JWT got %d, want 201", nextCommit)
			}
			wantShare(t, afterNext, "(d) the reloaded key with the next JWT")
		})
	})

	// (e) is a record, not a requirement: §4.3 lets a new commit leave the
	// user's older session alive until its own JWT expires.
	t.Run("e", func(t *testing.T) {
		forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
			base := time.Now().Truncate(time.Second)
			clock := fakeClock(t, base)
			jwt1 := userToken(t, "alice", "e10e-1", base.Add(10*time.Minute))
			c1 := newProofClient(t, algEd25519)
			mustCommit(t, f.h, c1, jwt1)
			wantShare(t, c1.do(f.h, jwt1, rt.method, rt.path, rt.body, 1), "session 1 with JWT 1")

			*clock = base.Add(5 * time.Minute)
			jwt2 := userToken(t, "alice", "e10e-2", base.Add(40*time.Minute))
			c2 := newProofClient(t, algEd25519)
			mustCommit(t, f.h, c2, jwt2)

			w := c1.do(f.h, jwt1, rt.method, rt.path, rt.body, 2)
			t.Logf("V5-E10 (e) record (%s): after JWT 2 was committed and before JWT 1 expired, session 1 with JWT 1 got %d (share returned: %t)",
				rt.name, w.Code, hasShare(w))
			wantShare(t, w, "(e) session 1 with JWT 1 after JWT 2's commit")
		})
	})
}

// V5-E12. A record, not a requirement: with SESSION_PROOF_MODE=all, the three
// routes the Client App calls directly need a proof too, so the JWT alone no
// longer reaches them. The commit route stays reachable with the JWT alone.
func TestModeAllBlocksJWTOnlyRoutes(t *testing.T) {
	type call struct {
		method, path string
		served       int
	}
	setup := func(t *testing.T, mode string) (proofFixture, string, []call) {
		t.Helper()
		f := newProofFixture(t, mode)
		secondary, err := newDevice("second-device-share", f.account.SignerId, false)
		if err != nil {
			t.Fatalf("seed secondary device: %v", err)
		}
		if err := db.Create(&secondary).Error; err != nil {
			t.Fatalf("seed secondary device row: %v", err)
		}
		return f, secondary.ID, []call{
			{http.MethodGet, "/v2/accounts", http.StatusOK},
			{http.MethodGet, "/v2/devices", http.StatusOK},
			{http.MethodDelete, "/v2/devices/" + secondary.ID, http.StatusNoContent},
		}
	}

	t.Run("all", func(t *testing.T) {
		f, secondaryID, calls := setup(t, sessionProofAll)
		token := aliceToken(t, "e12")
		codes := make([]int, len(calls))
		for i, cl := range calls {
			codes[i] = jwtOnly(f.h, token, cl.method, cl.path, "").Code
		}
		c := newProofClient(t, algEd25519)
		commit := c.commit(f.h, token).Code

		t.Logf("V5-E12 record: with SESSION_PROOF_MODE=all and the JWT alone, GET /v2/accounts got %d, GET /v2/devices got %d, "+
			"DELETE /v2/devices/{deviceId} got %d; POST /v2/sessions/commit got %d", codes[0], codes[1], codes[2], commit)
		for i, cl := range calls {
			if codes[i] != http.StatusUnauthorized {
				t.Fatalf("%s %s with the JWT alone got %d, want 401", cl.method, cl.path, codes[i])
			}
		}
		if commit != http.StatusCreated {
			t.Fatalf("commit with the JWT alone got %d, want 201", commit)
		}
		var d Device
		if err := db.First(&d, "id = ?", secondaryID).Error; err != nil {
			t.Fatalf("load secondary device: %v", err)
		}
		if d.RevokedAt != nil || d.Share == "" {
			t.Fatal("the refused DELETE revoked the device")
		}
		wantRejected(t, jwtOnly(f.h, token, http.MethodGet, "/v1/devices/primary", ""), http.StatusUnauthorized,
			"a share route with the JWT alone")

		// With a proof, the same calls are served.
		for i, cl := range calls {
			if w := c.do(f.h, token, cl.method, cl.path, "", uint64(i+1)); w.Code != cl.served {
				t.Fatalf("%s %s with a proof got %d, want %d", cl.method, cl.path, w.Code, cl.served)
			}
		}
	})

	t.Run("share-serves-them-with-the-JWT-alone", func(t *testing.T) {
		f, _, calls := setup(t, sessionProofShare)
		token := aliceToken(t, "e12")
		for _, cl := range calls {
			if code := jwtOnly(f.h, token, cl.method, cl.path, "").Code; code != cl.served {
				t.Fatalf("%s %s with the JWT alone got %d, want %d", cl.method, cl.path, code, cl.served)
			}
		}
	})
}

// The check order of requireSessionProof, pinned where two checks would give
// different answers, and the cases the experiments above do not reach.
func TestProofCheckOrder(t *testing.T) {
	forEachShareRoute(t, sessionProofShare, func(t *testing.T, f proofFixture, rt shareRoute) {
		token := aliceToken(t, "order")
		c := newProofClient(t, algEd25519)
		mustCommit(t, f.h, c, token)

		valid := c.proof(rt.method, rt.path, rt.deviceID, rt.body, 1)
		sig, err := base64.RawURLEncoding.DecodeString(valid)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		b64 := base64.RawURLEncoding.EncodeToString
		// 64 bytes encode to 86 characters; the last carries 4 unused bits, so
		// flipping its lowest bit decodes to the same bytes in a lenient decoder.
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		last := strings.IndexByte(alphabet, valid[len(valid)-1])
		nonCanonical := valid[:len(valid)-1] + string(alphabet[last^1])
		unknownID := uuid.NewString()
		// An authenticated identity with no JWT binding behind it.
		injected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiMux().ServeHTTP(w, asUser(r, "alice", authProviderDefault))
		})
		send := func(mutate ...func(*http.Request)) *httptest.ResponseRecorder {
			return c.do(f.h, token, rt.method, rt.path, rt.body, 1, mutate...)
		}

		cases := []struct {
			name string
			want int
			send func() *httptest.ResponseRecorder
		}{
			{"no X-Session-Id", http.StatusUnauthorized, func() *httptest.ResponseRecorder {
				return send(withoutHeader(headerSessionID))
			}},
			{"no X-Session-Counter", http.StatusUnauthorized, func() *httptest.ResponseRecorder {
				return send(withoutHeader(headerSessionCounter))
			}},
			{"no X-Session-Signature", http.StatusUnauthorized, func() *httptest.ResponseRecorder {
				return send(withoutHeader(headerSessionSignature))
			}},
			{"no proof headers", http.StatusUnauthorized, func() *httptest.ResponseRecorder {
				return jwtOnly(f.h, token, rt.method, rt.path, rt.body)
			}},
			{"missing before malformed", http.StatusUnauthorized, func() *httptest.ResponseRecorder {
				return send(withoutHeader(headerSessionSignature), withHeader(headerSessionCounter, "x"))
			}},
			{"missing before query string", http.StatusUnauthorized, func() *httptest.ResponseRecorder {
				return c.do(f.h, token, rt.method, rt.path+"?x=1", rt.body, 1, withoutHeader(headerSessionSignature))
			}},
			{"empty session id", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionID, ""))
			}},
			{"session id that is not a UUID", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionID, "not-a-uuid"))
			}},
			{"session id of 129 bytes", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionID, strings.Repeat("a", 129)))
			}},
			{"upper-case session id", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionID, strings.ToUpper(c.sessionID)))
			}},
			{"session id in braces", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionID, "{"+c.sessionID+"}"))
			}},
			{"repeated counter header", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(addHeader(headerSessionCounter, "1"))
			}},
			{"padded signature", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionSignature, base64.URLEncoding.EncodeToString(sig)))
			}},
			{"signature with non-canonical trailing bits", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionSignature, nonCanonical))
			}},
			{"signature outside the base64url alphabet", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionSignature, valid[:10]+"+"+valid[11:]))
			}},
			{"63-byte signature", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionSignature, b64(sig[:63])))
			}},
			{"65-byte signature", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionSignature, b64(append(append([]byte(nil), sig...), 0))))
			}},
			{"query string before session lookup", http.StatusBadRequest, func() *httptest.ResponseRecorder {
				return c.do(f.h, token, rt.method, rt.path+"?x=1", rt.body, 1, withHeader(headerSessionID, unknownID))
			}},
			{"unknown session", http.StatusUnauthorized, func() *httptest.ResponseRecorder {
				return send(withHeader(headerSessionID, unknownID))
			}},
			{"identity without a JWT binding", http.StatusUnauthorized, func() *httptest.ResponseRecorder {
				return c.do(injected, "", rt.method, rt.path, rt.body, 1)
			}},
			{"body over 1 MiB", http.StatusRequestEntityTooLarge, func() *httptest.ResponseRecorder {
				return c.do(f.h, token, rt.method, rt.path, strings.Repeat(" ", 1<<20+1), 1)
			}},
		}
		for _, tc := range cases {
			wantRejected(t, tc.send(), tc.want, tc.name)
		}
		if got := storedCounter(t, c.sessionID); got != 0 {
			t.Fatalf("stored counter %d after the rejected requests, want 0", got)
		}
		wantShare(t, c.do(f.h, token, rt.method, rt.path, rt.body, 1), "counter 1 after the rejected requests")

		// Signature (401) before counter (409): counter 1 is now used. A caller
		// without the session key must get 401, not a 409 that would tell it the
		// session's counter; the session's own key gets the 409.
		other := newProofClient(t, algEd25519)
		other.sessionID = c.sessionID
		foreign := other.proof(rt.method, rt.path, rt.deviceID, rt.body, 1)
		wantRejected(t, c.do(f.h, token, rt.method, rt.path, rt.body, 1, withHeader(headerSessionSignature, foreign)),
			http.StatusUnauthorized, "used counter, signed by another key")
		wantRejected(t, c.do(f.h, token, rt.method, rt.path, rt.body, 1), http.StatusConflict,
			"used counter, signed by the session key")
		if got := storedCounter(t, c.sessionID); got != 1 {
			t.Fatalf("stored counter %d after the used-counter requests, want 1", got)
		}

		// Step 6 on its own: the JWT is still valid, the stored expiry is not.
		if err := db.Model(&CommitSession{}).Where("id = ?", c.sessionID).
			Update("expires_at", nowFunc().Add(-time.Second)).Error; err != nil {
			t.Fatalf("expire session: %v", err)
		}
		wantRejected(t, c.do(f.h, token, rt.method, rt.path, rt.body, 2), http.StatusUnauthorized,
			"session past its stored expiry, JWT still valid")
		if got := storedCounter(t, c.sessionID); got != 1 {
			t.Fatalf("stored counter %d after the expired request, want 1", got)
		}
	})
}
