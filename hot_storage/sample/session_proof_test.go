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
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	switch c.alg {
	case algEd25519:
		return ed25519.Sign(c.edKey, msg)
	case algES256:
		digest := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, c.ecKey, digest[:])
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig
	}
	t.Fatalf("sign: unsupported alg %q", c.alg)
	return nil
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
