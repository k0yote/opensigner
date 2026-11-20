package main

// Prototype of commit-reveal for the P2 verification (V5). It lives on a
// verification branch only: never merged, never deployed.
//
// A client commits an ephemeral public key together with its JWT, once per
// JWT. Later share-returning requests carry a counter and a signature over
// signingInput made with that key. SESSION_PROOF_MODE selects where the proof
// is required; off (the default) leaves every existing route as it was.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm/clause"
)

const (
	sessionProofOff   = "off"
	sessionProofShare = "share"
	sessionProofAll   = "all"

	algEd25519 = "Ed25519"
	algES256   = "ES256"

	// signingInputDomain is the first field of every signing input, so a proof
	// cannot be mistaken for a signature made for another purpose.
	signingInputDomain = "opensigner/commit-reveal/v1"

	fieldJwtBinding contextKey = "jwtBinding"
	fieldJwtExpiry  contextKey = "jwtExpiry"
)

// parseSessionProofMode returns the effective mode for a SESSION_PROOF_MODE
// value: empty means off, and anything other than off, share or all is an
// error, so a typo cannot quietly select a mode.
func parseSessionProofMode(raw string) (string, error) {
	switch raw {
	case "", sessionProofOff:
		return sessionProofOff, nil
	case sessionProofShare, sessionProofAll:
		return raw, nil
	}
	return "", fmt.Errorf("SESSION_PROOF_MODE must be off, share or all (got %q)", raw)
}

// proofFields are the request facts a proof signature covers.
type proofFields struct {
	Method, Path, DeviceID string
	BodySHA256             [32]byte
	Counter                uint64
	SessionID              string
}

// signingInput encodes f as seven fields, each a 4-byte big-endian byte length
// followed by the bytes: the domain string, method, path, deviceId (empty when
// the route has none), the raw SHA-256 of the body, the counter as 8 bytes
// big-endian, and the session id. The JavaScript client produces the same
// bytes; lab/p2-v5/vectors.json is the contract.
func signingInput(f proofFields) []byte {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], f.Counter)
	fields := [][]byte{
		[]byte(signingInputDomain),
		[]byte(f.Method),
		[]byte(f.Path),
		[]byte(f.DeviceID),
		f.BodySHA256[:],
		counter[:],
		[]byte(f.SessionID),
	}
	size := 0
	for _, field := range fields {
		size += 4 + len(field)
	}
	out := make([]byte, 0, size)
	for _, field := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out
}

// jwtBinding identifies a JWT for the one-commit-per-JWT rule: the lowercase
// hex SHA-256 of header + "." + payload exactly as received. The signature
// segment is left out, so re-encodings of the same signature cannot pass as a
// second token.
func jwtBinding(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("token is not a three-segment JWS")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return hex.EncodeToString(sum[:]), nil
}

// checkPublicKey reports whether key has the shape alg requires: 32 raw bytes
// for Ed25519, or a 65-byte uncompressed point on P-256 for ES256.
func checkPublicKey(alg string, key []byte) error {
	switch alg {
	case algEd25519:
		// Length only: small-order public keys (the identity point among them)
		// are not rejected, and anyone can forge proofs under such a key. A
		// real implementation must reject them.
		if len(key) != ed25519.PublicKeySize {
			return errors.New("Ed25519 public key must be 32 bytes")
		}
		return nil
	case algES256:
		_, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), key)
		return err
	}
	return errors.New("unknown alg")
}

// verifyProof checks sig over msg under publicKey. Ed25519 signs msg directly;
// ES256 is ECDSA P-256 over SHA-256(msg) with sig as 64 bytes r||s (not DER).
// Any malformed input is false, never a panic.
func verifyProof(alg string, publicKey, msg, sig []byte) bool {
	switch alg {
	case algEd25519:
		// ed25519.Verify panics on a public key of the wrong length.
		if len(publicKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(publicKey, msg, sig)
	case algES256:
		if len(sig) != 64 {
			return false
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKey)
		if err != nil {
			return false
		}
		digest := sha256.Sum256(msg)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(pub, digest[:], r, s)
	}
	return false
}

// withJwtBinding adds the binding and expiry of the request's default-provider
// JWT to ctx. validateAuth has already accepted the token; the claims are read
// again through parseVerified with the same parameters as validate, so the
// expiry never comes from an unverified parse. On any failure ctx is returned
// unchanged: a handler that needs the binding answers 401, and every other
// route behaves as before.
func withJwtBinding(ctx context.Context, r *http.Request) context.Context {
	token, err := getToken(r)
	if err != nil {
		return ctx
	}
	binding, err := jwtBinding(token)
	if err != nil {
		return ctx
	}
	jwkURL := fmt.Sprintf("%s/.well-known/jwks.json", authServerURL)
	claims, err := parseVerified(token, jwkURL, expectedIssuer, expectedAudience, []string{"EdDSA"})
	if err != nil {
		return ctx
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return ctx
	}
	ctx = context.WithValue(ctx, fieldJwtBinding, binding)
	return context.WithValue(ctx, fieldJwtExpiry, exp.Time)
}

// jwtBindingContext returns what withJwtBinding placed in the request context.
// ok is false when it is absent.
func jwtBindingContext(r *http.Request) (binding string, expiresAt time.Time, ok bool) {
	binding, bok := r.Context().Value(fieldJwtBinding).(string)
	expiresAt, eok := r.Context().Value(fieldJwtExpiry).(time.Time)
	if !bok || !eok || binding == "" {
		return "", time.Time{}, false
	}
	return binding, expiresAt, true
}

type commitSessionRequest struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"publicKey"` // base64url, unpadded
}

type commitSessionResponse struct {
	SessionID string `json:"sessionId"`
	ExpiresAt int64  `json:"expiresAt"` // unix seconds, the JWT's exp
}

// handleCommitSession serves POST /v2/sessions/commit: it stores the caller's
// ephemeral public key under the binding of the JWT that authenticated the
// request. The first commit for a JWT gets 201; any later one gets 409.
func handleCommitSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userId, authProvider, ok := authContext(r)
	if !ok {
		unauthorized(w)
		return
	}
	binding, expiresAt, ok := jwtBindingContext(r)
	if !ok {
		unauthorized(w)
		return
	}

	var req commitSessionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// The re-encoding must match the input, so padding, non-zero trailing bits
	// and embedded newlines are all refused.
	publicKey, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil || base64.RawURLEncoding.EncodeToString(publicKey) != req.PublicKey {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}
	if err := checkPublicKey(req.Alg, publicKey); err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}

	session := CommitSession{
		ID:           uuid.NewString(),
		JwtBinding:   binding,
		Username:     userId,
		AuthProvider: authProvider,
		Alg:          req.Alg,
		PublicKey:    publicKey,
		ExpiresAt:    expiresAt,
	}
	// The unique index on jwt_binding decides between concurrent commits for
	// one JWT: the losing insert does nothing and affects no rows. There is no
	// read before the write for a race to slip between.
	res := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&session)
	if res.Error != nil {
		http.Error(w, "failed to commit session", http.StatusInternalServerError)
		return
	}
	if res.RowsAffected == 0 {
		http.Error(w, "a session is already committed for this token", http.StatusConflict)
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(commitSessionResponse{SessionID: session.ID, ExpiresAt: expiresAt.Unix()})
}
