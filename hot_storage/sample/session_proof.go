package main

// Prototype of commit-reveal for the P2 verification (V5). It lives on a
// verification branch only: never merged, never deployed.
//
// A client commits an ephemeral public key together with its JWT, once per
// JWT. Later share-returning requests carry a counter and a signature over
// signingInput made with that key. SESSION_PROOF_MODE selects where the proof
// is required; off (the default) leaves every existing route as it was.

import (
	"bytes"
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
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
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

	headerSessionID        = "X-Session-Id"
	headerSessionCounter   = "X-Session-Counter"
	headerSessionSignature = "X-Session-Signature"

	// maxProofBody is decodeJSON's limit too: the body is read whole for its
	// hash, then handed to the handler.
	maxProofBody = 1 << 20
	// maxSessionIDLen bounds X-Session-Id; session ids are 36-byte UUIDs.
	maxSessionIDLen    = 128
	proofSignatureSize = 64
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

var (
	errProofHeaderMissing   = errors.New("session proof header missing")
	errProofHeaderMalformed = errors.New("session proof header malformed")
)

// currentSessionProofMode is the mode apiMux applies. validateConfig refuses
// to start with an invalid SESSION_PROOF_MODE; should one reach here anyway,
// the strictest mode is used rather than none.
func currentSessionProofMode() string {
	mode, err := parseSessionProofMode(sessionProofMode)
	if err != nil {
		return sessionProofAll
	}
	return mode
}

// proofRequired reports whether mode puts the proof check on a route: all
// routes for all, the share-returning ones for share, none for off.
func proofRequired(mode string, returnsShare bool) bool {
	switch mode {
	case sessionProofAll:
		return true
	case sessionProofShare:
		return returnsShare
	}
	return false
}

// proofHeaders are the three proof headers of a request, parsed.
type proofHeaders struct {
	sessionID string
	counter   uint64
	signature []byte
}

// parseProofHeaders returns errProofHeaderMissing when any of the three
// headers is absent, checked for all three before any is parsed, and
// errProofHeaderMalformed when one is present but not in its exact form.
func parseProofHeaders(h http.Header) (proofHeaders, error) {
	id, counter, sig := h.Values(headerSessionID), h.Values(headerSessionCounter), h.Values(headerSessionSignature)
	if len(id) == 0 || len(counter) == 0 || len(sig) == 0 {
		return proofHeaders{}, errProofHeaderMissing
	}
	// With a header repeated, which value was meant is ambiguous.
	if len(id) != 1 || len(counter) != 1 || len(sig) != 1 {
		return proofHeaders{}, errProofHeaderMalformed
	}

	p := proofHeaders{sessionID: id[0]}
	if p.sessionID == "" || len(p.sessionID) > maxSessionIDLen {
		return proofHeaders{}, errProofHeaderMalformed
	}
	// A canonical decimal (no sign, leading zero or exponent) below 2^63, the
	// range of the stored counter.
	n, err := strconv.ParseUint(counter[0], 10, 64)
	if err != nil || n > math.MaxInt64 || strconv.FormatUint(n, 10) != counter[0] {
		return proofHeaders{}, errProofHeaderMalformed
	}
	p.counter = n
	// The re-encoding must match the input, as for the commit's public key.
	s, err := base64.RawURLEncoding.DecodeString(sig[0])
	if err != nil || len(s) != proofSignatureSize || base64.RawURLEncoding.EncodeToString(s) != sig[0] {
		return proofHeaders{}, errProofHeaderMalformed
	}
	p.signature = s
	return p, nil
}

// requireSessionProof puts the prototype proof check in front of next, which
// is reached only when every check passes. The checks run in this order:
//
//  1. a proof header is missing: 401
//  2. a proof header is malformed: 400
//  3. the URL has a query string, which the signature does not cover: 400
//  4. the session does not exist: 401
//  5. the request has no JWT binding, or not the session's: 401
//  6. the session has expired: 401
//  7. the signature does not verify: 401
//  8. the counter is not above the session's last accepted one: 409
//
// The body is read between 6 and 7, up to maxProofBody (beyond it, 413), and
// handed to next unchanged. The counter moves only after the signature has
// verified, so a request made without the key cannot use up a session's
// counters. Nothing here is logged.
func requireSessionProof(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof, err := parseProofHeaders(r.Header)
		if errors.Is(err, errProofHeaderMissing) {
			unauthorized(w)
			return
		}
		if err != nil {
			http.Error(w, "invalid session proof", http.StatusBadRequest)
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "query string not allowed with a session proof", http.StatusBadRequest)
			return
		}

		var session CommitSession
		if err := db.First(&session, "id = ?", proof.sessionID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				unauthorized(w)
				return
			}
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		binding, _, ok := jwtBindingContext(r)
		if !ok || binding != session.JwtBinding {
			unauthorized(w)
			return
		}
		if !nowFunc().Before(session.ExpiresAt) {
			unauthorized(w)
			return
		}

		var body []byte
		if r.Body != nil {
			body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxProofBody))
			if err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		msg := signingInput(proofFields{
			Method:     r.Method,
			Path:       r.URL.Path,
			DeviceID:   r.PathValue(fieldDeviceId),
			BodySHA256: sha256.Sum256(body),
			Counter:    proof.counter,
			SessionID:  session.ID,
		})
		if !verifyProof(session.Alg, session.PublicKey, msg, proof.signature) {
			unauthorized(w)
			return
		}

		// Conditional on the stored counter, so of two requests carrying the
		// same counter exactly one passes, however they interleave.
		res := db.Model(&CommitSession{}).
			Where("id = ? AND counter < ?", session.ID, int64(proof.counter)).
			Update("counter", int64(proof.counter))
		if res.Error != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		if res.RowsAffected != 1 {
			http.Error(w, "session counter already used", http.StatusConflict)
			return
		}
		next.ServeHTTP(w, r)
	})
}
