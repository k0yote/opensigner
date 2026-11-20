package main

import (
	"errors"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

var (
	jwkCache   = make(map[string]keyfunc.Keyfunc)
	jwkCacheMu sync.RWMutex
)

func getOrCreateKeyfunc(jwkURL string) (keyfunc.Keyfunc, error) {
	jwkCacheMu.RLock()
	k, ok := jwkCache[jwkURL]
	jwkCacheMu.RUnlock()
	if ok {
		return k, nil
	}

	jwkCacheMu.Lock()
	defer jwkCacheMu.Unlock()

	// Double-check after acquiring write lock
	if k, ok := jwkCache[jwkURL]; ok {
		return k, nil
	}

	k, err := keyfunc.NewDefault([]string{jwkURL})
	if err != nil {
		return nil, err
	}
	jwkCache[jwkURL] = k
	return k, nil
}

// validate verifies a token from the first-party auth service, which signs with
// EdDSA only.
func validate(token, jwkURL, expectedIss, expectedAud string) (string, error) {
	return validateWithMethods(token, jwkURL, expectedIss, expectedAud, []string{"EdDSA"})
}

// validateWithMethods verifies the token with parseVerified and returns its
// non-empty sub claim.
func validateWithMethods(token, jwkURL, expectedIss, expectedAud string, methods []string) (string, error) {
	claims, err := parseVerified(token, jwkURL, expectedIss, expectedAud, methods)
	if err != nil {
		return "", err
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", errors.New("missing sub claim")
	}
	return sub, nil
}

// nowFunc is the clock the parser checks exp against. It is a var only so
// tests can move time.
var nowFunc = time.Now

// parseVerified verifies the token's signature against the key set at jwkURL,
// enforces the registered claims, and returns the claims. Only the given
// signing methods are accepted, and base64url segments must be canonically
// encoded (no non-zero trailing bits). expectedIss and expectedAud must be
// non-empty: without them a token signed by the key set is accepted no matter
// who issued it or which client it was minted for.
func parseVerified(token, jwkURL, expectedIss, expectedAud string, methods []string) (jwt.MapClaims, error) {
	if expectedIss == "" || expectedAud == "" {
		return nil, errors.New("issuer/audience not configured for this auth provider")
	}
	// jwt.WithValidMethods(nil) skips the signing-method check entirely.
	if len(methods) == 0 {
		return nil, errors.New("signing methods not configured for this auth provider")
	}

	k, err := getOrCreateKeyfunc(jwkURL)
	if err != nil {
		return nil, err
	}

	parsed, err := jwt.Parse(token, k.Keyfunc,
		jwt.WithValidMethods(methods),
		jwt.WithStrictDecoding(),
		jwt.WithIssuer(expectedIss),
		jwt.WithAudience(expectedAud),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(nowFunc),
	)
	if err != nil {
		return nil, errors.New("invalid token")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
