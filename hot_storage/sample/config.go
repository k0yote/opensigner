package main

import (
	"fmt"
	"net/url"
	"os"
)

// authServerURL is the address hot_storage uses to FETCH the JWKS. It is an
// internal address (e.g. http://authservice:3000) and is deliberately NOT used
// as the expected issuer: auth_service mints tokens whose iss/aud are its
// externally visible base URL (BETTER_AUTH_BASE_URL), which differs.
var authServerURL = os.Getenv("AUTH_SERVER_URL")

// Expected iss/aud for tokens from the default (first-party) auth provider.
// Must equal the origin of auth_service's BETTER_AUTH_BASE_URL.
var (
	expectedIssuer   = os.Getenv("AUTH_JWT_ISSUER")
	expectedAudience = os.Getenv("AUTH_JWT_AUDIENCE")
)

// Expected audience for Google-issued ID tokens: the OAuth client ID this
// deployment accepts. Empty means the Google provider is not configured, and
// tokens for it are rejected rather than accepted with an unchecked audience --
// otherwise any Google-signed ID token, issued to any OAuth client, would
// authenticate as whatever subject it carries.
var googleAudience = os.Getenv("GOOGLE_JWT_AUDIENCE")

// allowInsecureAuthServer permits fetching the JWKS over plaintext HTTP. It
// defaults to false so a production deployment cannot silently retrieve signing
// keys over a channel an attacker can rewrite.
var allowInsecureAuthServer = os.Getenv("ALLOW_INSECURE_AUTH_SERVER") == "true"

func validateConfig() error {
	if authServerURL == "" {
		return fmt.Errorf("AUTH_SERVER_URL environment variable is not set")
	}

	parsed, err := url.Parse(authServerURL)
	if err != nil {
		return fmt.Errorf("AUTH_SERVER_URL is not a valid URL: %w", err)
	}
	if parsed.Scheme != "https" && !allowInsecureAuthServer {
		return fmt.Errorf(
			"AUTH_SERVER_URL must use https (got %q); set ALLOW_INSECURE_AUTH_SERVER=true "+
				"to override for local development only",
			parsed.Scheme,
		)
	}

	// Fail closed: without these, validation would accept any token signed by the
	// key set regardless of who it was issued to or by.
	if expectedIssuer == "" {
		return fmt.Errorf("AUTH_JWT_ISSUER must be set (origin of auth_service's BETTER_AUTH_BASE_URL)")
	}
	if expectedAudience == "" {
		return fmt.Errorf("AUTH_JWT_AUDIENCE must be set (origin of auth_service's BETTER_AUTH_BASE_URL)")
	}
	return nil
}
