package main

import "testing"

func withConfig(t *testing.T, serverURL, iss, aud string, allowInsecure bool) {
	t.Helper()
	origURL, origIss, origAud, origInsecure := authServerURL, expectedIssuer, expectedAudience, allowInsecureAuthServer
	authServerURL, expectedIssuer, expectedAudience, allowInsecureAuthServer = serverURL, iss, aud, allowInsecure
	t.Cleanup(func() {
		authServerURL, expectedIssuer, expectedAudience, allowInsecureAuthServer = origURL, origIss, origAud, origInsecure
	})
}

func TestValidateConfig(t *testing.T) {
	const iss = "https://auth.example"

	tests := []struct {
		name          string
		serverURL     string
		iss, aud      string
		allowInsecure bool
		wantErr       bool
	}{
		{name: "valid https config", serverURL: "https://auth.internal:3000", iss: iss, aud: iss},
		{name: "missing server url", serverURL: "", iss: iss, aud: iss, wantErr: true},
		{name: "unparseable url", serverURL: "http://bad url with spaces", iss: iss, aud: iss, wantErr: true},
		// Plaintext JWKS fetch lets a network attacker substitute signing keys.
		{name: "http refused by default", serverURL: "http://auth.internal:3000", iss: iss, aud: iss, wantErr: true},
		{name: "http allowed with explicit override", serverURL: "http://auth.internal:3000", iss: iss, aud: iss, allowInsecure: true},
		{name: "missing issuer", serverURL: "https://auth.internal:3000", iss: "", aud: iss, wantErr: true},
		{name: "missing audience", serverURL: "https://auth.internal:3000", iss: iss, aud: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withConfig(t, tt.serverURL, tt.iss, tt.aud, tt.allowInsecure)
			err := validateConfig()
			if tt.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
