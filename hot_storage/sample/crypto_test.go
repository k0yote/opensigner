package main

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func withTestKey(t *testing.T) {
	t.Helper()
	original := shareEncryptionKey
	key, err := hex.DecodeString(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("failed to build test key: %v", err)
	}
	shareEncryptionKey = key
	t.Cleanup(func() { shareEncryptionKey = original })
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	withTestKey(t)

	for _, plaintext := range []string{
		"a-shamir-share",
		"",
		strings.Repeat("x", 4096),
		"unicode: éèê \U0001f511",
	} {
		ciphertext, err := encryptShare(plaintext, "device-1")
		if err != nil {
			t.Fatalf("encryptShare(%q) failed: %v", plaintext, err)
		}
		if !strings.HasPrefix(ciphertext, boundSharePrefix) {
			t.Fatalf("ciphertext %q lacks the bound format prefix", ciphertext)
		}
		got, err := decryptShare(ciphertext, "device-1")
		if err != nil {
			t.Fatalf("decryptShare failed: %v", err)
		}
		if got != plaintext {
			t.Fatalf("round trip gave %q, want %q", got, plaintext)
		}
	}
}

func TestEncryptShareIsNonDeterministic(t *testing.T) {
	withTestKey(t)

	// A fresh nonce per encryption is what stops an observer from telling that
	// two devices hold the same share.
	first, err := encryptShare("same-share", "device-1")
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}
	second, err := encryptShare("same-share", "device-1")
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}
	if first == second {
		t.Fatal("encrypting the same plaintext twice produced identical ciphertext; nonce is being reused")
	}
}

func TestDecryptShareRejectsTamperedCiphertext(t *testing.T) {
	withTestKey(t)

	ciphertext, err := encryptShare("a-shamir-share", "device-1")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, boundSharePrefix))
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Flip a bit in the final byte; GCM must reject it rather than return garbage.
	raw[len(raw)-1] ^= 0x01
	if _, err := decryptShare(boundSharePrefix+base64.StdEncoding.EncodeToString(raw), "device-1"); err == nil {
		t.Fatal("expected tampered ciphertext to fail authentication")
	}
}

func TestDecryptShareRejectsMalformedInput(t *testing.T) {
	withTestKey(t)

	// Inputs carry the format prefix so each reaches the branch it targets;
	// unprefixed values are covered by TestDecryptShareRequiresThePrefix.
	for _, name := range []string{
		boundSharePrefix + "not-base64!!!",
		boundSharePrefix,
		boundSharePrefix + base64.StdEncoding.EncodeToString([]byte("short")), // shorter than the nonce
	} {
		if _, err := decryptShare(name, "device-1"); err == nil {
			t.Errorf("expected an error for malformed input %q", name)
		}
	}
}

func TestDecryptShareFailsWithWrongKey(t *testing.T) {
	withTestKey(t)
	ciphertext, err := encryptShare("a-shamir-share", "device-1")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	wrong, err := hex.DecodeString(strings.Repeat("cd", 32))
	if err != nil {
		t.Fatalf("failed to build wrong key: %v", err)
	}
	shareEncryptionKey = wrong

	if _, err := decryptShare(ciphertext, "device-1"); err == nil {
		t.Fatal("expected decryption to fail under a different key")
	}
}

func TestInitEncryptionKeyValidation(t *testing.T) {
	original := shareEncryptionKey
	t.Cleanup(func() { shareEncryptionKey = original })

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid 32 byte key", value: strings.Repeat("ab", 32), wantErr: false},
		{name: "empty", value: "", wantErr: true},
		{name: "not hex", value: strings.Repeat("zz", 32), wantErr: true},
		{name: "too short", value: strings.Repeat("ab", 16), wantErr: true},
		{name: "too long", value: strings.Repeat("ab", 48), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SHARE_ENCRYPTION_KEY", tt.value)
			err := initEncryptionKey()
			if tt.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestShareIsBoundToItsDevice(t *testing.T) {
	withTestKey(t)

	ciphertext, err := encryptShare("a-shamir-share", "device-owned-by-victim")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Moving a ciphertext to a different device row must not decrypt. This is the
	// property that stops someone with write access to the devices table from
	// re-pointing a victim's share at a device they control.
	if _, err := decryptShare(ciphertext, "device-owned-by-attacker"); err == nil {
		t.Fatal("a share decrypted under a device id it was not bound to")
	}

	got, err := decryptShare(ciphertext, "device-owned-by-victim")
	if err != nil {
		t.Fatalf("decrypt under the correct device failed: %v", err)
	}
	if got != "a-shamir-share" {
		t.Fatalf("got %q, want the original share", got)
	}
}

func TestUnboundSharesAreRejected(t *testing.T) {
	withTestKey(t)

	// A value written without binding -- no prefix, no AAD -- is not a supported
	// format. Accepting one would reinstate the weakness binding exists to close:
	// an unbound ciphertext is valid in any row, so anyone able to write to the
	// devices table could plant a share taken from a backup and have it decrypted.
	gcm, err := newGCM()
	if err != nil {
		t.Fatalf("gcm failed: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	unbound := base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("unbound-share"), nil))

	if _, err := decryptShare(unbound, "any-device-id"); err == nil {
		t.Fatal("an unbound share decrypted; the bound format must be required")
	}
}

func TestDecryptShareRequiresThePrefix(t *testing.T) {
	withTestKey(t)

	// Sealed with the correct AAD but stored without the prefix. The AEAD alone
	// would accept this, so only the format check can refuse it -- which is what
	// keeps a stored value from being anything other than what this code wrote.
	gcm, err := newGCM()
	if err != nil {
		t.Fatalf("gcm failed: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	sealed := gcm.Seal(nonce, nonce, []byte("a-shamir-share"), shareAAD("device-1"))

	if _, err := decryptShare(base64.StdEncoding.EncodeToString(sealed), "device-1"); err == nil {
		t.Fatal("a share without the format prefix was accepted")
	}
}

func TestDecryptShareRequiresDeviceID(t *testing.T) {
	withTestKey(t)

	ciphertext, err := encryptShare("a-shamir-share", "device-1")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if _, err := decryptShare(ciphertext, ""); err == nil {
		t.Fatal("expected decryption without a device id to be refused")
	}
}

func TestEncryptShareRequiresDeviceID(t *testing.T) {
	withTestKey(t)

	if _, err := encryptShare("a-shamir-share", ""); err == nil {
		t.Fatal("expected encryption without a device id to be refused")
	}
}
