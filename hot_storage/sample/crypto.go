package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

var shareEncryptionKey []byte

// Stored ciphertexts carry this prefix. It makes a stored value self-describing,
// so anything not written by this scheme is refused outright instead of being fed
// to the AEAD as arbitrary bytes.
const sharePrefix = "v2:"

func initEncryptionKey() error {
	keyHex := os.Getenv("SHARE_ENCRYPTION_KEY")
	if keyHex == "" {
		return fmt.Errorf("SHARE_ENCRYPTION_KEY environment variable must be set (64 hex chars = 32 bytes)")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("SHARE_ENCRYPTION_KEY must be valid hex: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("SHARE_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}
	shareEncryptionKey = key
	return nil
}

func newGCM() (cipher.AEAD, error) {
	block, err := aes.NewCipher(shareEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm, nil
}

// shareAAD binds a ciphertext to the device row that owns it.
//
// Encryption alone proves a value was produced by a holder of the key; it says
// nothing about where that value belongs. Without this binding, anyone able to
// write to the devices table could copy another user's encrypted share onto a
// device they control and have the service decrypt it for them -- the ciphertext
// is equally valid in any row. Including the device id as additional
// authenticated data makes a ciphertext verifiable only in the row it was
// written for.
func shareAAD(deviceID string) []byte {
	return []byte("device:" + deviceID)
}

// encryptShare encrypts a share with AES-256-GCM, bound to deviceID.
// Returns "v2:" followed by base64(nonce || ciphertext).
func encryptShare(plaintext, deviceID string) (string, error) {
	if deviceID == "" {
		return "", fmt.Errorf("deviceID is required to bind the encrypted share")
	}

	gcm, err := newGCM()
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), shareAAD(deviceID))
	return sharePrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptShare decrypts a stored share, authenticated against deviceID.
//
// Binding is unconditional: there is no unbound format to fall back to, so a
// value that does not carry the prefix is rejected rather than decrypted.
func decryptShare(encoded, deviceID string) (string, error) {
	if !strings.HasPrefix(encoded, sharePrefix) {
		return "", fmt.Errorf("share is not in the bound format")
	}
	encoded = strings.TrimPrefix(encoded, sharePrefix)
	if deviceID == "" {
		return "", fmt.Errorf("deviceID is required to decrypt a share")
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	gcm, err := newGCM()
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, shareAAD(deviceID))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt share: %w", err)
	}

	return string(plaintext), nil
}
