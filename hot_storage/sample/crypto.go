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

// Ciphertexts written with additional authenticated data carry this prefix.
// Without a marker there is no way to tell a bound ciphertext from an unbound one,
// and decryption would have to guess which rule to apply.
const boundSharePrefix = "v2:"

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
	return boundSharePrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptShare decrypts a stored share.
//
// Values carrying the "v2:" prefix are authenticated against deviceID. Values
// without it are decrypted unbound; migrateSharesToBound converts them.
func decryptShare(encoded, deviceID string) (string, error) {
	bound := strings.HasPrefix(encoded, boundSharePrefix)
	if bound {
		encoded = strings.TrimPrefix(encoded, boundSharePrefix)
		if deviceID == "" {
			return "", fmt.Errorf("deviceID is required to decrypt a bound share")
		}
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

	var aad []byte
	if bound {
		aad = shareAAD(deviceID)
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt share: %w", err)
	}

	return string(plaintext), nil
}

// isBoundShare reports whether a stored value is already bound to its row.
func isBoundShare(encoded string) bool {
	return strings.HasPrefix(encoded, boundSharePrefix)
}

// migrateSharesToBound re-wraps every unbound share so it is bound to its device.
//
// This is a one-way conversion: a re-wrapped share is only readable by a binary
// that understands the "v2:" prefix, so run it once the deployment is settled.
func migrateSharesToBound() error {
	var devices []Device
	if err := db.Find(&devices).Error; err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	migrated, skipped := 0, 0
	for _, device := range devices {
		if isBoundShare(device.Share) {
			skipped++
			continue
		}

		plaintext, err := decryptShare(device.Share, device.ID)
		if err != nil {
			return fmt.Errorf("device %s: failed to decrypt existing share: %w", device.ID, err)
		}
		rewrapped, err := encryptShare(plaintext, device.ID)
		if err != nil {
			return fmt.Errorf("device %s: failed to re-encrypt share: %w", device.ID, err)
		}
		if err := db.Model(&Device{}).Where("id = ?", device.ID).
			Update("share", rewrapped).Error; err != nil {
			return fmt.Errorf("device %s: failed to store re-encrypted share: %w", device.ID, err)
		}
		migrated++
	}

	fmt.Printf("share migration complete: %d re-wrapped, %d already bound\n", migrated, skipped)
	return nil
}
