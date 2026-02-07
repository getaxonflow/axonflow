// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
)

// CredentialEncryptor provides AES-256-GCM encryption for connector credentials.
// When no encryption key is configured (dev/community mode), credentials pass through
// as plaintext JSON for backward compatibility.
type CredentialEncryptor struct {
	key     []byte     // 32-byte AES-256 key
	gcm     cipher.AEAD // cached GCM instance (safe for concurrent use)
	enabled bool
}

// NewCredentialEncryptor creates a CredentialEncryptor from the CONNECTOR_ENCRYPTION_KEY
// environment variable. The key must be a 32-byte base64-encoded string.
// Returns a no-op encryptor if the env var is not set (dev/community mode).
// Panics if the env var is set but the key is invalid — misconfiguration must not
// silently fall back to plaintext storage.
func NewCredentialEncryptor() *CredentialEncryptor {
	key := os.Getenv("CONNECTOR_ENCRYPTION_KEY")
	if key == "" {
		return &CredentialEncryptor{enabled: false}
	}

	enc := NewCredentialEncryptorFromKey(key)
	if !enc.enabled {
		log.Fatalf("CONNECTOR_ENCRYPTION_KEY is set but invalid (expected 32 bytes base64-encoded). " +
			"Refusing to start — credentials would be stored in plaintext. " +
			"Generate a valid key with: openssl rand -base64 32")
	}
	return enc
}

// NewCredentialEncryptorFromKey creates a CredentialEncryptor from a base64-encoded key.
// Returns a disabled (no-op) encryptor if the key is empty or invalid.
func NewCredentialEncryptorFromKey(encodedKey string) *CredentialEncryptor {
	if encodedKey == "" {
		return &CredentialEncryptor{enabled: false}
	}

	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return &CredentialEncryptor{enabled: false}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return &CredentialEncryptor{enabled: false}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return &CredentialEncryptor{enabled: false}
	}

	return &CredentialEncryptor{key: key, gcm: gcm, enabled: true}
}

// IsEnabled returns true if encryption is active.
func (e *CredentialEncryptor) IsEnabled() bool {
	return e.enabled
}

// encryptedPrefix marks ciphertext so we can distinguish it from plaintext JSON.
const encryptedPrefix = "enc:"

// Encrypt serializes credentials to JSON and encrypts with AES-256-GCM.
// When encryption is disabled, returns plain JSON.
func (e *CredentialEncryptor) Encrypt(creds map[string]string) ([]byte, error) {
	if creds == nil {
		creds = make(map[string]string)
	}

	plaintext, err := json.Marshal(creds)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if !e.enabled {
		return plaintext, nil
	}

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, nil)

	// Prefix with "enc:" and base64-encode, then JSON-marshal as a string
	// so it is valid JSONB (the credentials column is typed JSONB).
	encoded := encryptedPrefix + base64.StdEncoding.EncodeToString(ciphertext)
	jsonQuoted, err := json.Marshal(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to JSON-encode encrypted data: %w", err)
	}
	return jsonQuoted, nil
}

// Decrypt decrypts AES-256-GCM encrypted credentials.
// Handles three formats for backward compatibility:
//   - JSON-quoted encrypted string: "enc:base64..." (current format, valid JSONB)
//   - Raw encrypted string: enc:base64... (legacy, before JSONB fix)
//   - Plain JSON object: {"username":"...","password":"..."} (unencrypted)
func (e *CredentialEncryptor) Decrypt(data []byte) (map[string]string, error) {
	if len(data) == 0 {
		return make(map[string]string), nil
	}

	// Try JSON-unmarshal as a string first (current encrypted format: "enc:base64...")
	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		if len(strVal) > len(encryptedPrefix) && strVal[:len(encryptedPrefix)] == encryptedPrefix {
			if !e.enabled {
				return nil, fmt.Errorf("encrypted credentials found but no encryption key configured")
			}
			return e.decryptCiphertext(strVal[len(encryptedPrefix):])
		}
	}

	// Check for raw (non-JSON-quoted) encrypted prefix (backward compat)
	str := string(data)
	if len(str) > len(encryptedPrefix) && str[:len(encryptedPrefix)] == encryptedPrefix {
		if !e.enabled {
			return nil, fmt.Errorf("encrypted credentials found but no encryption key configured")
		}
		return e.decryptCiphertext(str[len(encryptedPrefix):])
	}

	// Plain JSON object — backward compatible (unencrypted credentials)
	var creds map[string]string
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}
	return creds, nil
}

func (e *CredentialEncryptor) decryptCiphertext(encoded string) (map[string]string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	var creds map[string]string
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted credentials: %w", err)
	}

	return creds, nil
}
