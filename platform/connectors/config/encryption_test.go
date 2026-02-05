// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func generateTestKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestCredentialEncryptor_RoundTrip(t *testing.T) {
	enc := NewCredentialEncryptorFromKey(generateTestKey(t))

	creds := map[string]string{
		"username": "admin",
		"password": "s3cret@pass/word",
		"api_key":  "sk-1234567890abcdef",
	}

	encrypted, err := enc.Encrypt(creds)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Encrypted output is a JSON-quoted string: "enc:base64..."
	var encStr string
	if err := json.Unmarshal(encrypted, &encStr); err != nil {
		t.Fatalf("encrypted data is not valid JSON string: %v", err)
	}
	if !strings.HasPrefix(encStr, encryptedPrefix) {
		t.Error("encrypted data missing prefix")
	}

	if strings.Contains(string(encrypted), "s3cret") {
		t.Error("encrypted data contains plaintext password")
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	for k, v := range creds {
		if decrypted[k] != v {
			t.Errorf("key %q: got %q, want %q", k, decrypted[k], v)
		}
	}
}

func TestCredentialEncryptor_Disabled(t *testing.T) {
	enc := NewCredentialEncryptorFromKey("")

	if enc.IsEnabled() {
		t.Error("encryptor should be disabled with empty key")
	}

	creds := map[string]string{"username": "admin", "password": "secret"}

	data, err := enc.Encrypt(creds)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("disabled encrypt should produce valid JSON: %v", err)
	}
	if decoded["password"] != "secret" {
		t.Error("disabled encrypt should pass through plaintext")
	}

	result, err := enc.Decrypt(data)
	if err != nil {
		t.Fatalf("Decrypt plaintext failed: %v", err)
	}
	if result["password"] != "secret" {
		t.Error("Decrypt plaintext failed")
	}
}

func TestCredentialEncryptor_BackwardCompatibility(t *testing.T) {
	enc := NewCredentialEncryptorFromKey(generateTestKey(t))

	legacyData := []byte(`{"username":"admin","password":"oldpass"}`)

	creds, err := enc.Decrypt(legacyData)
	if err != nil {
		t.Fatalf("Decrypt legacy data failed: %v", err)
	}

	if creds["username"] != "admin" || creds["password"] != "oldpass" {
		t.Error("backward compatibility failed for plaintext JSON")
	}
}

func TestCredentialEncryptor_NilCreds(t *testing.T) {
	enc := NewCredentialEncryptorFromKey(generateTestKey(t))

	data, err := enc.Encrypt(nil)
	if err != nil {
		t.Fatalf("Encrypt nil failed: %v", err)
	}

	creds, err := enc.Decrypt(data)
	if err != nil {
		t.Fatalf("Decrypt nil creds failed: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("expected empty creds, got %v", creds)
	}
}

func TestCredentialEncryptor_EmptyData(t *testing.T) {
	enc := NewCredentialEncryptorFromKey(generateTestKey(t))

	creds, err := enc.Decrypt([]byte{})
	if err != nil {
		t.Fatalf("Decrypt empty failed: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("expected empty creds, got %v", creds)
	}
}

func TestCredentialEncryptor_InvalidKey(t *testing.T) {
	enc := NewCredentialEncryptorFromKey("dG9vc2hvcnQ=")
	if enc.IsEnabled() {
		t.Error("should be disabled with short key")
	}

	enc = NewCredentialEncryptorFromKey("not-valid-base64!!!")
	if enc.IsEnabled() {
		t.Error("should be disabled with invalid base64")
	}
}

func TestCredentialEncryptor_WrongKeyDecrypt(t *testing.T) {
	enc1 := NewCredentialEncryptorFromKey(generateTestKey(t))
	enc2 := NewCredentialEncryptorFromKey(generateTestKey(t))

	encrypted, err := enc1.Encrypt(map[string]string{"password": "secret"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc2.Decrypt(encrypted)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestCredentialEncryptor_EncryptedWithoutKey(t *testing.T) {
	enc := NewCredentialEncryptorFromKey(generateTestKey(t))
	noKey := NewCredentialEncryptorFromKey("")

	encrypted, _ := enc.Encrypt(map[string]string{"key": "val"})

	_, err := noKey.Decrypt(encrypted)
	if err == nil {
		t.Error("expected error when decrypting without key")
	}
}

func TestCredentialEncryptor_CorruptedCiphertext(t *testing.T) {
	enc := NewCredentialEncryptorFromKey(generateTestKey(t))

	// JSON-quoted encrypted string with invalid base64
	_, err := enc.Decrypt([]byte(`"enc:not-valid-base64!!!"`))
	if err == nil {
		t.Error("expected error for invalid base64 ciphertext")
	}

	// JSON-quoted encrypted string with valid base64 but too short for nonce
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	quoted, _ := json.Marshal("enc:" + short)
	_, err = enc.Decrypt(quoted)
	if err == nil {
		t.Error("expected error for ciphertext shorter than nonce")
	}

	// Raw (non-JSON-quoted) encrypted prefix — backward compat path
	_, err = enc.Decrypt([]byte("enc:not-valid-base64!!!"))
	if err == nil {
		t.Error("expected error for raw encrypted with invalid base64")
	}
}

func TestCredentialEncryptor_InvalidPlaintextJSON(t *testing.T) {
	enc := NewCredentialEncryptorFromKey(generateTestKey(t))

	// Not valid JSON and not encrypted
	_, err := enc.Decrypt([]byte("not json at all"))
	if err == nil {
		t.Error("expected error for invalid plaintext JSON")
	}
}

func TestNewCredentialEncryptor_FromEnv(t *testing.T) {
	// Test with no env var set (default path)
	enc := NewCredentialEncryptor()
	// Should be disabled since CONNECTOR_ENCRYPTION_KEY is not set in test env
	if enc.IsEnabled() {
		t.Skip("CONNECTOR_ENCRYPTION_KEY is set in test environment")
	}
	// Disabled encryptor should still work for plaintext
	data, err := enc.Encrypt(map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	creds, err := enc.Decrypt(data)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if creds["k"] != "v" {
		t.Errorf("expected k=v, got %v", creds)
	}
}
