// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"context"
	"log"
	"os"
	"testing"
)

func TestMaskARN(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want string
	}{
		{
			name: "full ARN",
			arn:  "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-abc123",
			want: "...t-abc123", // Last 8 chars
		},
		{
			name: "short string",
			arn:  "short",
			want: "***",
		},
		{
			name: "exact 12 chars",
			arn:  "123456789012",
			want: "***",
		},
		{
			name: "13 chars",
			arn:  "1234567890123",
			want: "...67890123",
		},
		{
			name: "empty string",
			arn:  "",
			want: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskARN(tt.arn); got != tt.want {
				t.Errorf("maskARN(%q) = %q, want %q", tt.arn, got, tt.want)
			}
		})
	}
}

func TestNewLocalSecretsManager(t *testing.T) {
	// With nil logger
	sm := NewLocalSecretsManager(nil)
	if sm == nil {
		t.Fatal("expected non-nil secrets manager")
	}
	if sm.secrets == nil {
		t.Error("expected secrets map to be initialized")
	}
	if sm.logger == nil {
		t.Error("expected logger to be set")
	}

	// With custom logger
	logger := log.New(os.Stdout, "[TEST] ", 0)
	sm2 := NewLocalSecretsManager(logger)
	if sm2.logger != logger {
		t.Error("expected custom logger to be used")
	}
}

func TestLocalSecretsManager_GetSetSecret(t *testing.T) {
	sm := NewLocalSecretsManager(nil)
	ctx := context.Background()

	// Get non-existent secret
	_, err := sm.GetSecret(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for non-existent secret")
	}

	// Set and get secret
	testSecret := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}
	sm.SetSecret("my-secret-arn", testSecret)

	got, err := sm.GetSecret(ctx, "my-secret-arn")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["username"] != "testuser" {
		t.Errorf("expected username 'testuser', got %q", got["username"])
	}
	if got["password"] != "testpass" {
		t.Errorf("expected password 'testpass', got %q", got["password"])
	}
}

func TestNewEnvSecretsManager(t *testing.T) {
	// With nil logger
	sm := NewEnvSecretsManager(nil)
	if sm == nil {
		t.Fatal("expected non-nil secrets manager")
	}
	if sm.logger == nil {
		t.Error("expected logger to be set")
	}

	// With custom logger
	logger := log.New(os.Stdout, "[TEST] ", 0)
	sm2 := NewEnvSecretsManager(logger)
	if sm2.logger != logger {
		t.Error("expected custom logger to be used")
	}
}

func TestEnvSecretsManager_GetSecret(t *testing.T) {
	sm := NewEnvSecretsManager(nil)
	ctx := context.Background()

	// Set up environment variables
	os.Setenv("MYCONN_USERNAME", "envuser")
	os.Setenv("MYCONN_PASSWORD", "envpass")
	os.Setenv("MYCONN_API_KEY", "myapikey")
	os.Setenv("MYCONN_HOST", "localhost")
	os.Setenv("MYCONN_PORT", "5432")
	os.Setenv("MYCONN_DATABASE", "mydb")
	defer func() {
		os.Unsetenv("MYCONN_USERNAME")
		os.Unsetenv("MYCONN_PASSWORD")
		os.Unsetenv("MYCONN_API_KEY")
		os.Unsetenv("MYCONN_HOST")
		os.Unsetenv("MYCONN_PORT")
		os.Unsetenv("MYCONN_DATABASE")
	}()

	// Get secret
	got, err := sm.GetSecret(ctx, "MYCONN")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got["username"] != "envuser" {
		t.Errorf("expected username 'envuser', got %q", got["username"])
	}
	if got["password"] != "envpass" {
		t.Errorf("expected password 'envpass', got %q", got["password"])
	}
	if got["api_key"] != "myapikey" {
		t.Errorf("expected api_key 'myapikey', got %q", got["api_key"])
	}
	if got["host"] != "localhost" {
		t.Errorf("expected host 'localhost', got %q", got["host"])
	}
	if got["port"] != "5432" {
		t.Errorf("expected port '5432', got %q", got["port"])
	}
	if got["database"] != "mydb" {
		t.Errorf("expected database 'mydb', got %q", got["database"])
	}
}

func TestEnvSecretsManager_GetSecret_NotFound(t *testing.T) {
	sm := NewEnvSecretsManager(nil)
	ctx := context.Background()

	// No env vars set for this prefix
	_, err := sm.GetSecret(ctx, "NONEXISTENT_PREFIX")
	if err == nil {
		t.Error("expected error when no credentials found")
	}
}

func TestEnvSecretsManager_GetSecret_AllFields(t *testing.T) {
	sm := NewEnvSecretsManager(nil)
	ctx := context.Background()

	// Test all field types
	fields := map[string]string{
		"TEST_USERNAME":      "user1",
		"TEST_PASSWORD":      "pass1",
		"TEST_API_KEY":       "key1",
		"TEST_API_SECRET":    "secret1",
		"TEST_CLIENT_ID":     "client1",
		"TEST_CLIENT_SECRET": "csecret1",
		"TEST_TOKEN":         "token1",
		"TEST_PRIVATE_KEY":   "pkey1",
		"TEST_ACCESS_KEY":    "akey1",
		"TEST_SECRET_KEY":    "skey1",
	}

	for k, v := range fields {
		os.Setenv(k, v)
	}
	defer func() {
		for k := range fields {
			os.Unsetenv(k)
		}
	}()

	got, err := sm.GetSecret(ctx, "TEST")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]string{
		"username":      "user1",
		"password":      "pass1",
		"api_key":       "key1",
		"api_secret":    "secret1",
		"client_id":     "client1",
		"client_secret": "csecret1",
		"token":         "token1",
		"private_key":   "pkey1",
		"access_key":    "akey1",
		"secret_key":    "skey1",
	}

	for k, v := range expected {
		if got[k] != v {
			t.Errorf("expected %s = %q, got %q", k, v, got[k])
		}
	}
}

func TestFieldToKey(t *testing.T) {
	tests := []struct {
		field string
		want  string
	}{
		{"USERNAME", "username"},
		{"PASSWORD", "password"},
		{"API_KEY", "api_key"},
		{"API_SECRET", "api_secret"},
		{"CLIENT_ID", "client_id"},
		{"CLIENT_SECRET", "client_secret"},
		{"TOKEN", "token"},
		{"PRIVATE_KEY", "private_key"},
		{"ACCESS_KEY", "access_key"},
		{"SECRET_KEY", "secret_key"},
		{"HOST", "host"},
		{"PORT", "port"},
		{"DATABASE", "database"},
		{"UNKNOWN_FIELD", "UNKNOWN_FIELD"}, // default case
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			if got := fieldToKey(tt.field); got != tt.want {
				t.Errorf("fieldToKey(%q) = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}
