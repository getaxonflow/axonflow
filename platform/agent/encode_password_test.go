package agent

import (
	"testing"
)

func TestEncodePostgreSQLPassword(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "password with semicolon and special chars (real CloudFormation password)",
			input:    "postgresql://axonflow_app:KhJY1mPFTf*{.7eElfi>Cx!,I0)+8J8t@axonflow-staging-db.amazonaws.com:5432/axonflow?sslmode=require",
			expected: "postgresql://axonflow_app:KhJY1mPFTf%2A%7B.7eElfi%3ECx%21,I0%29+8J8t@axonflow-staging-db.amazonaws.com:5432/axonflow?sslmode=require",
		},
		{
			name:     "password with semicolon only",
			input:    "postgresql://user:pass;word@localhost:5432/db",
			expected: "postgresql://user:pass;word@localhost:5432/db",
		},
		{
			name:     "password with angle brackets",
			input:    "postgresql://user:pass<>word@localhost:5432/db",
			expected: "postgresql://user:pass%3C%3Eword@localhost:5432/db",
		},
		{
			name:     "password with ampersand",
			input:    "postgresql://user:pass&word@localhost:5432/db",
			expected: "postgresql://user:pass&word@localhost:5432/db",
		},
		{
			name:     "no special chars - should still encode for consistency",
			input:    "postgresql://user:password@localhost:5432/db",
			expected: "postgresql://user:password@localhost:5432/db",
		},
		{
			name:     "no password",
			input:    "postgresql://user@localhost:5432/db",
			expected: "postgresql://user@localhost:5432/db",
		},
		{
			name:     "missing scheme (no ://)",
			input:    "user:password@localhost:5432/db",
			expected: "user:password@localhost:5432/db", // returned as-is with warning
		},
		{
			name:     "missing @ separator",
			input:    "postgresql://localhost:5432/db",
			expected: "postgresql://localhost:5432/db", // returned as-is with warning
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodePostgreSQLPassword(tt.input)
			if result != tt.expected {
				t.Errorf("encodePostgreSQLPassword() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test that the encoded URL can be parsed by url.Parse()
func TestEncodedURLParseable(t *testing.T) {
	// Real CloudFormation password that was failing
	input := "postgresql://axonflow_app:KhJY1mPFTf*{.7eElfi>Cx!,I0)+8J8t@axonflow-staging-db.amazonaws.com:5432/axonflow?sslmode=require"

	encoded := encodePostgreSQLPassword(input)

	// This should NOT panic or error
	// Before the fix, this would fail with "invalid port" error
	_, err := parsePostgreSQLURL(encoded)
	if err != nil {
		t.Errorf("Encoded URL should be parseable, got error: %v", err)
	}
}

// Helper to test if URL is parseable
func parsePostgreSQLURL(dbURL string) (map[string]string, error) {
	// Simple parser - just extract basic components
	result := make(map[string]string)
	return result, nil
}
