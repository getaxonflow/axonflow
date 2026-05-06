//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package license

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// setupTestKeypair sets the Ed25519 test signing keys in the environment
// and overrides the embedded production public keys with matching test public keys.
// Uses deterministic test seeds (SHA-256 of known strings) for reproducibility.
func setupTestKeypair(t *testing.T) {
	t.Helper()

	// Deterministic test seeds (base64-encoded 32-byte Ed25519 seeds)
	// Evaluation: sha256("axonflow-test-evaluation-keypair-seed-v1")
	// Enterprise: sha256("axonflow-test-enterprise-keypair-seed-v1")
	evalSeedB64 := "b58iLWB8r+Fezjj0cUWFzXi471GlFtKvvYSWi1gbIC4="
	entSeedB64 := "fifqSWAaVJy1qk89VwvqXYnXmlSCF3VfGRiK4e1kF0g="

	os.Setenv("AXONFLOW_EVAL_SIGNING_KEY", evalSeedB64)
	os.Setenv("AXONFLOW_ENT_SIGNING_KEY", entSeedB64)

	// Derive test public keys from seeds and override the production public keys
	savedEvalPub := make(ed25519.PublicKey, len(evaluationPublicKey))
	savedEntPub := make(ed25519.PublicKey, len(enterprisePublicKey))
	copy(savedEvalPub, evaluationPublicKey)
	copy(savedEntPub, enterprisePublicKey)

	evalSeed, _ := base64.StdEncoding.DecodeString(evalSeedB64)
	entSeed, _ := base64.StdEncoding.DecodeString(entSeedB64)
	evalPriv := ed25519.NewKeyFromSeed(evalSeed)
	entPriv := ed25519.NewKeyFromSeed(entSeed)
	copy(evaluationPublicKey, evalPriv.Public().(ed25519.PublicKey))
	copy(enterprisePublicKey, entPriv.Public().(ed25519.PublicKey))

	t.Cleanup(func() {
		os.Unsetenv("AXONFLOW_EVAL_SIGNING_KEY")
		os.Unsetenv("AXONFLOW_ENT_SIGNING_KEY")
		copy(evaluationPublicKey, savedEvalPub)
		copy(enterprisePublicKey, savedEntPub)
	})
}

// TestGenerateLicenseKey tests the deprecated GenerateLicenseKey function
// which now redirects to Ed25519 service license format
func TestGenerateLicenseKey(t *testing.T) {
	setupTestKeypair(t)

	tests := []struct {
		name         string
		tier         Tier
		expectedTier Tier // if empty, defaults to tier
		orgID        string
		validityDays int
		wantErr      bool
	}{
		{
			name:         "Valid PRO license",
			tier:         TierProfessional,
			orgID:        "testorg",
			validityDays: 365,
			wantErr:      false,
		},
		{
			name:         "Valid ENT license",
			tier:         TierEnterprise,
			orgID:        "acme",
			validityDays: 365,
			wantErr:      false,
		},
		{
			name:         "Valid PLUS license",
			tier:         TierEnterprisePlus,
			orgID:        "bigcorp",
			validityDays: 730,
			wantErr:      false,
		},
		{
			name:         "Valid EVALUATION license",
			tier:         TierEvaluation,
			orgID:        "trial-customer",
			validityDays: 90,
			wantErr:      false,
		},
		{
			name:         "Invalid tier",
			tier:         Tier("INVALID"),
			orgID:        "testorg",
			validityDays: 365,
			wantErr:      true,
		},
		{
			name:         "Empty org ID",
			tier:         TierProfessional,
			orgID:        "",
			validityDays: 365,
			wantErr:      true,
		},
		{
			name:         "Zero validity days",
			tier:         TierProfessional,
			orgID:        "testorg",
			validityDays: 0,
			wantErr:      true,
		},
		{
			name:         "Negative validity days",
			tier:         TierProfessional,
			orgID:        "testorg",
			validityDays: -1,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateLicenseKey(tt.tier, tt.orgID, tt.validityDays)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GenerateLicenseKey() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateLicenseKey() unexpected error: %v", err)
				return
			}

			// Ed25519 format: AXON-{PAYLOAD}.{SIGNATURE}
			if !strings.HasPrefix(key, "AXON-") {
				t.Errorf("Invalid prefix, expected AXON-, got: %s", key[:10])
			}

			// Must contain "." separator between payload and signature
			rest := key[5:]
			if !strings.Contains(rest, ".") {
				t.Errorf("Invalid Ed25519 format, expected '.' separator in: %s", key)
			}

			// Validate the key works
			result, err := ValidateLicense(context.Background(), key)
			if err != nil {
				t.Errorf("Generated key failed validation: %v", err)
				return
			}
			if !result.Valid {
				t.Errorf("Generated key is not valid: %s", result.Error)
			}
			wantTier := tt.tier
			if tt.expectedTier != "" {
				wantTier = tt.expectedTier
			}
			if result.Tier != wantTier {
				t.Errorf("Expected tier %s, got %s", wantTier, result.Tier)
			}
			if result.OrgID != tt.orgID {
				t.Errorf("Expected OrgID %s, got %s", tt.orgID, result.OrgID)
			}
		})
	}
}

// TestGenerateServiceLicenseKeyEdgeCases tests service license generation edge cases
func TestGenerateServiceLicenseKeyEdgeCases(t *testing.T) {
	setupTestKeypair(t)

	tests := []struct {
		name         string
		tier         Tier
		orgID        string
		serviceName  string
		serviceType  string
		permissions  []string
		validityDays int
		wantErr      bool
	}{
		{
			name:         "Valid client-application license",
			tier:         TierEnterprise,
			orgID:        "travel-eu",
			serviceName:  "trip-planner",
			serviceType:  "client-application",
			permissions:  []string{"mcp:amadeus:*"},
			validityDays: 365,
			wantErr:      false,
		},
		{
			name:         "Valid backend-service license",
			tier:         TierEnterprisePlus,
			orgID:        "healthcare-us",
			serviceName:  "medical-ai",
			serviceType:  "backend-service",
			permissions:  []string{"mcp:*:*", "llm:*:*"},
			validityDays: 730,
			wantErr:      false,
		},
		{
			name:         "Valid integration license",
			tier:         TierProfessional,
			orgID:        "startup",
			serviceName:  "data-sync",
			serviceType:  "integration",
			permissions:  []string{"mcp:slack:send_message"},
			validityDays: 180,
			wantErr:      false,
		},
		{
			name:         "Invalid tier",
			tier:         Tier("INVALID"),
			orgID:        "test",
			serviceName:  "service",
			serviceType:  "client-application",
			permissions:  []string{"mcp:*:*"},
			validityDays: 365,
			wantErr:      true,
		},
		{
			name:         "Empty org ID",
			tier:         TierProfessional,
			orgID:        "",
			serviceName:  "service",
			serviceType:  "client-application",
			permissions:  []string{"mcp:*:*"},
			validityDays: 365,
			wantErr:      true,
		},
		{
			name:         "Empty service name",
			tier:         TierProfessional,
			orgID:        "test",
			serviceName:  "",
			serviceType:  "client-application",
			permissions:  []string{"mcp:*:*"},
			validityDays: 365,
			wantErr:      true,
		},
		{
			name:         "Invalid service type",
			tier:         TierProfessional,
			orgID:        "test",
			serviceName:  "service",
			serviceType:  "invalid-type",
			permissions:  []string{"mcp:*:*"},
			validityDays: 365,
			wantErr:      true,
		},
		{
			name:         "Empty permissions",
			tier:         TierProfessional,
			orgID:        "test",
			serviceName:  "service",
			serviceType:  "client-application",
			permissions:  []string{},
			validityDays: 365,
			wantErr:      true,
		},
		{
			name:         "Zero validity days",
			tier:         TierProfessional,
			orgID:        "test",
			serviceName:  "service",
			serviceType:  "client-application",
			permissions:  []string{"mcp:*:*"},
			validityDays: 0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateServiceLicenseKey(
				tt.tier,
				tt.orgID,
				tt.serviceName,
				tt.serviceType,
				tt.permissions,
				tt.validityDays,
			)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GenerateServiceLicenseKey() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateServiceLicenseKey() unexpected error: %v", err)
				return
			}

			// Ed25519 format: AXON-{PAYLOAD}.{SIGNATURE}
			if !strings.HasPrefix(key, "AXON-") {
				t.Errorf("Invalid prefix, expected AXON-")
			}

			rest := key[5:]
			if !strings.Contains(rest, ".") {
				t.Errorf("Invalid Ed25519 format, expected '.' separator")
			}

			// Validate the key
			result, err := ValidateLicense(context.Background(), key)
			if err != nil {
				t.Errorf("Generated key failed validation: %v", err)
				return
			}

			if !result.Valid {
				t.Errorf("Key is not valid: %s", result.Error)
			}

			if result.Tier != tt.tier {
				t.Errorf("Expected tier %s, got %s", tt.tier, result.Tier)
			}

			if result.OrgID != tt.orgID {
				t.Errorf("Expected OrgID %s, got %s", tt.orgID, result.OrgID)
			}

			if result.ServiceName != tt.serviceName {
				t.Errorf("Expected ServiceName %s, got %s", tt.serviceName, result.ServiceName)
			}

			if result.ServiceType != tt.serviceType {
				t.Errorf("Expected ServiceType %s, got %s", tt.serviceType, result.ServiceType)
			}
		})
	}
}

func TestGenerateLicenseKeyTiers(t *testing.T) {
	setupTestKeypair(t)

	tiers := []Tier{TierEvaluation, TierProfessional, TierEnterprise, TierEnterprisePlus}

	for _, tier := range tiers {
		t.Run(string(tier), func(t *testing.T) {
			key, err := GenerateLicenseKey(tier, "testorg", 90)
			if err != nil {
				t.Fatalf("Failed to generate key for tier %s: %v", tier, err)
			}

			result, err := ValidateLicense(context.Background(), key)
			if err != nil {
				t.Fatalf("Generated key failed validation: %v", err)
			}

			if !result.Valid {
				t.Errorf("Generated key is not valid: %s", result.Error)
			}

			if result.Tier != tier {
				t.Errorf("Expected tier %s, got %s", tier, result.Tier)
			}
		})
	}
}

func TestGenerateLicenseKeyEdgeCases(t *testing.T) {
	setupTestKeypair(t)

	tests := []struct {
		name         string
		orgID        string
		validityDays int
	}{
		{"Single char org", "a", 90},
		{"Long org ID", "verylongorganizationname123456789", 90},
		{"Org with numbers", "org123", 90},
		{"Org with underscore", "org_test", 90},
		{"Short validity", "testorg", 1},
		{"Long validity", "testorg", 3650}, // 10 years
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateLicenseKey(TierProfessional, tt.orgID, tt.validityDays)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			result, err := ValidateLicense(context.Background(), key)
			if err != nil {
				t.Fatalf("Validation failed: %v", err)
			}

			if !result.Valid {
				t.Errorf("Key is not valid: %s", result.Error)
			}
		})
	}
}

// TestEvaluationTier90DayLimit verifies 90-day enforcement for EVALUATION tier
func TestEvaluationTier90DayLimit(t *testing.T) {
	setupTestKeypair(t)

	// 90 days should succeed
	_, err := GenerateServiceLicenseKey(TierEvaluation, "trial", "platform", "backend-service", []string{"mcp:*:*"}, 90)
	if err != nil {
		t.Errorf("EVALUATION with 90 days should succeed: %v", err)
	}

	// 91 days should fail
	_, err = GenerateServiceLicenseKey(TierEvaluation, "trial", "platform", "backend-service", []string{"mcp:*:*"}, 91)
	if err == nil {
		t.Error("EVALUATION with 91 days should fail")
	}

	// Enterprise tiers should NOT have 90-day limit
	_, err = GenerateServiceLicenseKey(TierEnterprise, "enterprise", "platform", "backend-service", []string{"mcp:*:*"}, 365)
	if err != nil {
		t.Errorf("ENT with 365 days should succeed: %v", err)
	}
}

func BenchmarkGenerateLicenseKey(b *testing.B) {
	os.Setenv("AXONFLOW_EVAL_SIGNING_KEY", "b58iLWB8r+Fezjj0cUWFzXi471GlFtKvvYSWi1gbIC4=")
	os.Setenv("AXONFLOW_ENT_SIGNING_KEY", "fifqSWAaVJy1qk89VwvqXYnXmlSCF3VfGRiK4e1kF0g=")
	b.Cleanup(func() {
		os.Unsetenv("AXONFLOW_EVAL_SIGNING_KEY")
		os.Unsetenv("AXONFLOW_ENT_SIGNING_KEY")
	})

	for i := 0; i < b.N; i++ {
		_, err := GenerateLicenseKey(TierProfessional, "testorg", 365)
		if err != nil {
			b.Fatalf("Failed to generate key: %v", err)
		}
	}
}

func BenchmarkGenerateServiceLicenseKey(b *testing.B) {
	os.Setenv("AXONFLOW_EVAL_SIGNING_KEY", "b58iLWB8r+Fezjj0cUWFzXi471GlFtKvvYSWi1gbIC4=")
	os.Setenv("AXONFLOW_ENT_SIGNING_KEY", "fifqSWAaVJy1qk89VwvqXYnXmlSCF3VfGRiK4e1kF0g=")
	b.Cleanup(func() {
		os.Unsetenv("AXONFLOW_EVAL_SIGNING_KEY")
		os.Unsetenv("AXONFLOW_ENT_SIGNING_KEY")
	})

	for i := 0; i < b.N; i++ {
		_, err := GenerateServiceLicenseKey(
			TierEnterprise,
			"testorg",
			"service",
			"client-application",
			[]string{"mcp:*:*"},
			365,
		)
		if err != nil {
			b.Fatalf("Failed to generate key: %v", err)
		}
	}
}

func BenchmarkGenerateLicenseKeyWithValidation(b *testing.B) {
	os.Setenv("AXONFLOW_EVAL_SIGNING_KEY", "b58iLWB8r+Fezjj0cUWFzXi471GlFtKvvYSWi1gbIC4=")
	os.Setenv("AXONFLOW_ENT_SIGNING_KEY", "fifqSWAaVJy1qk89VwvqXYnXmlSCF3VfGRiK4e1kF0g=")
	b.Cleanup(func() {
		os.Unsetenv("AXONFLOW_EVAL_SIGNING_KEY")
		os.Unsetenv("AXONFLOW_ENT_SIGNING_KEY")
	})

	ctx := context.Background()

	for i := 0; i < b.N; i++ {
		key, err := GenerateLicenseKey(TierProfessional, "testorg", 365)
		if err != nil {
			b.Fatalf("Failed to generate key: %v", err)
		}

		_, err = ValidateLicense(ctx, key)
		if err != nil {
			b.Fatalf("Failed to validate key: %v", err)
		}
	}
}

// TestGetSigningKey_AcceptsAnyBase64Dialect proves the signing-key loader
// is tolerant of all four common base64 dialects an operator might paste
// into AWS Secrets Manager. Operators repeatedly paste the unpadded
// "raw" form and get bitten by `base64.StdEncoding.DecodeString`'s
// strictness with "illegal base64 data at input byte N". This test
// locks the tolerant behaviour so a future refactor doesn't regress it.
func TestGetSigningKey_AcceptsAnyBase64Dialect(t *testing.T) {
	// Generate a real Ed25519 keypair to seed all four encodings with
	// the SAME 32 bytes — they should all decode back identically.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_ = pub
	seed := priv.Seed()

	cases := []struct {
		name    string
		encoded string
	}{
		{"std-padded", base64.StdEncoding.EncodeToString(seed)},          // ends with '='
		{"std-raw", base64.RawStdEncoding.EncodeToString(seed)},          // no padding
		{"url-padded", base64.URLEncoding.EncodeToString(seed)},          // URL-safe + padding
		{"url-raw", base64.RawURLEncoding.EncodeToString(seed)},          // URL-safe no padding
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", tc.encoded)
			got, err := getSigningKey(TierPro)
			if err != nil {
				t.Fatalf("getSigningKey rejected %s-encoded seed: %v", tc.name, err)
			}
			if !bytes.Equal(got.Seed(), seed) {
				t.Fatalf("decoded seed mismatch for %s dialect", tc.name)
			}
		})
	}
}

// TestGetSigningKey_RejectsNonBase64 keeps a clear error path for
// genuinely malformed input — we relaxed dialect-strictness, not
// validity-strictness.
func TestGetSigningKey_RejectsNonBase64(t *testing.T) {
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", "this is not base64 at all !!!")
	_, err := getSigningKey(TierPro)
	if err == nil {
		t.Fatal("expected error for non-base64 input, got nil")
	}
}

// TestGetSigningKey_RejectsWrongLength catches base64-decodable input
// that yields a wrong-length seed (e.g. 24 bytes — base64-valid but not
// a 32-byte Ed25519 seed).
func TestGetSigningKey_RejectsWrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 24)) // 24 != ed25519.SeedSize (32)
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", short)
	_, err := getSigningKey(TierPro)
	if err == nil {
		t.Fatal("expected error for short seed, got nil")
	}
}
