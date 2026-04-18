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
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestEd25519SignatureVerification tests core Ed25519 signature verification
func TestEd25519SignatureVerification(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	// Generate a valid license
	key, err := GenerateServiceLicenseKey(TierEnterprise, "acme", "platform", "backend-service", []string{"mcp:*:*"}, 365)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	// Validate it
	result, err := ValidateLicense(ctx, key)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected valid license, got invalid: %s", result.Error)
	}
}

// TestCrossKeyRejection verifies that a license signed with the evaluation key
// is rejected when verified against the enterprise public key, and vice versa.
func TestCrossKeyRejection(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	// Generate an evaluation license (signed with eval key)
	evalKey, err := GenerateServiceLicenseKey(TierEvaluation, "trial", "platform", "backend-service", []string{"mcp:*:*"}, 90)
	if err != nil {
		t.Fatalf("Failed to generate eval license: %v", err)
	}

	// Generate an enterprise license (signed with ent key)
	entKey, err := GenerateServiceLicenseKey(TierEnterprise, "acme", "platform", "backend-service", []string{"mcp:*:*"}, 365)
	if err != nil {
		t.Fatalf("Failed to generate ent license: %v", err)
	}

	// Both should validate normally
	evalResult, err := ValidateLicense(ctx, evalKey)
	if err != nil {
		t.Fatalf("Eval validation failed: %v", err)
	}
	if !evalResult.Valid {
		t.Error("Eval license should be valid")
	}

	entResult, err := ValidateLicense(ctx, entKey)
	if err != nil {
		t.Fatalf("Ent validation failed: %v", err)
	}
	if !entResult.Valid {
		t.Error("Ent license should be valid")
	}

	// Now tamper: swap the tier in an eval license payload to "Enterprise"
	// This should fail because the signature was made with the eval key
	// but verification will use the enterprise key
	rest := evalKey[5:]
	dotIdx := strings.LastIndex(rest, ".")
	payloadBase64 := rest[:dotIdx]
	signatureBase64 := rest[dotIdx+1:]

	payloadJSON, _ := base64.RawURLEncoding.DecodeString(payloadBase64)
	var payload ServiceLicensePayload
	json.Unmarshal(payloadJSON, &payload)

	// Change tier to Enterprise
	payload.Tier = "Enterprise"
	tamperedJSON, _ := json.Marshal(payload)
	tamperedPayload := base64.RawURLEncoding.EncodeToString(tamperedJSON)

	// Re-use the original signature (signed with eval key)
	tamperedKey := "AXON-" + tamperedPayload + "." + signatureBase64

	// Should fail: signature was made with eval key, but ENT tier verification uses enterprise key
	_, err = ValidateLicense(ctx, tamperedKey)
	if err == nil {
		t.Error("Cross-key tampered license should fail validation")
	} else if !strings.Contains(err.Error(), "invalid license signature") {
		t.Errorf("Expected 'invalid license signature' error, got: %v", err)
	}
}

// TestPayloadTampering verifies that modifying the payload invalidates the signature
func TestPayloadTampering(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	key, err := GenerateServiceLicenseKey(TierEnterprise, "acme", "platform", "backend-service", []string{"mcp:*:*"}, 365)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	// Tamper with the payload by modifying a character
	rest := key[5:]
	dotIdx := strings.LastIndex(rest, ".")
	payloadBase64 := rest[:dotIdx]
	signatureBase64 := rest[dotIdx+1:]

	// Flip a character in the payload
	tamperedPayload := []byte(payloadBase64)
	if tamperedPayload[10] == 'a' {
		tamperedPayload[10] = 'b'
	} else {
		tamperedPayload[10] = 'a'
	}

	tamperedKey := "AXON-" + string(tamperedPayload) + "." + signatureBase64

	_, err = ValidateLicense(ctx, tamperedKey)
	if err == nil {
		t.Error("Tampered payload should fail validation")
	}
}

// TestSignatureTampering verifies that modifying the signature invalidates the license
func TestSignatureTampering(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	key, err := GenerateServiceLicenseKey(TierEnterprise, "acme", "platform", "backend-service", []string{"mcp:*:*"}, 365)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	rest := key[5:]
	dotIdx := strings.LastIndex(rest, ".")
	payloadBase64 := rest[:dotIdx]
	signatureBase64 := rest[dotIdx+1:]

	// Flip a character in the signature
	tamperedSig := []byte(signatureBase64)
	if tamperedSig[5] == 'X' {
		tamperedSig[5] = 'Y'
	} else {
		tamperedSig[5] = 'X'
	}

	tamperedKey := "AXON-" + payloadBase64 + "." + string(tamperedSig)

	_, err = ValidateLicense(ctx, tamperedKey)
	if err == nil {
		t.Error("Tampered signature should fail validation")
	}
}

// TestV2FormatRejection verifies old V2 HMAC format is rejected
func TestV2FormatRejection(t *testing.T) {
	ctx := context.Background()

	_, err := ValidateLicense(ctx, "AXON-V2-eyJ0aWVyIjoiRU5UIn0-abc12345")
	if err == nil {
		t.Error("V2 format should be rejected")
	}

	if !strings.Contains(err.Error(), "no longer supported") {
		t.Errorf("Expected 'no longer supported' error, got: %v", err)
	}
}

// TestV1FormatRejection verifies old V1 format is rejected
func TestV1FormatRejection(t *testing.T) {
	ctx := context.Background()

	_, err := ValidateLicense(ctx, "AXON-ENT-testorg-20261028-abc12345")
	if err == nil {
		t.Error("V1 format should be rejected")
	}

	if !strings.Contains(err.Error(), "no longer supported") {
		t.Errorf("Expected 'no longer supported' error, got: %v", err)
	}
}

// TestValidateHMACSecretAtStartup_NoOp verifies that HMAC validation is now a no-op
func TestValidateHMACSecretAtStartup_NoOp(t *testing.T) {
	err := ValidateHMACSecretAtStartup()
	if err != nil {
		t.Errorf("ValidateHMACSecretAtStartup should be a no-op, got error: %v", err)
	}
}

// TestKeyDerivation verifies that setupTestKeypair correctly overrides
// the production public keys with test-derived keys.
func TestKeyDerivation(t *testing.T) {
	setupTestKeypair(t)

	// Derive evaluation public key from known seed
	evalSeed := sha256.Sum256([]byte("axonflow-test-evaluation-keypair-seed-v1"))
	evalPriv := ed25519.NewKeyFromSeed(evalSeed[:])
	evalPub := evalPriv.Public().(ed25519.PublicKey)

	// After setupTestKeypair, the embedded key should match the test key
	if !evalPub.Equal(evaluationPublicKey) {
		t.Error("setupTestKeypair did not override evaluationPublicKey correctly")
	}

	// Derive enterprise public key from known seed
	entSeed := sha256.Sum256([]byte("axonflow-test-enterprise-keypair-seed-v1"))
	entPriv := ed25519.NewKeyFromSeed(entSeed[:])
	entPub := entPriv.Public().(ed25519.PublicKey)

	if !entPub.Equal(enterprisePublicKey) {
		t.Error("setupTestKeypair did not override enterprisePublicKey correctly")
	}
}

// TestMissingSigningKey verifies clear error when signing keys are not set
func TestMissingSigningKey(t *testing.T) {
	// Ensure keys are NOT set
	os.Unsetenv("AXONFLOW_EVAL_SIGNING_KEY")
	os.Unsetenv("AXONFLOW_ENT_SIGNING_KEY")

	_, err := GenerateServiceLicenseKey(TierEnterprise, "test", "svc", "backend-service", []string{"mcp:*:*"}, 365)
	if err == nil {
		t.Error("Should fail when signing key is not set")
	}
	if !strings.Contains(err.Error(), "signing key not configured") {
		t.Errorf("Expected 'signing key not configured' error, got: %v", err)
	}
}
