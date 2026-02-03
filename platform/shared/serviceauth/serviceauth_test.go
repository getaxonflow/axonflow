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

package serviceauth

import (
	"os"
	"regexp"
	"testing"
	"time"
)

// mockClock is a controllable clock for testing.
type mockClock struct {
	now time.Time
}

func (m *mockClock) Now() time.Time { return m.now }

func newMockClock(t time.Time) *mockClock {
	return &mockClock{now: t}
}

const testSecret = "test-hmac-secret-for-unit-tests-at-least-32-chars"

func TestGenerateToken_Format(t *testing.T) {
	clock := newMockClock(time.Unix(1700000000, 0))
	gen := NewTokenGenerator(testSecret, clock)
	token := gen.GenerateToken()

	pattern := `^AXON-INTERNAL-\d+-[0-9a-f]{16}$`
	matched, err := regexp.MatchString(pattern, token)
	if err != nil {
		t.Fatalf("regex error: %v", err)
	}
	if !matched {
		t.Errorf("token %q does not match expected pattern %s", token, pattern)
	}
}

func TestGenerateToken_SignatureVerifies(t *testing.T) {
	clock := newMockClock(time.Unix(1700000000, 0))
	gen := NewTokenGenerator(testSecret, clock)
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	token := gen.GenerateToken()
	valid, isLegacy, err := val.ValidateToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isLegacy {
		t.Error("expected HMAC token, got legacy")
	}
	if !valid {
		t.Error("expected valid token")
	}
}

func TestValidateToken_ValidToken(t *testing.T) {
	now := time.Now()
	clock := newMockClock(now)
	gen := NewTokenGenerator(testSecret, clock)
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	token := gen.GenerateToken()
	valid, isLegacy, err := val.ValidateToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isLegacy {
		t.Error("should not be legacy")
	}
	if !valid {
		t.Error("should be valid")
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	genClock := newMockClock(time.Unix(1700000000, 0))
	gen := NewTokenGenerator(testSecret, genClock)
	token := gen.GenerateToken()

	// Validate 6 minutes later (beyond 5-min skew)
	valClock := newMockClock(time.Unix(1700000000+360, 0))
	val := NewTokenValidator(testSecret, valClock, DefaultClockSkew)

	valid, isLegacy, err := val.ValidateToken(token)
	if valid {
		t.Error("expired token should not be valid")
	}
	if isLegacy {
		t.Error("should not be legacy")
	}
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestValidateToken_FutureTimestamp(t *testing.T) {
	// Generate token 6 minutes in the future
	genClock := newMockClock(time.Unix(1700000360, 0))
	gen := NewTokenGenerator(testSecret, genClock)
	token := gen.GenerateToken()

	valClock := newMockClock(time.Unix(1700000000, 0))
	val := NewTokenValidator(testSecret, valClock, DefaultClockSkew)

	valid, isLegacy, err := val.ValidateToken(token)
	if valid {
		t.Error("future token should not be valid")
	}
	if isLegacy {
		t.Error("should not be legacy")
	}
	if err == nil {
		t.Error("expected error for future token")
	}
}

func TestValidateToken_TamperedSignature(t *testing.T) {
	clock := newMockClock(time.Unix(1700000000, 0))
	gen := NewTokenGenerator(testSecret, clock)
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	token := gen.GenerateToken()
	// Tamper with last char of signature
	tampered := token[:len(token)-1] + "0"
	if tampered == token {
		tampered = token[:len(token)-1] + "1"
	}

	valid, _, err := val.ValidateToken(tampered)
	if valid {
		t.Error("tampered signature should not be valid")
	}
	if err == nil {
		t.Error("expected error for tampered signature")
	}
}

func TestValidateToken_TamperedTimestamp(t *testing.T) {
	clock := newMockClock(time.Unix(1700000000, 0))
	gen := NewTokenGenerator(testSecret, clock)
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	token := gen.GenerateToken()
	// Change the timestamp by 1 second (signature won't match)
	tampered := "AXON-INTERNAL-1700000001" + token[len("AXON-INTERNAL-1700000000"):]

	valid, _, err := val.ValidateToken(tampered)
	if valid {
		t.Error("tampered timestamp should not be valid")
	}
	if err == nil {
		t.Error("expected error for tampered timestamp")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	clock := newMockClock(time.Unix(1700000000, 0))
	gen := NewTokenGenerator(testSecret, clock)
	val := NewTokenValidator("completely-different-secret-that-is-long-enough", clock, DefaultClockSkew)

	token := gen.GenerateToken()
	valid, _, err := val.ValidateToken(token)
	if valid {
		t.Error("wrong secret should not be valid")
	}
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestValidateToken_LegacyTokenFormat(t *testing.T) {
	clock := newMockClock(time.Now())
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	// A plain secret (non-HMAC format) should return isLegacy=true
	valid, isLegacy, err := val.ValidateToken("some-plain-secret-value")
	if valid {
		t.Error("legacy token should not be 'valid' via HMAC")
	}
	if !isLegacy {
		t.Error("should be detected as legacy format")
	}
	if err != nil {
		t.Errorf("legacy token should not produce error, got: %v", err)
	}
}

func TestValidateToken_EdgeTimestamp(t *testing.T) {
	genClock := newMockClock(time.Unix(1700000000, 0))
	gen := NewTokenGenerator(testSecret, genClock)
	token := gen.GenerateToken()

	// Exactly at 5-minute boundary (300 seconds)
	valClock := newMockClock(time.Unix(1700000000+300, 0))
	val := NewTokenValidator(testSecret, valClock, DefaultClockSkew)

	valid, _, _ := val.ValidateToken(token)
	if !valid {
		t.Error("token at exactly the skew boundary should be valid")
	}

	// One second past the boundary (301 seconds)
	valClock2 := newMockClock(time.Unix(1700000000+301, 0))
	val2 := NewTokenValidator(testSecret, valClock2, DefaultClockSkew)

	valid2, _, _ := val2.ValidateToken(token)
	if valid2 {
		t.Error("token 1s past the skew boundary should be rejected")
	}
}

func TestIsValidRequest_HMACToken(t *testing.T) {
	ResetWarnings()
	clock := newMockClock(time.Now())
	gen := NewTokenGenerator(testSecret, clock)
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	token := gen.GenerateToken()
	if !IsValidInternalServiceRequest(ClientID, token, val) {
		t.Error("valid HMAC token should be accepted")
	}
}

func TestIsValidRequest_LegacyFallback(t *testing.T) {
	ResetWarnings()
	clock := newMockClock(time.Now())
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	// Pass the raw secret as token (legacy behavior)
	if !IsValidInternalServiceRequest(ClientID, testSecret, val) {
		t.Error("legacy plain-secret token should be accepted for backward compatibility")
	}
}

func TestIsValidRequest_CommunityMode(t *testing.T) {
	ResetWarnings()
	// No validator = community/dev mode
	if !IsValidInternalServiceRequest(ClientID, TokenFallback, nil) {
		t.Error("fallback token should be accepted in community mode (nil validator)")
	}

	// Wrong token in community mode
	if IsValidInternalServiceRequest(ClientID, "wrong-token", nil) {
		t.Error("wrong token should be rejected even in community mode")
	}
}

func TestIsValidRequest_WrongClientID(t *testing.T) {
	ResetWarnings()
	clock := newMockClock(time.Now())
	gen := NewTokenGenerator(testSecret, clock)
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	token := gen.GenerateToken()
	if IsValidInternalServiceRequest("wrong-client", token, val) {
		t.Error("wrong client ID should always be rejected")
	}

	// Also test with nil validator
	if IsValidInternalServiceRequest("wrong-client", TokenFallback, nil) {
		t.Error("wrong client ID should be rejected in community mode too")
	}
}

func TestGetToken_WithSecret(t *testing.T) {
	clock := newMockClock(time.Unix(1700000000, 0))
	gen := NewTokenGenerator(testSecret, clock)

	token := GetInternalServiceToken(gen)
	if token == TokenFallback {
		t.Error("should return HMAC token when generator is available")
	}
	pattern := `^AXON-INTERNAL-\d+-[0-9a-f]{16}$`
	matched, _ := regexp.MatchString(pattern, token)
	if !matched {
		t.Errorf("token %q does not match HMAC format", token)
	}
}

func TestGetToken_WithoutSecret(t *testing.T) {
	token := GetInternalServiceToken(nil)
	if token != TokenFallback {
		t.Errorf("expected fallback token %q, got %q", TokenFallback, token)
	}
}

func TestLogAuthWarning_NoSecret(t *testing.T) {
	ResetWarnings()
	os.Unsetenv(SecretEnvVar)
	// Should not panic
	LogAuthWarning()
	// Second call should be a no-op
	LogAuthWarning()
}

func TestLogAuthWarning_ShortSecret(t *testing.T) {
	ResetWarnings()
	t.Setenv(SecretEnvVar, "short")
	LogAuthWarning()
}

func TestLogAuthWarning_AdequateSecret(t *testing.T) {
	ResetWarnings()
	t.Setenv(SecretEnvVar, "this-is-a-sufficiently-long-secret-for-production")
	LogAuthWarning()
}

func TestConstants(t *testing.T) {
	if ClientID != "orchestrator-internal" {
		t.Errorf("ClientID = %q, expected 'orchestrator-internal'", ClientID)
	}
	if TokenFallback != "orchestrator-internal-token" {
		t.Errorf("TokenFallback = %q, expected 'orchestrator-internal-token'", TokenFallback)
	}
	if TenantID != "*" {
		t.Errorf("TenantID = %q, expected '*'", TenantID)
	}
	if SecretMinLength != 32 {
		t.Errorf("SecretMinLength = %d, expected 32", SecretMinLength)
	}
	if SignatureLength != 16 {
		t.Errorf("SignatureLength = %d, expected 16", SignatureLength)
	}
}

func TestIsValidRequest_ExpiredHMACToken(t *testing.T) {
	ResetWarnings()
	genClock := newMockClock(time.Unix(1700000000, 0))
	gen := NewTokenGenerator(testSecret, genClock)
	token := gen.GenerateToken()

	// 6 minutes later
	valClock := newMockClock(time.Unix(1700000360, 0))
	val := NewTokenValidator(testSecret, valClock, DefaultClockSkew)

	if IsValidInternalServiceRequest(ClientID, token, val) {
		t.Error("expired HMAC token should be rejected")
	}
}

func TestIsValidRequest_WrongLegacySecret(t *testing.T) {
	ResetWarnings()
	clock := newMockClock(time.Now())
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	// Wrong plain secret
	if IsValidInternalServiceRequest(ClientID, "wrong-secret", val) {
		t.Error("wrong legacy secret should be rejected")
	}
}
