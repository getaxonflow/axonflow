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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Internal service authentication constants for orchestrator-to-agent routing.
const (
	// ClientID is the client ID used for internal orchestrator calls.
	ClientID = "orchestrator-internal"

	// TokenFallback is used when AXONFLOW_INTERNAL_SERVICE_SECRET is not configured.
	// This provides backwards compatibility for Community/development environments.
	TokenFallback = "orchestrator-internal-token"

	// TenantID is the wildcard tenant ID for internal calls.
	TenantID = "*"

	// SecretEnvVar is the environment variable for the shared secret.
	SecretEnvVar = "AXONFLOW_INTERNAL_SERVICE_SECRET"

	// SecretMinLength is the recommended minimum length for the shared secret.
	SecretMinLength = 32

	// TokenPrefix is the prefix for HMAC-signed tokens.
	TokenPrefix = "AXON-INTERNAL-"

	// SignatureLength is the number of hex characters of HMAC signature to include.
	SignatureLength = 16

	// DefaultClockSkew is the maximum allowed time difference between token generation
	// and validation. Tokens outside this window are rejected for replay protection.
	DefaultClockSkew = 5 * time.Minute
)

// Clock abstracts time for testability.
type Clock interface {
	Now() time.Time
}

// RealClock uses the system clock.
type RealClock struct{}

// Now returns the current time.
func (RealClock) Now() time.Time { return time.Now() }

// TokenGenerator creates HMAC-signed internal service tokens.
type TokenGenerator struct {
	secret string
	clock  Clock
}

// NewTokenGenerator creates a new TokenGenerator.
func NewTokenGenerator(secret string, clock Clock) *TokenGenerator {
	if clock == nil {
		clock = RealClock{}
	}
	return &TokenGenerator{secret: secret, clock: clock}
}

// GenerateToken produces a token in the format: AXON-INTERNAL-{unix_timestamp}-{hmac_signature_16hex}
func (g *TokenGenerator) GenerateToken() string {
	ts := g.clock.Now().Unix()
	sig := computeSignature(g.secret, ClientID, ts)
	return fmt.Sprintf("%s%d-%s", TokenPrefix, ts, sig)
}

// TokenValidator validates HMAC-signed internal service tokens.
type TokenValidator struct {
	secret  string
	clock   Clock
	maxSkew time.Duration
}

// NewTokenValidator creates a new TokenValidator.
func NewTokenValidator(secret string, clock Clock, maxSkew time.Duration) *TokenValidator {
	if clock == nil {
		clock = RealClock{}
	}
	if maxSkew <= 0 {
		maxSkew = DefaultClockSkew
	}
	return &TokenValidator{secret: secret, clock: clock, maxSkew: maxSkew}
}

// ValidateToken checks an HMAC-signed token.
// Returns (valid, isLegacy, err):
//   - valid=true, isLegacy=false: HMAC token accepted
//   - valid=false, isLegacy=true, err=nil: not an HMAC token (legacy format)
//   - valid=false, isLegacy=false, err!=nil: HMAC token but invalid (expired, tampered, etc.)
func (v *TokenValidator) ValidateToken(token string) (valid bool, isLegacy bool, err error) {
	if !strings.HasPrefix(token, TokenPrefix) {
		return false, true, nil
	}

	// Parse: AXON-INTERNAL-{timestamp}-{signature}
	rest := token[len(TokenPrefix):]
	dashIdx := strings.Index(rest, "-")
	if dashIdx < 0 {
		return false, false, fmt.Errorf("invalid token format: missing signature separator")
	}

	tsStr := rest[:dashIdx]
	sig := rest[dashIdx+1:]

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false, false, fmt.Errorf("invalid token format: bad timestamp: %w", err)
	}

	if len(sig) != SignatureLength {
		return false, false, fmt.Errorf("invalid token format: signature length %d, expected %d", len(sig), SignatureLength)
	}

	// Check timestamp within allowed skew
	now := v.clock.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(v.maxSkew/time.Second) {
		return false, false, fmt.Errorf("token expired: timestamp %d is %ds from current time (max %ds)", ts, diff, int64(v.maxSkew/time.Second))
	}

	// Verify HMAC signature
	expected := computeSignature(v.secret, ClientID, ts)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return false, false, fmt.Errorf("token signature mismatch")
	}

	return true, false, nil
}

// IsValidInternalServiceRequest checks if the request is from a trusted internal service.
//
// Authentication paths, in order:
//  1. HMAC-signed token (preferred; requires non-nil validator)
//  2. Legacy plain-secret token (requires non-nil validator; deprecated)
//  3. Static fallback token (ONLY when validator is nil AND allowFallback is true)
//
// The fallback path exists so single-node Community/dev deployments work without
// any secret configuration. Production/Enterprise deployments MUST set
// AXONFLOW_INTERNAL_SERVICE_SECRET (so the caller passes a non-nil validator)
// AND MUST pass allowFallback=false. If allowFallback=true ever leaks into a
// deployment that lacks a configured secret, any caller knowing the literal
// constant TokenFallback could authenticate as the orchestrator and impersonate
// arbitrary tenants via X-Tenant-ID/X-Org-ID injection.
//
// Callers should gate allowFallback on `isCommunityMode() || isCommunitySaasMode()`
// — never hard-code true.
func IsValidInternalServiceRequest(clientID, userToken string, validator *TokenValidator, allowFallback bool) bool {
	if clientID != ClientID {
		return false
	}

	// No validator means no secret configured. Only the static fallback token
	// can satisfy this branch, and only when the caller explicitly allows it.
	if validator == nil {
		if !allowFallback {
			logFallbackRejection()
			return false
		}
		return userToken == TokenFallback
	}

	valid, isLegacy, err := validator.ValidateToken(userToken)
	if valid {
		return true
	}

	if isLegacy {
		// Legacy path: plain secret comparison with deprecation warning
		logLegacyDeprecationWarning()
		return subtle.ConstantTimeCompare([]byte(userToken), []byte(validator.secret)) == 1
	}

	// HMAC token but invalid (expired, tampered, wrong secret)
	log.Printf("[SECURITY WARNING] Internal service token validation failed: %v", err)
	return false
}

// GetInternalServiceToken returns an HMAC token if a generator is available,
// otherwise returns the fallback token.
func GetInternalServiceToken(generator *TokenGenerator) string {
	if generator != nil {
		return generator.GenerateToken()
	}
	return TokenFallback
}

var (
	authWarningOnce       sync.Once
	legacyDeprecationOnce sync.Once
	fallbackRejectionOnce sync.Once
)

// LogAuthWarning logs a one-time startup warning about security configuration.
func LogAuthWarning() {
	authWarningOnce.Do(func() {
		secret := os.Getenv(SecretEnvVar)
		if secret == "" {
			log.Printf("[SECURITY WARNING] %s not configured - using fallback token for internal service auth. This is acceptable for development but NOT recommended for production. Set %s to a secure random string (minimum %d characters).",
				SecretEnvVar, SecretEnvVar, SecretMinLength)
		} else if len(secret) < SecretMinLength {
			log.Printf("[SECURITY WARNING] %s is only %d characters - recommend at least %d characters for production security.",
				SecretEnvVar, len(secret), SecretMinLength)
		}
	})
}

// logLegacyDeprecationWarning logs a one-time warning when a legacy (non-HMAC) token is accepted.
func logLegacyDeprecationWarning() {
	legacyDeprecationOnce.Do(func() {
		log.Printf("[SECURITY DEPRECATION] Accepted legacy plain-secret token for internal service auth. " +
			"This is deprecated and will be removed in a future release. " +
			"Upgrade all services to use HMAC-signed tokens (ensure both orchestrator and agent run the latest version).")
	})
}

// logFallbackRejection logs a one-time warning when an internal-service auth attempt
// is rejected because no validator is configured and the caller did not allow the
// fallback path. This usually means the deployment is missing
// AXONFLOW_INTERNAL_SERVICE_SECRET in a non-Community mode.
func logFallbackRejection() {
	fallbackRejectionOnce.Do(func() {
		log.Printf("[SECURITY] Internal service auth rejected: %s is not set in this deployment. "+
			"Fallback token is disabled outside Community/Community-SaaS mode. "+
			"Configure %s on every service (agent, orchestrator, customer-portal) so HMAC-signed tokens can be issued and validated.",
			SecretEnvVar, SecretEnvVar)
	})
}

// ResetWarnings resets the warning flags. Only for use in tests.
func ResetWarnings() {
	authWarningOnce = sync.Once{}
	legacyDeprecationOnce = sync.Once{}
	fallbackRejectionOnce = sync.Once{}
}

// computeSignature computes the first SignatureLength hex chars of HMAC-SHA256(secret, "orchestrator-internal:{timestamp}").
func computeSignature(secret, clientID string, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "%s:%d", clientID, timestamp)
	fullSig := hex.EncodeToString(mac.Sum(nil))
	return fullSig[:SignatureLength]
}
