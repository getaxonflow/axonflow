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
	"context"
	"os"
	"regexp"
	"strconv"
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
	if !IsValidInternalServiceRequest(ClientID, token, val, false) {
		t.Error("valid HMAC token should be accepted (allowFallback=false)")
	}
	if !IsValidInternalServiceRequest(ClientID, token, val, true) {
		t.Error("valid HMAC token should be accepted (allowFallback=true)")
	}
}

func TestIsValidRequest_LegacyFallback(t *testing.T) {
	ResetWarnings()
	clock := newMockClock(time.Now())
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	// Pass the raw secret as token (legacy behavior); allowFallback irrelevant when validator non-nil
	if !IsValidInternalServiceRequest(ClientID, testSecret, val, false) {
		t.Error("legacy plain-secret token should be accepted for backward compatibility")
	}
}

func TestIsValidRequest_CommunityMode(t *testing.T) {
	ResetWarnings()
	// No validator + allowFallback=true = community/dev mode
	if !IsValidInternalServiceRequest(ClientID, TokenFallback, nil, true) {
		t.Error("fallback token should be accepted in community mode (nil validator, allowFallback=true)")
	}

	// Wrong token in community mode
	if IsValidInternalServiceRequest(ClientID, "wrong-token", nil, true) {
		t.Error("wrong token should be rejected even in community mode")
	}
}

func TestIsValidRequest_FallbackRejectedWhenNotAllowed(t *testing.T) {
	ResetWarnings()
	// No validator + allowFallback=false = enterprise misconfig — must reject
	// even when the caller supplies the literal TokenFallback.
	if IsValidInternalServiceRequest(ClientID, TokenFallback, nil, false) {
		t.Error("fallback token MUST be rejected when allowFallback=false (enterprise mode without configured secret)")
	}

	// Anything else also rejected
	if IsValidInternalServiceRequest(ClientID, "anything", nil, false) {
		t.Error("arbitrary token MUST be rejected when validator is nil and allowFallback=false")
	}
}

func TestIsValidRequest_WrongClientID(t *testing.T) {
	ResetWarnings()
	clock := newMockClock(time.Now())
	gen := NewTokenGenerator(testSecret, clock)
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	token := gen.GenerateToken()
	if IsValidInternalServiceRequest("wrong-client", token, val, false) {
		t.Error("wrong client ID should always be rejected")
	}

	// Also test with nil validator (both fallback values)
	if IsValidInternalServiceRequest("wrong-client", TokenFallback, nil, true) {
		t.Error("wrong client ID should be rejected in community mode too")
	}
	if IsValidInternalServiceRequest("wrong-client", TokenFallback, nil, false) {
		t.Error("wrong client ID should be rejected in strict mode too")
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

	if IsValidInternalServiceRequest(ClientID, token, val, false) {
		t.Error("expired HMAC token should be rejected")
	}
}

func TestIsValidRequest_WrongLegacySecret(t *testing.T) {
	ResetWarnings()
	clock := newMockClock(time.Now())
	val := NewTokenValidator(testSecret, clock, DefaultClockSkew)

	// Wrong plain secret
	if IsValidInternalServiceRequest(ClientID, "wrong-secret", val, false) {
		t.Error("wrong legacy secret should be rejected")
	}
}

// ---------------------------------------------------------------------------
// Subject-bound tokens (#3629)
// ---------------------------------------------------------------------------

// TestASubjectBoundSignatureCoversTheSubject. If the subject were outside the
// covered material, every subject would share one signature and the binding
// would be decoration.
func TestASubjectBoundSignatureCoversTheSubject(t *testing.T) {
	const secret = "an-internal-service-secret-of-at-least-32-chars"
	g := NewTokenGenerator(secret, RealClock{})
	v := NewTokenValidator(secret, RealClock{}, DefaultClockSkew)

	token, err := g.GenerateTokenForSubject("wcp-01")
	if err != nil {
		t.Fatalf("GenerateTokenForSubject: %v", err)
	}
	if ok, err := v.ValidateTokenForSubject(token, "wcp-01"); !ok {
		t.Fatalf("a token must validate for its own subject: %v", err)
	}
	if ok, _ := v.ValidateTokenForSubject(token, "wcp-02"); ok {
		t.Fatal("a token minted for one subject validated for another; the subject is not inside the covered material")
	}
}

// TestTheSubjectSignatureIsInjectiveOverAdversarialSubjects.
//
// The property is that two DIFFERENT subject strings never produce one
// signature, because two identities that share a signature authenticate as each
// other. The set below is chosen for the ways an encoding usually loses that:
// the separator the format uses, leading and trailing whitespace, a prefix
// relationship, and case.
//
// A NOTE ON THE LENGTH PREFIX, so a later reader does not overclaim it. With a
// fixed domain tag in front and a digits-only timestamp behind, a naive
// `domain|subject|ts` join is ALREADY injective - there is no pair of subjects
// this test can build that collides under it. The length prefix is therefore
// defence for the day the trailing field stops being an integer, not a fix for
// a live ambiguity, and the mutant this test does kill is the one that matters
// more here: a subject that is trimmed, lower-cased or otherwise normalised
// before it is signed, which makes two spellings one identity.
func TestTheSubjectSignatureIsInjectiveOverAdversarialSubjects(t *testing.T) {
	const secret = "an-internal-service-secret-of-at-least-32-chars"
	const ts int64 = 1788458616
	subjects := []string{
		"wcp-01", "wcp-02", "wcp", "wcp|01", "wcp-01 ", " wcp-01", "WCP-01", "wcp-01\t", "",
	}
	seen := map[string]string{}
	for _, s := range subjects {
		if s == "" {
			continue // refused outright; see TestAnEmptySubjectIsRefusedOnBothSides
		}
		sig := computeSubjectSignature(secret, s, ts)
		if prev, dup := seen[sig]; dup {
			t.Fatalf("subjects %q and %q produce one signature; they are two identities that authenticate as each other", prev, s)
		}
		seen[sig] = s
	}
}

// TestASubjectBoundSignatureIsDomainSeparatedFromThePlainOne.
//
// ClientID is a legal subject string. Without the domain tag, a plain fleet
// token would be a valid subject-bound token for the subject
// "orchestrator-internal" - so every holder of the fleet secret would
// authenticate as that identity without ever having asked to.
func TestASubjectBoundSignatureIsDomainSeparatedFromThePlainOne(t *testing.T) {
	const secret = "an-internal-service-secret-of-at-least-32-chars"
	const ts int64 = 1788458616
	if computeSubjectSignature(secret, ClientID, ts) == computeSignature(secret, ClientID, ts) {
		t.Fatal("a plain token and a subject-bound token for the same string share a signature; the two schemes are not separated")
	}
}

// TestAnEmptySubjectIsRefusedOnBothSides. An empty subject would bind a token
// to nothing while looking bound, and a validator that accepted one would let
// "no identity" satisfy an identity check.
func TestAnEmptySubjectIsRefusedOnBothSides(t *testing.T) {
	const secret = "an-internal-service-secret-of-at-least-32-chars"
	g := NewTokenGenerator(secret, RealClock{})
	v := NewTokenValidator(secret, RealClock{}, DefaultClockSkew)
	// A CURRENT token, so only the empty-subject guard can be what refuses it.
	// The first draft used a hand-written token with timestamp 1, which the
	// skew bound rejected on its own - so the assertion passed with the guard
	// deleted, which is an assertion landing on a cheaper signal rather than on
	// the behaviour under test.
	fresh, err := g.GenerateTokenForSubject("wcp-01")
	if err != nil {
		t.Fatalf("GenerateTokenForSubject: %v", err)
	}
	for _, s := range []string{"", "   "} {
		if _, err := g.GenerateTokenForSubject(s); err == nil {
			t.Fatalf("GenerateTokenForSubject(%q) must be refused", s)
		}
		if ok, _ := v.ValidateTokenForSubject(fresh, s); ok {
			t.Fatalf("ValidateTokenForSubject(%q) must be refused", s)
		}
		// The case the signature comparison CANNOT refuse: a token whose
		// signature genuinely covers the empty subject. The generator will not
		// mint one, but anyone holding the secret can compute it, so the
		// validator's own guard is what has to refuse it - and without this
		// case, deleting that guard changes no test result, because every other
		// empty-subject token fails the signature check for an unrelated
		// reason.
		ts := time.Now().Unix()
		forged := TokenPrefix + strconv.FormatInt(ts, 10) + "-" + computeSubjectSignature(secret, s, ts)
		if ok, _ := v.ValidateTokenForSubject(forged, s); ok {
			t.Fatalf("a token correctly signed for the empty subject %q was accepted; an identity of nothing must never authenticate", s)
		}
	}
}

// TestASubjectBoundTokenStillExpires. The subject binding is added to the skew
// bound rather than in place of it: a replayed token from last week must not
// become acceptable because it now names a subject.
func TestASubjectBoundTokenStillExpires(t *testing.T) {
	const secret = "an-internal-service-secret-of-at-least-32-chars"
	past := &mockClock{now: time.Now().Add(-time.Hour)}
	g := NewTokenGenerator(secret, past)
	token, err := g.GenerateTokenForSubject("wcp-01")
	if err != nil {
		t.Fatalf("GenerateTokenForSubject: %v", err)
	}
	v := NewTokenValidator(secret, RealClock{}, DefaultClockSkew)
	if ok, _ := v.ValidateTokenForSubject(token, "wcp-01"); ok {
		t.Fatal("an hour-old subject-bound token was accepted inside a five-minute skew bound")
	}
}

// TestSubjectFromContextDistinguishesAbsentFromEmpty. An endpoint comparing a
// claimed identity against the authenticated one must be able to tell "nobody
// authenticated" from "somebody authenticated an empty string", or a body
// claiming "" would match an unauthenticated caller.
func TestSubjectFromContextDistinguishesAbsentFromEmpty(t *testing.T) {
	if _, ok := SubjectFromContext(context.Background()); ok {
		t.Fatal("a context with no subject reported one")
	}
	if _, ok := SubjectFromContext(ContextWithAuthenticatedSubject(context.Background(), "")); ok {
		t.Fatal("an empty subject reported as authenticated; an empty identity must never satisfy an identity check")
	}
	got, ok := SubjectFromContext(ContextWithAuthenticatedSubject(context.Background(), "wcp-01"))
	if !ok || got != "wcp-01" {
		t.Fatalf("subject = %q (ok=%v), want wcp-01", got, ok)
	}
}
