//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "unit-test-secret-do-not-reuse"

// stubRevocations is a scriptable RevocationChecker.
type stubRevocations struct {
	revoked bool
	err     error
	// captured inputs for assertion
	orgID, jti, email string
	issuedAt          time.Time
}

func (s *stubRevocations) IsRevoked(_ context.Context, orgID, jti, email string, issuedAt time.Time) (bool, error) {
	s.orgID, s.jti, s.email, s.issuedAt = orgID, jti, email, issuedAt
	return s.revoked, s.err
}

func mustHS256Validator(t *testing.T, rev RevocationChecker) TokenValidator {
	t.Helper()
	v, err := NewHS256Validator([]byte(testSecret), rev)
	if err != nil {
		t.Fatalf("NewHS256Validator: %v", err)
	}
	return v
}

// signHS256 mints a token like the portal mint API does, with claim overrides.
func signHS256(t *testing.T, secret string, mutate func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":    UserTokenIssuer,
		"email":  "Dev@Example.com",
		"role":   "developer",
		"org_id": "org-a",
		"jti":    "jti-1",
		"iat":    jwt.NewNumericDate(now),
		"exp":    jwt.NewNumericDate(now.Add(time.Hour)),
	}
	if mutate != nil {
		mutate(claims)
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestNewHS256Validator_FailFast(t *testing.T) {
	if _, err := NewHS256Validator(nil, &stubRevocations{}); err == nil {
		t.Fatal("empty secret must be rejected (fail closed)")
	}
	if _, err := NewHS256Validator([]byte("x"), nil); err == nil {
		t.Fatal("nil revocation checker must be rejected (revocation must be enforceable)")
	}
}

func TestHS256Validator_HappyPath_CanonicalizesEmail(t *testing.T) {
	rev := &stubRevocations{}
	v := mustHS256Validator(t, rev)
	id, err := v.Validate(context.Background(), "org-a", signHS256(t, testSecret, nil))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.Email != "dev@example.com" {
		t.Errorf("email not canonicalized: %q", id.Email)
	}
	if id.Role != "developer" || id.OrgID != "org-a" || id.JTI != "jti-1" || !id.Validated || id.Source != ValidatorNameHS256 {
		t.Errorf("unexpected identity: %+v", id)
	}
	if id.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must be populated")
	}
	// The revocation check must have been consulted with the canonical email.
	if rev.email != "dev@example.com" || rev.jti != "jti-1" || rev.orgID != "org-a" {
		t.Errorf("revocation check inputs: %+v", rev)
	}
}

func TestHS256Validator_Rejections(t *testing.T) {
	v := mustHS256Validator(t, &stubRevocations{})
	ctx := context.Background()

	cases := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"garbage", "not.a.jwt"},
		{"tampered signature", signHS256(t, "some-other-secret", nil)},
		{"expired", signHS256(t, testSecret, func(c jwt.MapClaims) {
			c["exp"] = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
			c["iat"] = jwt.NewNumericDate(time.Now().Add(-3 * time.Hour))
		})},
		{"missing exp (unbounded token)", signHS256(t, testSecret, func(c jwt.MapClaims) { delete(c, "exp") })},
		{"nbf in the future", signHS256(t, testSecret, func(c jwt.MapClaims) {
			c["nbf"] = jwt.NewNumericDate(time.Now().Add(time.Hour))
		})},
		{"missing email", signHS256(t, testSecret, func(c jwt.MapClaims) { delete(c, "email") })},
		{"missing jti (unrevocable)", signHS256(t, testSecret, func(c jwt.MapClaims) { delete(c, "jti") })},
		{"missing org_id", signHS256(t, testSecret, func(c jwt.MapClaims) { delete(c, "org_id") })},
		{"org mismatch", signHS256(t, testSecret, func(c jwt.MapClaims) { c["org_id"] = "org-b" })},
		{"wrong issuer", signHS256(t, testSecret, func(c jwt.MapClaims) { c["iss"] = "some-other-minter" })},
		{"missing issuer", signHS256(t, testSecret, func(c jwt.MapClaims) { delete(c, "iss") })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := v.Validate(ctx, "org-a", tc.token)
			if err == nil || id != nil {
				t.Fatalf("expected rejection, got identity=%+v err=%v", id, err)
			}
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("expected ErrTokenInvalid, got %v", err)
			}
		})
	}

	t.Run("empty org param", func(t *testing.T) {
		if _, err := v.Validate(ctx, "", signHS256(t, testSecret, nil)); err == nil {
			t.Fatal("expected rejection without an authenticated org")
		}
	})
}

// TestHS256Validator_AlgNone pins that an unsigned alg:none token — even one
// with a perfectly-shaped claim set — is rejected.
func TestHS256Validator_AlgNone(t *testing.T) {
	v := mustHS256Validator(t, &stubRevocations{})
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"email": "attacker@example.com", "role": "admin", "org_id": "org-a",
		"jti": "jti-x", "exp": time.Now().Add(time.Hour).Unix(),
	})
	token := header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
	if _, err := v.Validate(context.Background(), "org-a", token); err == nil {
		t.Fatal("alg:none token must be rejected")
	}
}

// TestHS256Validator_RS256Confusion pins that an RS256-signed token is
// rejected even if its claims are perfect — the HS256 validator must never
// treat any input as an RSA verification key.
func TestHS256Validator_RS256Confusion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	claims := jwt.MapClaims{
		"email": "attacker@example.com", "role": "admin", "org_id": "org-a",
		"jti": "jti-x", "exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	v := mustHS256Validator(t, &stubRevocations{})
	if _, err := v.Validate(context.Background(), "org-a", token); err == nil {
		t.Fatal("RS256 token must be rejected by the HS256 validator")
	}
}

// TestHS256Validator_NormalizesUnknownRole pins the defense-in-depth backstop:
// a token whose role claim is outside the known vocabulary resolves to
// least-privilege, never honored verbatim.
func TestHS256Validator_NormalizesUnknownRole(t *testing.T) {
	v := mustHS256Validator(t, &stubRevocations{})
	cases := map[string]string{
		"developer":  "developer",
		"admin":      "admin",
		"superadmin": "", // unknown → least-privilege
		"root":       "",
		"":           "",
	}
	for claim, want := range cases {
		tok := signHS256(t, testSecret, func(c jwt.MapClaims) { c["role"] = claim })
		id, err := v.Validate(context.Background(), "org-a", tok)
		if err != nil {
			t.Fatalf("role %q: Validate: %v", claim, err)
		}
		if id.Role != want {
			t.Errorf("role claim %q → %q, want %q", claim, id.Role, want)
		}
	}
}

func TestHS256Validator_Revocation(t *testing.T) {
	t.Run("revoked token rejected", func(t *testing.T) {
		v := mustHS256Validator(t, &stubRevocations{revoked: true})
		_, err := v.Validate(context.Background(), "org-a", signHS256(t, testSecret, nil))
		if !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("expected ErrTokenRevoked, got %v", err)
		}
	})
	t.Run("revocation store error fails closed", func(t *testing.T) {
		v := mustHS256Validator(t, &stubRevocations{err: fmt.Errorf("pg down")})
		id, err := v.Validate(context.Background(), "org-a", signHS256(t, testSecret, nil))
		if err == nil || id != nil {
			t.Fatal("a revocation-store failure must reject the token, not pass it")
		}
		if !strings.Contains(err.Error(), "revocation check failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
