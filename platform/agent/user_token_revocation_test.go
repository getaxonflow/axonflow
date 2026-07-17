// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Build-tag-agnostic unit tests for the decide-plane revocation seam (#2930
// R3). These exercise checkUserTokenRevoked's branching with a fake checker
// (the identity.RevocationChecker interface is untagged) so the logic is
// covered in the plain agent test run, independent of the enterprise realpg
// path in user_token_revocation_realpg_test.go.
package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type fakeRevocations struct {
	revoked bool
	err     error
	// captured
	gotOrg, gotJTI, gotEmail string
	gotIssuedAt              time.Time
	calls                    int
}

func (f *fakeRevocations) IsRevoked(_ context.Context, org, jti, email string, iat time.Time) (bool, error) {
	f.calls++
	f.gotOrg, f.gotJTI, f.gotEmail, f.gotIssuedAt = org, jti, email, iat
	return f.revoked, f.err
}

func withChecker(t *testing.T, c *fakeRevocations) {
	t.Helper()
	prev := userTokenRevocations
	if c == nil {
		userTokenRevocations = nil
	} else {
		userTokenRevocations = c
	}
	t.Cleanup(func() { userTokenRevocations = prev })
}

func TestCheckUserTokenRevoked_NilChecker(t *testing.T) {
	withChecker(t, nil)
	claims := jwt.MapClaims{"jti": "x", "email": "e@x.co"}
	if err := checkUserTokenRevoked(claims, "org"); err != nil {
		t.Fatalf("nil checker must be a no-op, got %v", err)
	}
}

func TestCheckUserTokenRevoked_NoJTI(t *testing.T) {
	f := &fakeRevocations{}
	withChecker(t, f)
	// A jti-less (legacy) token must not even consult the store.
	claims := jwt.MapClaims{"email": "legacy@x.co"}
	if err := checkUserTokenRevoked(claims, "org"); err != nil {
		t.Fatalf("jti-less token must be a no-op, got %v", err)
	}
	if f.calls != 0 {
		t.Fatalf("store must not be consulted for a jti-less token (calls=%d)", f.calls)
	}
}

func TestCheckUserTokenRevoked_LivePassesAndForwardsClaims(t *testing.T) {
	f := &fakeRevocations{revoked: false}
	withChecker(t, f)
	iat := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	claims := jwt.MapClaims{
		"jti":   "jti-1",
		"email": "dev@example.com",
		// float64 unix seconds — the shape a parsed JWT's iat claim carries
		// (a raw *NumericDate is not what MapClaims.GetIssuedAt reads).
		"iat": float64(iat.Unix()),
	}
	if err := checkUserTokenRevoked(claims, "org-x"); err != nil {
		t.Fatalf("a live token must pass, got %v", err)
	}
	if f.gotJTI != "jti-1" || f.gotEmail != "dev@example.com" || f.gotOrg != "org-x" {
		t.Fatalf("claims not forwarded: %+v", f)
	}
	if !f.gotIssuedAt.Equal(iat) {
		t.Fatalf("iat not forwarded: got %v want %v", f.gotIssuedAt, iat)
	}
}

func TestCheckUserTokenRevoked_Revoked(t *testing.T) {
	withChecker(t, &fakeRevocations{revoked: true})
	claims := jwt.MapClaims{"jti": "jti-dead", "email": "dev@example.com"}
	if err := checkUserTokenRevoked(claims, "org-x"); err == nil {
		t.Fatal("a revoked token must be rejected")
	}
}

func TestCheckUserTokenRevoked_StoreErrorFailsClosed(t *testing.T) {
	withChecker(t, &fakeRevocations{err: errors.New("pg down")})
	claims := jwt.MapClaims{"jti": "jti-1", "email": "dev@example.com"}
	if err := checkUserTokenRevoked(claims, "org-x"); err == nil {
		t.Fatal("a revocation-store error must fail closed (reject)")
	}
}

// TestValidateUserToken_RevocationBranch drives validateUserToken (the decide
// plane) end to end with a fake checker — no DB — covering the revocation
// branch: a revoked jti token is rejected, a live one passes.
func TestValidateUserToken_RevocationBranch(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	prevSecret := jwtSecret
	jwtSecret = []byte("decide-unit-secret")
	t.Cleanup(func() { jwtSecret = prevSecret })

	sign := func(jti string) string {
		t.Helper()
		now := time.Now().UTC()
		claims := jwt.MapClaims{
			"email":     "dev@example.com",
			"role":      "developer",
			"org_id":    "org-x",
			"tenant_id": "org-x",
			"jti":       jti,
			"iat":       jwt.NewNumericDate(now),
			"exp":       jwt.NewNumericDate(now.Add(time.Hour)),
		}
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}

	t.Run("revoked token rejected", func(t *testing.T) {
		withChecker(t, &fakeRevocations{revoked: true})
		if _, err := validateUserToken(sign("jti-dead"), "org-x"); err == nil {
			t.Fatal("validateUserToken must reject a revoked token")
		}
	})
	t.Run("live token passes", func(t *testing.T) {
		withChecker(t, &fakeRevocations{revoked: false})
		u, err := validateUserToken(sign("jti-live"), "org-x")
		if err != nil {
			t.Fatalf("live token must validate: %v", err)
		}
		if u.Email != "dev@example.com" {
			t.Fatalf("unexpected user: %+v", u)
		}
	})
	t.Run("store error fails closed", func(t *testing.T) {
		withChecker(t, &fakeRevocations{err: errors.New("pg down")})
		if _, err := validateUserToken(sign("jti-x"), "org-x"); err == nil {
			t.Fatal("validateUserToken must fail closed on a revocation-store error")
		}
	})
}

func TestWireUserTokenRevocation_NilDB(t *testing.T) {
	prev := userTokenRevocations
	t.Cleanup(func() { userTokenRevocations = prev })
	userTokenRevocations = nil
	wireUserTokenRevocation(nil)
	if userTokenRevocations != nil {
		t.Fatal("wiring with a nil db must leave the checker unset")
	}
}
