//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// hs256Validator validates AxonFlow-minted per-user HS256 tokens (Path A,
// #2924). It mirrors the agent's validateUserToken pinning (keyfunc asserts
// HMAC + WithValidMethods pins HS256, so alg:none and RS/ES-confusion tokens
// are rejected twice over) and adds the per-user-fleet requirements the
// legacy /decide-plane path does not have:
//
//   - exp is REQUIRED (no unbounded tokens),
//   - jti is REQUIRED (every token is individually revocable),
//   - email is REQUIRED (an identity-less token is useless and suspicious),
//   - the token's org_id claim MUST match the authenticated org,
//   - the revocation list is consulted on every validation, fail-closed.
type hs256Validator struct {
	secret      []byte
	revocations RevocationChecker
	leeway      time.Duration
}

// NewHS256Validator builds the Path A validator. Fails fast on an empty
// secret (HMAC over the empty key would accept forgeries signed with that
// same empty key — the same #2541 fail-closed posture as validateUserToken)
// and on a nil revocation checker (a validator that cannot consult the
// deny-list cannot honor a revoke; DoD requires revocation to take effect).
func NewHS256Validator(secret []byte, revocations RevocationChecker) (TokenValidator, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("identity: JWT secret not configured; refusing to build HS256 validator")
	}
	if revocations == nil {
		return nil, fmt.Errorf("identity: revocation checker required; refusing to build HS256 validator without one")
	}
	return &hs256Validator{secret: secret, revocations: revocations, leeway: 30 * time.Second}, nil
}

func (v *hs256Validator) Name() string { return ValidatorNameHS256 }

func (v *hs256Validator) Validate(ctx context.Context, orgID, token string) (*ValidatedIdentity, error) {
	if orgID == "" {
		return nil, fmt.Errorf("%w: no authenticated org", ErrTokenInvalid)
	}
	if token == "" {
		return nil, fmt.Errorf("%w: empty token", ErrTokenInvalid)
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// Algorithm pinning (same two-layer shape as run.go validateUserToken,
		// #2541 §5.4): assert HMAC before returning the symmetric secret.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %q (only HS256 accepted)", t.Header["alg"])
		}
		return v.secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(UserTokenIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(v.leeway),
	)
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected claims shape", ErrTokenInvalid)
	}

	email := CanonicalEmail(claimString(claims, "email"))
	if email == "" {
		return nil, fmt.Errorf("%w: missing email claim", ErrTokenInvalid)
	}
	jti := claimString(claims, "jti")
	if jti == "" {
		return nil, fmt.Errorf("%w: missing jti claim (per-user tokens must be revocable)", ErrTokenInvalid)
	}
	tokenOrg := claimString(claims, "org_id")
	if tokenOrg == "" {
		return nil, fmt.Errorf("%w: missing org_id claim", ErrTokenInvalid)
	}
	if tokenOrg != orgID {
		return nil, fmt.Errorf("%w: token org %q does not match authenticated org", ErrTokenInvalid, tokenOrg)
	}

	issuedAt := time.Time{}
	if iat, iatErr := claims.GetIssuedAt(); iatErr == nil && iat != nil {
		issuedAt = iat.Time
	}
	revoked, err := v.revocations.IsRevoked(ctx, orgID, jti, email, issuedAt)
	if err != nil {
		// Fail closed: an unreachable revocation store means we cannot prove
		// the token is still live, so it isn't.
		return nil, fmt.Errorf("%w: revocation check failed: %v", ErrTokenInvalid, err)
	}
	if revoked {
		return nil, ErrTokenRevoked
	}

	exp, _ := claims.GetExpirationTime() // presence already enforced by WithExpirationRequired
	identity := &ValidatedIdentity{
		Email: email,
		// Defense in depth: an unrecognized role claim → "" (least-privilege),
		// never honored verbatim. The mint API is the primary gate.
		Role:      NormalizeRole(claimString(claims, "role")),
		OrgID:     orgID,
		JTI:       jti,
		Source:    ValidatorNameHS256,
		Validated: true,
	}
	if exp != nil {
		identity.ExpiresAt = exp.Time
	}
	return identity, nil
}

// claimString extracts a string claim, returning "" for absent or non-string
// values (mirrors the agent's getClaimString semantics).
func claimString(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// claimBool extracts a boolean claim. present is false when the claim is
// absent; a claim present as a non-bool (e.g. the string "true") is treated
// as present-but-false so a stringly-typed IdP cannot slip an unverified
// email past the check.
func claimBool(claims jwt.MapClaims, key string) (value, present bool) {
	raw, ok := claims[key]
	if !ok {
		return false, false
	}
	b, _ := raw.(bool)
	return b, true
}
