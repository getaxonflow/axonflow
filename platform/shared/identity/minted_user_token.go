// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"fmt"
)

// A PER-USER TOKEN IS ONE RULE, WHEREVER IT IS PRESENTED (#4311).
//
// The per-user mint stamps UserTokenIssuer on every token it issues, and a
// token that carries that issuer claims to be a per-user token. Such a token
// is only a per-user token if it also carries what the mint always stamps:
// an expiry, an email (the canonical identity), a jti (so it can be revoked)
// and the organization it was minted for, which must be the authenticated
// credential's organization.
//
// Two places validate a signed per-user token: the fleet HS256 validator
// (hs256_validator.go, the MCP-server and proxied-REST planes) and the agent's
// own user-token admission (the request, decide and gateway planes). They used
// to disagree: the agent checked the signature only, so a correctly signed
// token without an email was admitted and decided there while the fleet
// validator refused it. Both now call CheckMintedUserTokenClaims, so the rule
// and its refusal texts cannot drift apart.
//
// A token WITHOUT the per-user issuer is not held to this rule. The tenant
// token kind (scripts/generate-jwt.sh's default) carries no issuer and no
// email by design, and is handled as it always was.

// IsMintedUserToken reports whether a verified claim set carries the per-user
// mint's issuer, which is what makes it a per-user token.
func IsMintedUserToken(claims map[string]any) bool {
	return claimStringFromMap(claims, "iss") == UserTokenIssuer
}

// CheckMintedUserTokenClaims applies the per-user token's claim rule to a claim
// set whose signature has already been verified. authenticatedOrgID is the
// organization of the authenticated CREDENTIAL, never a client-asserted header,
// and it is compared exactly, as the fleet validator always compared it.
//
// It returns the canonical email and the jti on success. Every refusal wraps
// ErrTokenInvalid and names the claim that failed.
func CheckMintedUserTokenClaims(claims map[string]any, authenticatedOrgID string) (email, jti string, err error) {
	if authenticatedOrgID == "" {
		return "", "", fmt.Errorf("%w: no authenticated org", ErrTokenInvalid)
	}
	// timeClaim reads a numeric exp; an absent, non-numeric or unparseable exp
	// is the zero time. An exp less than one second after the epoch is no
	// expiry either: the jwt library reads a float64 exp of 0 as absent, so a
	// parse that does not require exp (the agent's) would otherwise admit that
	// token forever.
	if exp := timeClaim(claims, "exp"); exp.IsZero() || exp.Unix() <= 0 {
		return "", "", fmt.Errorf("%w: missing exp claim (per-user tokens must expire)", ErrTokenInvalid)
	}
	email = CanonicalEmail(claimStringFromMap(claims, "email"))
	if email == "" {
		return "", "", fmt.Errorf("%w: missing email claim", ErrTokenInvalid)
	}
	jti = claimStringFromMap(claims, "jti")
	if jti == "" {
		return "", "", fmt.Errorf("%w: missing jti claim (per-user tokens must be revocable)", ErrTokenInvalid)
	}
	tokenOrg := claimStringFromMap(claims, "org_id")
	if tokenOrg == "" {
		return "", "", fmt.Errorf("%w: missing org_id claim", ErrTokenInvalid)
	}
	if tokenOrg != authenticatedOrgID {
		return "", "", fmt.Errorf("%w: token org %q does not match authenticated org", ErrTokenInvalid, tokenOrg)
	}
	return email, jti, nil
}
