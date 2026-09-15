// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"encoding/json"
	"errors"
	"testing"
)

func mintedClaimSet(org string) map[string]any {
	return map[string]any{
		"iss":    UserTokenIssuer,
		"sub":    "alice@corp.example",
		"email":  "Alice@Corp.Example ",
		"jti":    "jti-1",
		"org_id": org,
		"exp":    float64(4102444800),
	}
}

func TestIsMintedUserTokenKeysOnTheMintIssuerAlone(t *testing.T) {
	for name, c := range map[string]struct {
		claims map[string]any
		want   bool
	}{
		"the mint's issuer":                   {map[string]any{"iss": UserTokenIssuer}, true},
		"no issuer (the tenant token kind)":   {map[string]any{"tenant_id": "t"}, false},
		"another issuer":                      {map[string]any{"iss": "https://idp.example"}, false},
		"the issuer as a non-string":          {map[string]any{"iss": 1}, false},
		"a nil claim set":                     {nil, false},
		"the mint's issuer with other claims": {mintedClaimSet("org-a"), true},
	} {
		if got := IsMintedUserToken(c.claims); got != c.want {
			t.Errorf("%s: IsMintedUserToken = %v, want %v", name, got, c.want)
		}
	}
}

func TestCheckMintedUserTokenClaimsAcceptsTheMintsClaimSet(t *testing.T) {
	email, jti, err := CheckMintedUserTokenClaims(mintedClaimSet("org-a"), "org-a")
	if err != nil {
		t.Fatalf("the mint's claim set for the credential's org was refused: %v", err)
	}
	if email != "alice@corp.example" || jti != "jti-1" {
		t.Fatalf("got email %q jti %q; want the canonical email and the jti", email, jti)
	}
}

// Every refusal names the claim that failed and wraps ErrTokenInvalid. The
// email, jti and org texts are the fleet validator's own, unchanged; the exp
// text is new, because the fleet validator's parse had always enforced exp
// before any claim check ran, and the agent's parse does not.
func TestCheckMintedUserTokenClaimsNamesEachFailedClaim(t *testing.T) {
	without := func(claim string) map[string]any {
		c := mintedClaimSet("org-a")
		delete(c, claim)
		return c
	}
	with := func(claim string, v any) map[string]any {
		c := mintedClaimSet("org-a")
		c[claim] = v
		return c
	}
	for name, c := range map[string]struct {
		claims  map[string]any
		org     string
		message string
	}{
		"no authenticated org":                        {mintedClaimSet("org-a"), "", "per-user token invalid: no authenticated org"},
		"a blank authenticated org, compared exactly": {mintedClaimSet("org-a"), "  ", `per-user token invalid: token org "org-a" does not match authenticated org`},
		"missing exp":                                 {without("exp"), "org-a", "per-user token invalid: missing exp claim (per-user tokens must expire)"},
		"exp as a string":                             {with("exp", "4102444800"), "org-a", "per-user token invalid: missing exp claim (per-user tokens must expire)"},
		"exp as an unparseable number":                {with("exp", json.Number("soon")), "org-a", "per-user token invalid: missing exp claim (per-user tokens must expire)"},
		"an exp of 0 (no expiry)":                     {with("exp", float64(0)), "org-a", "per-user token invalid: missing exp claim (per-user tokens must expire)"},
		"an exp before the epoch":                     {with("exp", float64(-1)), "org-a", "per-user token invalid: missing exp claim (per-user tokens must expire)"},
		"missing email":                               {without("email"), "org-a", "per-user token invalid: missing email claim"},
		"a blank email":                               {with("email", "   "), "org-a", "per-user token invalid: missing email claim"},
		"missing jti":                                 {without("jti"), "org-a", "per-user token invalid: missing jti claim (per-user tokens must be revocable)"},
		"missing org_id":                              {without("org_id"), "org-a", "per-user token invalid: missing org_id claim"},
		"another organization's token":                {mintedClaimSet("org-b"), "org-a", `per-user token invalid: token org "org-b" does not match authenticated org`},
	} {
		_, _, err := CheckMintedUserTokenClaims(c.claims, c.org)
		if err == nil {
			t.Errorf("%s: admitted; want a refusal", name)
			continue
		}
		if !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("%s: %v does not wrap ErrTokenInvalid", name, err)
		}
		if err.Error() != c.message {
			t.Errorf("%s: message %q, want %q", name, err.Error(), c.message)
		}
	}
}

func TestCheckMintedUserTokenClaimsReadsExpInEveryDecodedShape(t *testing.T) {
	for name, exp := range map[string]any{
		"float64":     float64(4102444800),
		"int64":       int64(4102444800),
		"int":         4102444800,
		"json.Number": json.Number("4102444800"),
	} {
		c := mintedClaimSet("org-a")
		c["exp"] = exp
		if _, _, err := CheckMintedUserTokenClaims(c, "org-a"); err != nil {
			t.Errorf("exp as %s was refused: %v", name, err)
		}
	}
}
