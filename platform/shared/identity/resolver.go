// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Fleet/MCP-server plane token resolver (#2920 foundation, reconciled onto the
// #2924 validator seam). Untagged: it iterates whatever TokenValidators the
// process registered (enterprise builds register the HS256 + OIDC backends;
// community builds register none — the constructors are Enterprise-only), so
// the SAME resolve contract compiles and behaves in both editions.
package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ResolveToken resolves a validated per-user identity from a presented token
// by trying each registered TokenValidator in registration order. It is the
// single choke point the fleet/MCP-server plane calls; its contract is
// deliberately fail-closed:
//
//   - token == "": returns (nil, nil). NO token was presented — the caller
//     applies its least-privilege fallback identity (attribution-only,
//     Role ""). This is the legacy shared-tenant-credential path.
//   - no validators registered: returns (nil, nil). Per-user tokens are an
//     Enterprise capability; in a build/deployment with no validators the
//     token cannot be validated, so it is IGNORED (least-privilege) rather
//     than rejected — a community build must never reject a caller that
//     happens to carry a token, and ignoring it can never ELEVATE.
//   - a validator returns a ValidatedIdentity: returns it (first success
//     wins). HS256 (Path A) is tried before OIDC (Path B) by registration
//     order; an OIDC token that HS256 rejects (wrong alg / iss) falls through
//     to OIDC, so "HS256 rejected it" is NOT terminal.
//   - a validator returns ErrNotConfigured: that backend has no config for
//     this org (e.g. no OIDC row) — skip it and try the next.
//   - token presented, ≥1 validator registered, NONE produced an identity:
//     returns (nil, error). A presented token that no configured validator
//     accepts is a rejected access attempt — the caller MUST reject, never
//     downgrade to least-privilege.
//
// orgID is the ALREADY-AUTHENTICATED tenant (from the Basic credential), never
// a client-asserted header; it is passed to each validator so a token minted
// or configured for another org cannot validate.
func ResolveToken(ctx context.Context, orgID, token string) (*ValidatedIdentity, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil // no token presented → caller uses least-privilege
	}

	validators := RegisteredValidators()
	if len(validators) == 0 {
		return nil, nil // capability absent (community build) → least-privilege, never elevate
	}

	var lastErr, outageErr error
	for _, v := range validators {
		id, err := v.Validate(ctx, orgID, token)
		if err == nil && id != nil {
			return id, nil // first success wins
		}
		if err != nil && !errors.Is(err, ErrNotConfigured) {
			// Recognized-but-invalid (bad signature / expired / revoked / wrong
			// org). Remember it, but keep trying: a token this validator can't
			// handle (e.g. an OIDC token hitting the HS256 validator) may be
			// another registered validator's to accept.
			lastErr = err
			// AN OUTAGE OUTRANKS A LATER REJECTION. Each validator rejects the
			// other's credential class by SHAPE before it consults anything:
			// the HS256 validator's HMAC check precedes its deny-list lookup,
			// and the OIDC verifier's RSA check precedes its key fetch. So an
			// outage comes only from the validator that examined the
			// credential, and with HS256 registered first, last-wins would
			// report its revocation outage as the OIDC verifier's shape
			// rejection in every organization with OIDC configured. The first
			// outage is kept; a later one says nothing about this credential.
			if outageErr == nil && (errors.Is(err, ErrRevocationUnavailable) || errors.Is(err, ErrJWKSUnavailable)) {
				outageErr = err
			}
		}
	}
	if outageErr != nil {
		lastErr = outageErr
	}

	// A token was presented but no validator produced an identity. Fail closed.
	if lastErr == nil {
		// Every validator skipped (ErrNotConfigured) — nothing could handle a
		// presented token. Still a rejected access attempt.
		lastErr = ErrTokenInvalid
	}
	return nil, fmt.Errorf("no registered validator accepted the per-user token: %w", lastErr)
}

// ValidatedIdentityPrincipal is the credential principal for a per-user
// identity a registered validator ALREADY accepted, for a caller that holds the
// identity and not the resolution that produced it - an MCP server session,
// whose token was resolved when the session was created (#3564).
//
// The path is taken from the validator that produced the identity
// (ValidatedIdentity.Source), never assumed. An identity with no recorded source
// is attributed to the HS256 path, the only one registered unconditionally in
// an enterprise build.
func ValidatedIdentityPrincipal(orgID string, id *ValidatedIdentity) CredentialPrincipal {
	var claims map[string]any
	source := ""
	if id != nil {
		claims = id.Claims
		source = id.Source
	}
	accepted := id != nil
	if source == ValidatorNameOIDC {
		return OIDCPrincipal(orgID, claims, accepted, "")
	}
	return HS256Principal(orgID, claims, accepted, "")
}
