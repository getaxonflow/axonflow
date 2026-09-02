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
	id, outcome, err := resolveTokenLegacy(ctx, orgID, token)

	// The identity-plane compat adapter (#3550) runs HERE, at the choke point,
	// not at any of the planes that consume this function. Every caller of
	// ResolveToken is covered by construction, including one added tomorrow.
	//
	// An absent token, and a build with no validators, are skipped: nothing
	// was presented, so there is no credential decision to compare against.
	// Recording those as agreements would inflate the shadow's agreement rate
	// with requests that carried no credential at all.
	if id != nil || err != nil {
		legacy := tokenLegacyAuth(orgID, id, outcome, err)
		// #3602: the observation-window canary tag, taken off the CONTEXT
		// because this function is a shared choke point with no request of its
		// own. Its callers stamp it with ContextWithSyntheticProbe;
		// TestEveryResolveTokenCallerStampsTheSyntheticProbe walks the agent
		// package's AST and fails when a caller does not, which is what keeps
		// "every caller of ResolveToken is covered by construction, including
		// one added tomorrow" true for this field as well as for the record.
		legacy.Synthetic = SyntheticProbeFromContext(ctx)
		if ref := CompatResolve(ctx, legacy).Refusal(); ref != nil {
			// THE REASON CODE ONLY, never the refusal itself.
			// CompatRefusal.Error renders Detail, and Detail names realm
			// configuration built from the credential and the realm: the
			// declared subject claim, the accepted algorithms and audiences,
			// the presented issuer. This error reaches an HTTP 401 body
			// (proxy.go and mcp_server_handler.go both format it), so wrapping
			// the refusal with %w hands an authenticated tenant caller enough
			// to construct a token that DOES satisfy the realm. The detail
			// belongs in the counterfactual record, which is where an operator
			// looks.
			return nil, fmt.Errorf("%s: no registered validator accepted the per-user token: refused by the identity plane (%s)",
				CompatRefusalCode, ref.Reason)
		}
	}
	return id, err
}

// tokenOutcome carries what the counterfactual needs and the caller does not:
// which validator produced the outcome, and whether any validator reported an
// OUTAGE rather than a verdict.
type tokenOutcome struct {
	// source names the validator whose error is the one being returned.
	source string
	// outageErr is the FIRST error from any validator that could not reach a
	// verdict (unavailable key material, an unreachable deny-list), and
	// outageSource names it. Both are empty when every validator reached one.
	outageErr    error
	outageSource string
}

// resolveTokenLegacy is the unchanged legacy resolution. Its (*ValidatedIdentity,
// error) pair is byte-identical to what it was before this change; the
// tokenOutcome is additional, is read only by the counterfactual, and cannot
// change what the caller sees.
func resolveTokenLegacy(ctx context.Context, orgID, token string) (*ValidatedIdentity, tokenOutcome, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, tokenOutcome{}, nil // no token presented → caller uses least-privilege
	}

	validators := RegisteredValidators()
	if len(validators) == 0 {
		return nil, tokenOutcome{}, nil // capability absent (community build) → least-privilege, never elevate
	}

	var lastErr error
	var lastErrSource string
	var outageErr error
	var outageSource string
	for _, v := range validators {
		id, err := v.Validate(ctx, orgID, token)
		if err == nil && id != nil {
			return id, tokenOutcome{source: v.Name()}, nil // first success wins
		}
		if err != nil && !errors.Is(err, ErrNotConfigured) {
			// Recognized-but-invalid (bad signature / expired / revoked / wrong
			// org). Remember it, but keep trying: a token this validator can't
			// handle (e.g. an OIDC token hitting the HS256 validator) may be
			// another registered validator's to accept.
			//
			lastErr = err
			lastErrSource = v.Name()

			// AN OUTAGE IS REMEMBERED SEPARATELY, because last-wins loses it.
			//
			// Both validators are tried for every token, and each rejects the
			// other's credential class by SHAPE: an HS256 token hits the OIDC
			// verifier's RSA method check, an RS256 token hits the HS256 one's
			// HMAC check. So the LAST error is routinely from the validator
			// that never had a chance. With HS256 registered first, an
			// ErrRevocationUnavailable from the validator that actually
			// examined the credential was overwritten by the OIDC verifier's
			// shape rejection on every request in an SSO-configured org,
			// deleting exactly the classification this change exists to create
			// and attributing the counterfactual to the wrong path.
			//
			// This is tracked ALONGSIDE lastErr rather than replacing it, so
			// the error RETURNED to the caller is byte-identical to what it
			// was before this change. Only the counterfactual reads it, and
			// only the FIRST outage is kept: a second outage from a validator
			// that rejected by shape says nothing about this credential.
			if outageErr == nil && ClassifyTokenError(err) != "" {
				outageErr = err
				outageSource = v.Name()
			}
		}
	}

	// A token was presented but no validator produced an identity. Fail closed.
	if lastErr == nil {
		// Every validator skipped (ErrNotConfigured) — nothing could handle a
		// presented token. Still a rejected access attempt.
		lastErr = ErrTokenInvalid
	}
	return nil, tokenOutcome{source: lastErrSource, outageErr: outageErr, outageSource: outageSource},
		fmt.Errorf("no registered validator accepted the per-user token: %w", lastErr)
}

// tokenLegacyAuth builds the adapter input from a token-resolution outcome.
//
// The path is taken from the validator that actually produced the outcome
// (ValidatedIdentity.Source on success, the rejecting validator's name on
// failure), never assumed. An outcome no validator produced - every backend
// skipped as ErrNotConfigured - is attributed to the HS256 path, which is the
// only one registered unconditionally in an enterprise build; the counterfactual
// still records the legacy reason verbatim, so the attribution cannot hide what
// happened.
func tokenLegacyAuth(orgID string, id *ValidatedIdentity, outcome tokenOutcome, err error) LegacyAuth {
	source := outcome.source
	if source == "" && id != nil {
		source = id.Source
	}
	accepted := id != nil && err == nil
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	var claims map[string]any
	if id != nil {
		claims = id.Claims
	}
	// An OUTAGE, where one occurred, is what the counterfactual reports, and
	// it overrides both the classification and the path attribution: it came
	// from the validator that actually examined the credential, while the
	// returned error is routinely from one that rejected it by shape.
	unverifiable := ClassifyTokenError(err)
	if outcome.outageErr != nil {
		unverifiable = ClassifyTokenError(outcome.outageErr)
		source = outcome.outageSource
	}
	if source == ValidatorNameOIDC {
		return OIDCLegacyAuth(orgID, claims, accepted, reason, unverifiable)
	}
	return HS256LegacyAuth(orgID, claims, accepted, reason, unverifiable)
}

// --- the synthetic-probe context value (#3602) ---

// syntheticProbeCtxKey is the key ContextWithSyntheticProbe stores under. It is
// an unexported struct type so no other package can collide with it or set the
// value without going through the constructor below.
type syntheticProbeCtxKey struct{}

// ContextWithSyntheticProbe marks a context as belonging to a request driven
// by AxonFlow's own observation-window canary.
//
// It exists because ResolveToken is a SHARED choke point that receives a
// context and a token and nothing else - it has no request to read a header
// from - while the fact it needs is carried on one. See LegacyAuth.Synthetic
// for what the flag means and why a caller-assertable channel is acceptable
// for it. It decides nothing: the value is read at exactly one site, to set
// one metric label.
func ContextWithSyntheticProbe(ctx context.Context, synthetic bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, syntheticProbeCtxKey{}, synthetic)
}

// SyntheticProbeFromContext reports whether the context was marked.
//
// AN UNSTAMPED CONTEXT ANSWERS FALSE, which puts the comparison in the ORGANIC
// bucket. That is the direction that matters: the opposite default would let a
// caller who forgot to stamp quietly move real tenant traffic out of the volume
// an operator is measuring, which is the reading the gate's coverage half
// depends on.
func SyntheticProbeFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(syntheticProbeCtxKey{}).(bool)
	return v
}
