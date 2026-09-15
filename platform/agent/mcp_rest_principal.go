// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"crypto/sha256"
	"encoding/hex"

	sharedidentity "axonflow/platform/shared/identity"
)

// The principal an MCP REST request is attributed to and cached under.
//
// The MCP REST routes (mcp_handler.go) authenticate an end user with
// ResolveUser -> validateUserToken (run.go): algorithm-pinned HS256, jti
// revocation, a real `email` claim. Two questions about that principal are
// answered here, once, for every route that asks them: whether it is a
// VERIFIED human (callerIsVerifiedHuman), and which idempotency scope a
// check-input response is cached under (mcpCheckInputIdempEndpoint).
//
// The token INGEST differs by plane and stays that way (#2941): the MCP REST
// handlers read it from their JSON body's `user_token` field. They do not read
// an X-User-Token header - that header is the OTHER envelope, with its own
// read seams, pinned by user_token_ingest_census_test.go.

// callerIsVerifiedHuman reports whether this request carries a VERIFIED HUMAN
// principal.
//
// The discriminator is exactly two facts, and nothing else:
//
//   - ResolveUser returned NO error, and
//   - auth.Kind == AuthKindEnterprise.
//
// Only the AuthKindEnterprise arm of ResolveUser (authenticator.go) runs
// validateUserToken; the other three arms SYNTHESIZE a fixed identity -
// AuthKindCommunity ("local-dev@axonflow.local"), AuthKindCommunitySaaS
// ("evaluator@try.getaxonflow.com") and AuthKindInternalService
// ("orchestrator@axonflow.internal") - which names no person.
//
// userErr != nil means the handler either synthesized the org-scoped service
// identity (client.ID+"@axonflow.local", the token-ABSENT compat path) or
// already returned 401 (#3472 presented-and-rejected, #3476
// absent-but-required).
func callerIsVerifiedHuman(auth *AuthResult, userErr *AuthError, presentedToken string) bool {
	if auth == nil {
		return false
	}
	// ONE predicate, shared with audit attribution (identity_trust.go), so
	// every use keys on one notion of "who this is": the audit row names the
	// principal the anchored engine was asked to decide for, which is only
	// meaningful if one function decides what counts as verified.
	return callerHasVerifiedUserIdentity(auth.Kind, userErr, presentedToken)
}

// mcpCheckInputIdempEndpoint derives the idempotency scope for
// /api/v1/mcp/check-input, binding the cached response to the principal the
// verdict was computed for.
//
// The store's key is (key, tenant_id, endpoint) and its replay path returns
// the cached body without running the handler, so anything the verdict depends
// on that is NOT in that key is replayable across callers. The anchored engine
// decides for the admitted principal - a published document can constrain one
// user and not another - so the principal has to be in the key.
//
// The value is hashed rather than embedded: idempotency_keys.endpoint is a
// plain TEXT column read by operators and sweeps, and it has no business
// holding an email. A hash keeps the partitioning exact while keeping identity
// out of the row.
func mcpCheckInputIdempEndpoint(principal string) string {
	sum := sha256.Sum256([]byte(sharedidentity.CanonicalEmail(principal)))
	return "mcp.check-input|p=" + hex.EncodeToString(sum[:])
}
