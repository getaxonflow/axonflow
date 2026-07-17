// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"

	identity "axonflow/platform/shared/identity"
)

// userTokenRevocations is the per-user-token revocation deny-list consulted by
// validateUserToken on the request/decide plane (#2924, #2930 R3). It stays
// nil in community builds and until wired at startup — a nil checker means the
// lookup is skipped (community has no per-user tokens; user_token_revocations
// is an Enterprise-only table). Set by wireUserTokenRevocation.
var userTokenRevocations identity.RevocationChecker

// wireUserTokenRevocation backs the decide-plane revocation lookup with the
// mig-135 deny-list over the request-plane DB pool (usageDB, axonflow_app_role
// — the table is FORCE-RLS org-isolated and the store sets app.current_org_id
// per lookup). Called once at startup. A community build's
// identity.NewDBRevocationStore returns ErrEnterpriseOnly, so the checker
// stays nil there and revocation-on-decide is naturally Enterprise-gated. A
// nil db (misconfigured deployment) also leaves it unset.
//
// The store is fronted by a short-TTL, jti-keyed not-revoked cache (#2931) so a
// high-QPS fleet does not do a BeginTx+SELECT EXISTS+Commit on every decide for
// the same live token. The cache never masks a revocation into an allow (only
// confirmed not-revoked results are cached; a mass revoke is caught early via
// the per-user watermark; a checker error still denies) — see
// cachedRevocationChecker.
func wireUserTokenRevocation(db *sql.DB) {
	if db == nil {
		return
	}
	checker, err := identity.NewDBRevocationStore(db)
	if err != nil {
		// ErrEnterpriseOnly (community build) or a nil db — revocation on the
		// decide plane is an Enterprise capability; leave the checker unset.
		return
	}
	userTokenRevocations = newCachedRevocationChecker(checker)
	log.Println("✅ Per-user token revocation enforcement wired on the request/decide plane (#2924, cached #2931)")
}

// checkUserTokenRevoked rejects a validated HS256 user token whose jti has been
// revoked (single-token OR mass revocation), so a DELETE .../user-tokens takes
// effect on the request/decide plane and not only on the fleet/MCP-server
// plane. It is a NO-OP when:
//   - no revocation checker is wired (community build / not Enterprise), or
//   - the token carries no jti — legacy generate-jwt.sh tokens have no jti and
//     are deliberately left alone; revocation is opt-in via the mint API's
//     jti (master's #2930 R3 contract: do not newly require iss/jti).
//
// It FAILS CLOSED: a revocation-store error rejects the token rather than
// letting an unverifiable token through. A short timeout bounds a hung DB.
func checkUserTokenRevoked(claims jwt.MapClaims, orgID string) error {
	if userTokenRevocations == nil {
		return nil
	}
	jti := getClaimString(claims, "jti")
	if jti == "" {
		return nil
	}
	email := getClaimString(claims, "email")
	issuedAt := time.Time{}
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		issuedAt = iat.Time
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	revoked, err := userTokenRevocations.IsRevoked(ctx, orgID, jti, email, issuedAt)
	if err != nil {
		return fmt.Errorf("revocation check failed: %w", err)
	}
	if revoked {
		return fmt.Errorf("token revoked")
	}
	return nil
}
