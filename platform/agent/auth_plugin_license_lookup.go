// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"axonflow/platform/agent/license"
	logutil "axonflow/platform/shared/logger"
)

// errPluginLicenseNotFound + errPluginLicenseTenantMismatch are sentinel
// errors returned by lookupActivePluginLicenseTier so callers can map them
// to the right HTTP status. Other errors (DB unavailable, connection lost)
// are returned wrapped and map to 503.
var (
	errPluginLicenseNotFound       = errors.New("plugin_user_licenses row not found or revoked")
	errPluginLicenseTenantMismatch = errors.New("plugin_user_licenses row tenant_id does not match token tenant_id")
)

// lookupActivePluginLicenseTier reads the active (non-revoked)
// plugin_user_licenses row for the given JTI and returns its tier.
// Enforces row.tenant_id == tenantID as defense against token re-use
// across tenants. The 2-second context timeout caps DB latency on the
// hot path; callers should pre-attach a request context so a slow DB
// can't outlast the request.
//
// This is the work that used to live in `plugin_claim_middleware.go`
// (deleted in the same PR that introduced this helper); it folds inline
// into the auth path per ADR-049 §3 + ADR-050 §9 Pattern B.
func lookupActivePluginLicenseTier(ctx context.Context, db pluginLicenseRowReader, jti, tenantID string) (license.Tier, error) {
	if db == nil {
		return "", errors.New("plugin_user_licenses lookup: db is nil")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var (
		rowTier      string
		rowTenantID  string
		rowRevokedAt *time.Time
	)
	err := db.QueryRowContext(lookupCtx, `
		SELECT tier, tenant_id, revoked_at
		  FROM plugin_user_licenses
		 WHERE license_token_jti = $1`, jti,
	).Scan(&rowTier, &rowTenantID, &rowRevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errPluginLicenseNotFound
	}
	if err != nil {
		return "", err
	}
	if rowRevokedAt != nil {
		return "", errPluginLicenseNotFound
	}
	if rowTenantID != tenantID {
		return "", errPluginLicenseTenantMismatch
	}
	return license.Tier(rowTier), nil
}

// mapPluginLicenseLookupError converts a lookupActivePluginLicenseTier
// error into a CommunitySaasAuthError with the right HTTP status. The
// JTI is intentionally NOT echoed in the user-facing message — it leaks
// no useful info to a legitimate caller and surfacing it would help an
// attacker enumerate revoked tokens.
func mapPluginLicenseLookupError(err error, jti string) *CommunitySaasAuthError {
	switch {
	case errors.Is(err, errPluginLicenseNotFound):
		return &CommunitySaasAuthError{
			StatusCode: http.StatusUnauthorized,
			Message:    "license_not_found_or_revoked",
		}
	case errors.Is(err, errPluginLicenseTenantMismatch):
		return &CommunitySaasAuthError{
			StatusCode: http.StatusForbidden,
			Message:    "license_tenant_mismatch",
		}
	default:
		// Unexpected DB error — surface as 503 so the plugin retries
		// rather than silently degrading to Free.
		return &CommunitySaasAuthError{
			StatusCode: http.StatusServiceUnavailable,
			Message:    fmt.Sprintf("license_lookup_unavailable (jti=%s)", logutil.Sanitize(jti)),
		}
	}
}

// pluginLicenseRowReader is the minimal interface lookupActivePluginLicenseTier
// needs from *sql.DB. Pulled out so unit tests can pass a sqlmock without
// depending on the concrete *sql.DB type.
type pluginLicenseRowReader interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
