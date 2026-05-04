//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"axonflow/platform/agent/license"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// pluginClaimContextKey is the request-context key under which the validated
// plugin-claim row is stashed. Unexported empty struct so external packages
// cannot collide with it.
type pluginClaimContextKey struct{}

// PluginClaimContext carries tier-aware metadata extracted from the validated
// plugin-claim license row. Set by PluginClaimMiddleware on the request
// context; read by downstream handlers via PluginClaimFromContext.
type PluginClaimContext struct {
	LicenseID        string                 // plugin_user_licenses.license_id (UUID, audit trail)
	Tier             string                 // "plugin-claimed" (Pro v1) or "plugin-subscription" (Premium v2)
	JTI              string                 // unique token id (audit + revocation)
	Entitlements     map[string]interface{} // mutable per-tier capabilities (retention_days, daily_event_quota, …)
	StripeCustomerID string                 // for refund / dispute / accounting reconciliation
}

// PluginClaimFromContext returns the plugin-claim metadata if the request
// presented a valid plugin-claim license token. Returns nil when:
//   - no X-License-Token header was sent (free tier)
//   - middleware was not in the chain for this route
//   - middleware was in the chain but token validation failed (request would
//     have already been rejected with 401 in that case)
//
// Downstream handlers branch on this nil/non-nil to apply tier-aware quota,
// retention, and capability enforcement (per ADR-049 section 4).
func PluginClaimFromContext(ctx context.Context) *PluginClaimContext {
	v, _ := ctx.Value(pluginClaimContextKey{}).(*PluginClaimContext)
	return v
}

// PluginClaimMiddleware validates plugin-claim license tokens issued by
// axonflow-billing on Stripe Checkout success (W4 paid Pro tier, ADR-049).
//
// Validation is two-stage:
//
//  1. Token-side (delegated to license.ValidatePluginClaimToken): signature,
//     audience, origin, tier, tenant_id, jti, expiry.
//  2. DB-side (this function): plugin_user_licenses row must exist for the
//     token's jti, must not be revoked, and its tenant_id must match the
//     token's tenant_id (defense against token re-use across tenants).
//
// Outcomes:
//   - No token in header → passes through unmodified (free tier behaviour).
//   - Token valid + row active → enriches request context with
//     *PluginClaimContext, then forwards to next handler.
//   - Token invalid (bad sig/aud/origin/tier/expiry) → 401 invalid_license_token.
//   - Token valid but row missing or revoked → 401 license_revoked.
//   - Token valid but row tenant_id mismatch → 403 license_tenant_mismatch.
//   - DB unavailable → 503 service_unavailable (so plugin retries).
//
// The DB lookup runs on every request because plugin-claim revocation must
// be effective within ~60s of a chargeback or dispute (ADR-049 section 2).
// The plugin_user_licenses row is small and the lookup is by indexed jti
// column (idx_plugin_lic_jti), so the per-request cost is sub-millisecond.
func PluginClaimMiddleware(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := r.Header.Get("X-License-Token")
			if tok == "" {
				pluginClaimValidationsTotal.WithLabelValues("absent").Inc()
				next.ServeHTTP(w, r)
				return
			}

			payload, err := license.ValidatePluginClaimToken(tok)
			if err != nil {
				pluginClaimValidationsTotal.WithLabelValues("invalid_token").Inc()
				log.Printf("[plugin_claim] token validation failed: %v", err)
				writeJSONError(w, "Invalid plugin license token", http.StatusUnauthorized)
				return
			}

			if db == nil {
				// Middleware installed without a DB handle — operator
				// misconfiguration. Surface as 503 so the plugin retries
				// rather than silently degrading to free tier.
				pluginClaimValidationsTotal.WithLabelValues("db_unavailable").Inc()
				log.Printf("[plugin_claim] DB nil; cannot look up license_token_jti=%s", payload.JTI)
				writeJSONError(w, "License lookup temporarily unavailable", http.StatusServiceUnavailable)
				return
			}

			lookupCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()

			var (
				licenseID        string
				tier             string
				rowTenantID      string
				entJSON          string
				stripeCustomerID string
				revokedAt        *time.Time
			)
			err = db.QueryRowContext(lookupCtx, `
				SELECT license_id::text, tier, tenant_id, entitlements::text,
				       COALESCE(stripe_customer_id, ''), revoked_at
				  FROM plugin_user_licenses
				 WHERE license_token_jti = $1`, payload.JTI,
			).Scan(&licenseID, &tier, &rowTenantID, &entJSON, &stripeCustomerID, &revokedAt)

			if errors.Is(err, sql.ErrNoRows) {
				// Token's jti has no corresponding row. Either the row was
				// hard-deleted (shouldn't happen — we only soft-delete via
				// revoked_at) or the token was forged with a valid signature
				// but a never-issued jti. Reject either way.
				pluginClaimValidationsTotal.WithLabelValues("not_found").Inc()
				writeJSONError(w, "License not found or revoked", http.StatusUnauthorized)
				return
			}
			if err != nil {
				pluginClaimValidationsTotal.WithLabelValues("db_error").Inc()
				log.Printf("[plugin_claim] DB query failed for jti=%s: %v", payload.JTI, err)
				writeJSONError(w, "License lookup temporarily unavailable", http.StatusServiceUnavailable)
				return
			}

			if revokedAt != nil {
				pluginClaimValidationsTotal.WithLabelValues("revoked").Inc()
				writeJSONError(w, "License has been revoked", http.StatusUnauthorized)
				return
			}

			if rowTenantID != payload.TenantID {
				// Token re-use attempt: someone is presenting a valid token
				// to a tenant other than the one it was issued for. Treat as
				// a forgery attempt and reject hard.
				pluginClaimValidationsTotal.WithLabelValues("tenant_mismatch").Inc()
				log.Printf("[plugin_claim] tenant mismatch for jti=%s: token=%s row=%s",
					payload.JTI, payload.TenantID, rowTenantID)
				writeJSONError(w, "License tenant mismatch", http.StatusForbidden)
				return
			}

			// Decode JSONB entitlements. Tolerate empty / malformed so a
			// bad row doesn't take down the whole tier — caller falls back
			// to default tier behaviour from a missing entitlements key.
			ent := map[string]interface{}{}
			if entJSON != "" {
				if jerr := json.Unmarshal([]byte(entJSON), &ent); jerr != nil {
					log.Printf("[plugin_claim] bad entitlements JSON for jti=%s: %v", payload.JTI, jerr)
				}
			}

			pluginClaimValidationsTotal.WithLabelValues("valid").Inc()

			pcc := &PluginClaimContext{
				LicenseID:        licenseID,
				Tier:             tier,
				JTI:              payload.JTI,
				Entitlements:     ent,
				StripeCustomerID: stripeCustomerID,
			}
			ctxOut := context.WithValue(r.Context(), pluginClaimContextKey{}, pcc)
			next.ServeHTTP(w, r.WithContext(ctxOut))
		})
	}
}

// pluginClaimValidationsTotal counts plugin-claim middleware outcomes.
// Operators alert on:
//   - sustained "invalid_token" or "tenant_mismatch" → likely token forgery
//   - sustained "db_error" / "db_unavailable" → DB or middleware regression
//   - sustained "not_found" → revocation lag, billing/agent DB drift
var pluginClaimValidationsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_agent_plugin_claim_validations_total",
		Help: "Plugin-claim license token validation outcomes per request " +
			"(result: valid|invalid_token|not_found|revoked|tenant_mismatch|db_error|db_unavailable|absent)",
	},
	[]string{"result"},
)
