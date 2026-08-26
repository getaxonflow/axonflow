// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq"

	"axonflow/platform/agent"
	sharedidentity "axonflow/platform/shared/identity"
)

// pqArray wraps a Go string slice as a PostgreSQL text[] for parameterised
// queries using ANY($n::text[]).
func pqArray(v []string) interface{} { return pq.Array(v) }

// Override TTL bounds per ADR-044.
// These are hard platform-level constants. Plugins may suggest shorter TTLs;
// the platform clamps on create.
const (
	OverrideDefaultTTL  = 60 * time.Minute
	OverrideHardCapTTL  = 24 * time.Hour
	OverrideMinTTL      = 1 * time.Minute // prevent zero/negative TTLs
	OverrideReasonMaxLn = 500             // cap free-text to prevent abuse
)

// CreateOverrideRequest is the request body for POST /api/v1/overrides.
// Reason is mandatory per ADR-044.
type CreateOverrideRequest struct {
	PolicyID       string `json:"policy_id"`
	PolicyType     string `json:"policy_type"` // "static" | "dynamic"
	ToolSignature  string `json:"tool_signature,omitempty"`
	OverrideReason string `json:"override_reason"`
	TTLSeconds     int64  `json:"ttl_seconds,omitempty"` // clamped server-side
}

// CreateOverrideResponse is returned on successful create.
type CreateOverrideResponse struct {
	ID            string    `json:"id"`
	PolicyID      string    `json:"policy_id"`
	PolicyType    string    `json:"policy_type"`
	ExpiresAt     time.Time `json:"expires_at"`
	TTLSeconds    int64     `json:"ttl_seconds"`
	RequestedTTL  int64     `json:"requested_ttl,omitempty"`
	Clamped       bool      `json:"clamped,omitempty"`
	ClampedReason string    `json:"clamped_reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// clampOverrideTTL applies ADR-044 server-side clamping rules.
// Returns: (actualTTL, wasClamped, reason).
//   - If requested > 0 and <= hard cap: use requested.
//   - If requested == 0: use default.
//   - If requested > hard cap: clamp to cap, reason="exceeds_hard_cap".
//   - If requested < min: clamp to min, reason="below_minimum".
func clampOverrideTTL(requestedSeconds int64) (time.Duration, bool, string) {
	if requestedSeconds == 0 {
		return OverrideDefaultTTL, false, ""
	}

	requested := time.Duration(requestedSeconds) * time.Second
	switch {
	case requested > OverrideHardCapTTL:
		return OverrideHardCapTTL, true, "exceeds_hard_cap"
	case requested < OverrideMinTTL:
		return OverrideMinTTL, true, "below_minimum"
	default:
		return requested, false, ""
	}
}

// policyRiskAndOverride returns (risk_level, allow_override) for the given
// policy, looking up static_policies or dynamic_policies based on policy_type.
// Returns sql.ErrNoRows when the policy does not exist so callers can
// distinguish "not found" (404) from "database error" (500).
//
// Accepts either the UUID id or the human-readable slug/policy_id, so
// plugin callers can pass whichever they have without a side-channel
// lookup. MCP check-input block responses carry the slug in
// `policy_matches[].policy_id`; an end-user who calls
// `createOverride({ policyId: that })` would otherwise get a 404 even
// though the policy exists.
// #3039: static/dynamic_policies are RLS-enabled (mig 018) and a bare read
// on the app-role pool matched 0 rows — every override create 404'd "policy
// not found". The lookup runs tenant-scoped first, then 'global'-scoped for
// system rows, with a matching SQL tenancy predicate so a bypass-RLS pool
// (master-role deployments) can't become a cross-tenant name/existence
// oracle — tenant A can never resolve or probe tenant B's policies.
func policyRiskAndOverride(ctx context.Context, db *sql.DB, tenantID, policyID, policyType string) (string, bool, string, error) {
	var table string
	switch policyType {
	case "static":
		table = "static_policies"
	case "dynamic":
		table = "dynamic_policies"
	default:
		return "", false, "", fmt.Errorf("invalid policy_type: %s", policyType)
	}

	//nolint:gosec // table name is validated via switch above; value side is parameterized.
	// Match on either id (UUID) or policy_id (slug for static; absent for
	// dynamic, where id IS the identifier). Dynamic_policies has no
	// policy_id slug column historically, but SELECT '' AS policy_id is
	// included in the UNION so the query shape works for both tables.
	//
	// REQUIRES migration 070 (ships with v7.1.0): both static_policies and
	// dynamic_policies must have risk_level + allow_override columns. COALESCE
	// only guards NULL values, not missing columns — running v7.1.1 binaries
	// against a pre-v7.1.0 schema will produce "column does not exist" SQL
	// errors surfaced to the caller as 500. This is intentional; partial
	// schema upgrades shouldn't silently degrade override semantics.
	var query string
	if table == "static_policies" {
		query = fmt.Sprintf(`
			SELECT risk_level, allow_override, id::text
			FROM %s
			WHERE (id::text = $1 OR policy_id = $1)
			  AND (tenant_id = $2 OR tenant_id = 'global')
			LIMIT 1`, table)
	} else {
		query = fmt.Sprintf(`
			SELECT COALESCE(risk_level, 'medium') AS risk_level,
			       COALESCE(allow_override, false) AS allow_override,
			       id::text
			FROM %s
			WHERE (id::text = $1 OR name = $1)
			  AND (tenant_id = $2 OR tenant_id = 'global')
			LIMIT 1`, table)
	}
	var riskLevel, canonicalUUID string
	var allowOverride bool
	scopedGet := func(scopeOrg string) error {
		return agent.WithOrgScope(ctx, db, scopeOrg, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, query, policyID, tenantID).Scan(&riskLevel, &allowOverride, &canonicalUUID)
		})
	}
	err := scopedGet(tenantID)
	if err == sql.ErrNoRows && tenantID != GlobalTenantSentinel {
		err = scopedGet(GlobalTenantSentinel)
	}
	if err != nil {
		return "", false, "", err
	}
	return riskLevel, allowOverride, canonicalUUID, nil
}

// resolvePolicyUUID returns the canonical UUID id for a policy given the
// UUID, the static_policies slug, or the dynamic_policies name. Returns
// an empty string (no error) when no match is found.
func resolvePolicyUUID(ctx context.Context, db *sql.DB, tenantID, policyID string) (string, error) {
	if db == nil || policyID == "" {
		return "", nil
	}
	// Same scoped two-pass + tenancy predicate as policyRiskAndOverride
	// (#3039): visible under app-role RLS, never a cross-tenant oracle on
	// bypass pools.
	var uuid string
	lookup := func(scopeOrg string) error {
		return agent.WithOrgScope(ctx, db, scopeOrg, func(tx *sql.Tx) error {
			err := tx.QueryRowContext(ctx, `
				SELECT id::text FROM static_policies
				WHERE (id::text = $1 OR policy_id = $1)
				  AND (tenant_id = $2 OR tenant_id = 'global')
				LIMIT 1
			`, policyID, tenantID).Scan(&uuid)
			if err == nil || err != sql.ErrNoRows {
				return err
			}
			return tx.QueryRowContext(ctx, `
				SELECT id::text FROM dynamic_policies
				WHERE (id::text = $1 OR name = $1)
				  AND (tenant_id = $2 OR tenant_id = 'global')
				LIMIT 1
			`, policyID, tenantID).Scan(&uuid)
		})
	}
	err := lookup(tenantID)
	if err == sql.ErrNoRows && tenantID != GlobalTenantSentinel {
		err = lookup(GlobalTenantSentinel)
	}
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return uuid, nil
}

// invalidateCachedDeniedDecisions deletes workflow_steps cache rows that
// referenced the just-overridden policy in a denied outcome, for the scope
// of the override's creator (tenant + user). #1607's idempotent retry
// semantics mean a subsequent step_gate call for the same (workflow, step)
// would otherwise replay the stale deny from workflow_steps instead of
// re-evaluating with the new override in place.
//
// Best-effort: a logged error on failure is preferable to failing the
// override create (the override record itself is durable; the cache is a
// performance optimisation). Returns no error on purpose.
//
// policyID can be either the UUID (what policy_overrides.policy_id stores)
// or the human-readable slug/name. The WCP adapter currently writes the
// policy NAME into workflow_steps.policies_matched[i].policy_id, so cache
// invalidation has to match either shape. We resolve all known identifiers
// for the policy (UUID, slug, name) and match any of them.
func invalidateCachedDeniedDecisions(ctx context.Context, db *sql.DB, tenantID, userEmail, policyID string) {
	if db == nil || policyID == "" {
		return
	}
	// #3065: the tenant dimension is MANDATORY, not one of two acceptable
	// dimensions. The old guard accepted (tenantID="", userEmail="alice@…")
	// and the SQL below then read `($1 = '' OR w.tenant_id = $1)` — so an
	// empty tenant disabled the tenancy filter and the DELETE reached every
	// tenant's workflow_steps rows for that email. The user dimension stays
	// optional (org-wide overrides carry no per-user identity) and narrows
	// within the tenant.
	if tenantID == "" {
		// Refuse to delete without a tenant scope — we will not invalidate
		// across the whole table.
		return
	}

	// Resolve all synonyms for the policy so the match survives WCP's
	// policy_id=name convention. Checks both static_policies and
	// dynamic_policies; collects unique non-empty values.
	synonyms := map[string]struct{}{policyID: {}}
	addRow := func(rows *sql.Rows) {
		for rows.Next() {
			var slug, name sql.NullString
			if err := rows.Scan(&slug, &name); err == nil {
				if slug.Valid && slug.String != "" {
					synonyms[slug.String] = struct{}{}
				}
				if name.Valid && name.String != "" {
					synonyms[name.String] = struct{}{}
				}
			}
		}
	}
	// Scoped two-pass (#3039): best-effort, so scope errors are ignored the
	// same way the old bare-read errors were.
	for _, scopeOrg := range []string{tenantID, GlobalTenantSentinel} {
		if scopeOrg == "" || (scopeOrg == GlobalTenantSentinel && tenantID == GlobalTenantSentinel) {
			continue
		}
		_ = agent.WithOrgScope(ctx, db, scopeOrg, func(tx *sql.Tx) error {
			if rows, err := tx.QueryContext(ctx,
				"SELECT policy_id, name FROM static_policies WHERE (id::text = $1 OR policy_id = $1 OR name = $1) AND (tenant_id = $2 OR tenant_id = 'global')",
				policyID, tenantID,
			); err == nil {
				addRow(rows)
				_ = rows.Close()
			}
			if rows, err := tx.QueryContext(ctx,
				"SELECT '' AS policy_id, name FROM dynamic_policies WHERE (id::text = $1 OR name = $1) AND (tenant_id = $2 OR tenant_id = 'global')",
				policyID, tenantID,
			); err == nil {
				addRow(rows)
				_ = rows.Close()
			}
			return nil
		})
	}

	synArr := make([]string, 0, len(synonyms))
	for k := range synonyms {
		synArr = append(synArr, k)
	}

	// JSONB match: any entry with policy_id matching any synonym OR
	// policy_name matching any synonym. We use jsonb_array_elements +
	// EXISTS so we can match on either key across a variadic set of
	// candidate values.
	result, err := db.ExecContext(ctx, `
		DELETE FROM workflow_steps
		WHERE id IN (
			SELECT ws.id
			FROM workflow_steps ws
			JOIN workflows w ON ws.workflow_id = w.workflow_id
			WHERE w.tenant_id = $1
			  AND ($2 = '' OR w.user_id = $2)
			  AND ws.decision IN ('block', 'require_approval')
			  AND (
			    EXISTS (
			      SELECT 1 FROM jsonb_array_elements(ws.policies_matched) AS m
			      WHERE m->>'policy_id' = ANY($3::text[])
			         OR m->>'policy_name' = ANY($3::text[])
			    )
			    OR EXISTS (
			      SELECT 1 FROM jsonb_array_elements(ws.policies_evaluated) AS m
			      WHERE m->>'policy_id' = ANY($3::text[])
			         OR m->>'policy_name' = ANY($3::text[])
			    )
			  )
		)
	`, tenantID, userEmail, pqArray(synArr))
	if err != nil {
		log.Printf("override create: cache invalidation failed (tenant=%s user=%s policy=%s synonyms=%v): %v",
			tenantID, userEmail, policyID, synArr, err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("override create: invalidated %d cached denied decisions for policy=%s (synonyms=%v)",
			n, policyID, synArr)
	}
}

// validateCreateOverrideRequest validates the request body against ADR-044
// invariants: reason required, policy_id required, policy_type valid,
// reason length capped.
func validateCreateOverrideRequest(req *CreateOverrideRequest) error {
	if strings.TrimSpace(req.PolicyID) == "" {
		return fmt.Errorf("policy_id is required")
	}
	if req.PolicyType != "static" && req.PolicyType != "dynamic" {
		return fmt.Errorf("policy_type must be 'static' or 'dynamic'")
	}
	if strings.TrimSpace(req.OverrideReason) == "" {
		return fmt.Errorf("override_reason is required (ADR-044: mandatory justification)")
	}
	if len(req.OverrideReason) > OverrideReasonMaxLn {
		return fmt.Errorf("override_reason exceeds maximum length of %d characters", OverrideReasonMaxLn)
	}
	return nil
}

// createOverrideHandler handles POST /api/v1/overrides.
// Writes a policy_overrides row, enforces ADR-044 rules server-side,
// emits an override_created audit event.
func createOverrideHandler(w http.ResponseWriter, r *http.Request) {
	// #2896 WS1b: the identity that KEYS the override (X-User-Email below) is
	// only trustworthy when set by the Agent gateway, which trust-gates the
	// per-user headers (#2897) and injects the HMAC proxy token. A direct
	// caller could otherwise create an override as an arbitrary principal —
	// the same deny→allow hijack class #2897 closed on the agent planes.
	// Mirrors auditToolCallHandler; Community mode (no secret) is exempt.
	if ok, msg := verifyAgentProxyAuth(r, "OverrideCreate"); !ok {
		sendErrorResponse(w, msg, http.StatusForbidden)
		return
	}

	var req CreateOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateCreateOverrideRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Identity from request headers (per ADR-041). Check identity BEFORE
	// any DB work — cheap header check rejects unauthenticated requests
	// without touching Postgres, and prevents orphaned audit-attributable
	// records (ADR-044 requires every override has a created_by).
	tenantID := r.Header.Get("X-Tenant-ID")
	orgID := r.Header.Get("X-Org-ID")
	userEmail := r.Header.Get("X-User-Email")
	if userEmail == "" {
		userEmail = r.Header.Get("X-User-ID")
	}
	// #2922 (R3 Finding 4): canonicalize created_by on write so it matches the
	// same canonical key the role-scoped override reads compare against — parity
	// with every other #2922 write path. The reads already canonicalize
	// created_by on comparison (LOWER() + CanonicalEmail), so this is belt-and-
	// braces consistency, but it keeps the stored value TRIM+lowercased so a
	// header with surrounding whitespace can never drop a developer's own
	// override out of their own scoped list.
	userEmail = sharedidentity.CanonicalEmail(userEmail)
	if userEmail == "" {
		// #3062: the bare "send X-User-Email" 401 sent users looking for a
		// client-side mistake when the cause is almost always server-side —
		// the agent's default-off identity trust gate removed the header they
		// did send. sendIdentityRequiredError names whichever it actually was.
		sendIdentityRequiredError(w, r, "policy overrides")
		return
	}
	if tenantID == "" {
		sendErrorResponse(w, "Tenant identity required (X-Tenant-ID header)", http.StatusBadRequest)
		return
	}

	// ADR-044: critical risk policies cannot be overridden.
	// policyRiskAndOverride accepts either the UUID or the human-readable
	// slug/name and returns the canonical UUID to store in policy_overrides.
	riskLevel, allowOverride, canonicalUUID, err := policyRiskAndOverride(r.Context(), usageDB, tenantID, req.PolicyID, req.PolicyType)
	if err == sql.ErrNoRows {
		sendErrorResponse(w, "Policy not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("override create: policy lookup failed: %v", err)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if riskLevel == "critical" {
		sendErrorResponse(w, "Critical-risk policies cannot be overridden", http.StatusForbidden)
		return
	}
	if !allowOverride {
		sendErrorResponse(w, "This policy has allow_override=false and cannot be session-overridden", http.StatusForbidden)
		return
	}

	// Server-side TTL clamping.
	ttl, clamped, clampReason := clampOverrideTTL(req.TTLSeconds)
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	overrideID := uuid.NewString()

	var toolSig sql.NullString
	if req.ToolSignature != "" {
		toolSig = sql.NullString{String: req.ToolSignature, Valid: true}
	}

	// v9 Phase 8 PR-C2 (#2384) + mig 110: policy_overrides RLS was rekeyed
	// to `app.current_org_id` GUC + org_id column. The legacy app.tenant_id
	// policy is gone; WithOrgScope + org_id col satisfy the new policy.
	// orgID from the X-Org-ID header is the canonical post-Phase-6 identifier;
	// fall back to tenantID for legacy callers (tenant_id == org_id collapse).
	overrideOrgScope := orgID
	if overrideOrgScope == "" {
		overrideOrgScope = tenantID
	}
	if wrapErr := agent.WithOrgScope(r.Context(), usageDB, overrideOrgScope, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(r.Context(), `
			INSERT INTO policy_overrides (
				id, policy_id, policy_type, tenant_id, org_id, tool_signature,
				action_override, override_reason, expires_at, created_by, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, 'allow', $7, $8, $9, $10, $10)
		`, overrideID, canonicalUUID, req.PolicyType,
			nullableString(tenantID), overrideOrgScope, toolSig,
			req.OverrideReason, expiresAt, userEmail, now)
		return execErr
	}); wrapErr != nil {
		log.Printf("override create: insert failed: %v", wrapErr)
		sendErrorResponse(w, "Failed to create override", http.StatusInternalServerError)
		return
	}

	// Invalidate cached step-gate decisions that would otherwise be served
	// stale. #1607 introduced idempotent retry semantics: workflow_steps is
	// a keyed cache, and a denied decision for policy P stays cached until
	// the caller opts into retry_policy=reevaluate. Without this hook, an
	// override created mid-session would be shadowed by the cached deny.
	// Scope: only the tenant+user who created the override, only denied
	// decisions (allow/approved decisions were never blocked by P), and only
	// workflow_steps whose policies_matched references this policy_id.
	invalidateCachedDeniedDecisions(r.Context(), usageDB, tenantID, userEmail, canonicalUUID)

	// Audit event.
	if auditLogger != nil {
		auditLogger.LogOverrideEvent(r.Context(), AuditEventOverrideCreated, &OverrideAuditEntry{
			OverrideID:    overrideID,
			PolicyIDs:     []string{req.PolicyID},
			TenantID:      tenantID,
			OrgID:         orgID,
			UserEmail:     userEmail,
			ToolSignature: req.ToolSignature,
			Reason:        req.OverrideReason,
			TTLSeconds:    int64(ttl.Seconds()),
			RequestedTTL:  req.TTLSeconds,
			Clamped:       clamped,
		})
	}

	resp := CreateOverrideResponse{
		ID:            overrideID,
		PolicyID:      req.PolicyID,
		PolicyType:    req.PolicyType,
		ExpiresAt:     expiresAt,
		TTLSeconds:    int64(ttl.Seconds()),
		RequestedTTL:  req.TTLSeconds,
		Clamped:       clamped,
		ClampedReason: clampReason,
		CreatedAt:     now,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// revokeOverrideHandler handles DELETE /api/v1/overrides/:id.
// Sets revoked_at + revoked_by on the override row.
// Emits override_revoked audit event.
func revokeOverrideHandler(w http.ResponseWriter, r *http.Request) {
	// #3076: the SAME guard createOverrideHandler opens with. Revoke keys
	// revoked_by on a per-user identity read from a client-assertable header,
	// and its per-user authorization (createdBy == scope.UserEmail, below)
	// keys on the same channel — so it belongs to the #2896 WS1b ingress class
	// even though the census that added the guard only named create.
	//
	// Since #3068 the whole orchestrator mux sits behind requireInternalProxyAuth,
	// so this is now the INNER of two layers rather than the only one, and the
	// asymmetry it removes is one of consistency: create carried both layers and
	// revoke carried one, for no stated reason. Keeping the pair identical is
	// what stops the next reader concluding the difference was deliberate.
	// Community mode with no configured secret is exempt inside the helper,
	// exactly as it is for create.
	if ok, msg := verifyAgentProxyAuth(r, "OverrideRevoke"); !ok {
		sendErrorResponse(w, msg, http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	overrideID := vars["id"]
	if overrideID == "" {
		sendErrorResponse(w, "Override id required", http.StatusBadRequest)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	orgID := r.Header.Get("X-Org-ID")
	revokedBy := r.Header.Get("X-User-Email")
	if revokedBy == "" {
		revokedBy = r.Header.Get("X-User-ID")
	}

	if revokedBy == "" {
		// #3062: same actionable body as create — revoke is the other half of
		// the lifecycle the plugins expose, and it failed the same opaque way.
		sendIdentityRequiredError(w, r, "policy overrides")
		return
	}
	if tenantID == "" {
		sendErrorResponse(w, "Tenant identity required (X-Tenant-ID header)", http.StatusBadRequest)
		return
	}

	// SECURITY: Scope the lookup to the caller's tenant so tenant A cannot
	// revoke tenant B's overrides even if A knows the UUID. Also confirms
	// the override belongs to the caller's tenant before any write.
	//
	// #3048: policy_overrides is RLS-enabled (mig 110, app.current_org_id) —
	// the bare read matched 0 rows under axonflow_app_role, so every revoke
	// 404'd before reaching the (already-scoped) UPDATE below. Same scope
	// key as that UPDATE.
	lookupScope := orgID
	if lookupScope == "" {
		lookupScope = tenantID
	}
	var policyID, createdBy string
	err := agent.WithOrgScope(r.Context(), usageDB, lookupScope, func(tx *sql.Tx) error {
		return tx.QueryRowContext(r.Context(),
			"SELECT policy_id, created_by FROM policy_overrides WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
			overrideID, tenantID,
		).Scan(&policyID, &createdBy)
	})
	if err == sql.ErrNoRows {
		sendErrorResponse(w, "Override not found or already revoked", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("override revoke: lookup failed: %v", err)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// #2922 (found by the #2923 census): revoke is per-user like the read —
	// a non-tenant-wide caller may revoke only overrides THEY created.
	// Previously any holder of the shared tenant credential could revoke any
	// user's override (a denial-of-service on a colleague's granted
	// exception). Same 404 as "no such id" (non-oracle). admin/owner may
	// revoke any override in the tenant.
	if scope := resolveCallerReadScope(r); !scope.TenantWide {
		if scope.UserEmail == "" ||
			sharedidentity.CanonicalEmail(createdBy) != scope.UserEmail {
			sendErrorResponse(w, "Override not found or already revoked", http.StatusNotFound)
			return
		}
	}

	now := time.Now().UTC()
	// SECURITY: Tenant-scoped UPDATE guards against race where tenant changes
	// between SELECT and UPDATE. Belt + suspenders.
	//
	// v9 Phase 8 PR-C2 (#2384) + mig 110: under axonflow_app_role + the
	// mig-110-normalized RLS policy, the UPDATE USING clause
	// `org_id = current_setting('app.current_org_id', true)` filters
	// to zero rows without the GUC set. Wrap before the UPDATE.
	revokeScope := orgID
	if revokeScope == "" {
		revokeScope = tenantID
	}
	if wrapErr := agent.WithOrgScope(r.Context(), usageDB, revokeScope, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(r.Context(),
			"UPDATE policy_overrides SET revoked_at = $1, revoked_by = $2, updated_at = $1, updated_by = $2 WHERE id = $3 AND tenant_id = $4",
			now, revokedBy, overrideID, tenantID,
		)
		return execErr
	}); wrapErr != nil {
		log.Printf("override revoke: update failed: %v", wrapErr)
		sendErrorResponse(w, "Failed to revoke override", http.StatusInternalServerError)
		return
	}

	if auditLogger != nil {
		auditLogger.LogOverrideEvent(r.Context(), AuditEventOverrideRevoked, &OverrideAuditEntry{
			OverrideID: overrideID,
			PolicyIDs:  []string{policyID},
			TenantID:   tenantID,
			OrgID:      orgID,
			UserEmail:  revokedBy,
			Reason:     "user_initiated",
			RevokedBy:  revokedBy,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         overrideID,
		"revoked_at": now,
	})
}

// getOverrideHandler handles GET /api/v1/overrides/:id.
// SECURITY: Scoped to the caller's tenant — does not leak override details
// across tenants.
func getOverrideHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	overrideID := vars["id"]
	if overrideID == "" {
		sendErrorResponse(w, "Override id required", http.StatusBadRequest)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		sendErrorResponse(w, "Tenant identity required (X-Tenant-ID header)", http.StatusBadRequest)
		return
	}

	type overrideRow struct {
		ID             string     `json:"id"`
		PolicyID       string     `json:"policy_id"`
		PolicyType     string     `json:"policy_type"`
		TenantID       *string    `json:"tenant_id,omitempty"`
		OrgID          *string    `json:"organization_id,omitempty"`
		ToolSignature  *string    `json:"tool_signature,omitempty"`
		OverrideReason string     `json:"override_reason"`
		ExpiresAt      *time.Time `json:"expires_at,omitempty"`
		CreatedBy      string     `json:"created_by"`
		CreatedAt      time.Time  `json:"created_at"`
		RevokedAt      *time.Time `json:"revoked_at,omitempty"`
		RevokedBy      *string    `json:"revoked_by,omitempty"`
	}

	// #3060 (#2991 coverage gap): stamped before the lookup so the header goes
	// out on both 404s this handler can produce — the non-oracle body cannot
	// distinguish "no such override" from "not yours".
	scope := resolveCallerReadScope(r)
	applyReadScopeHeader(w, r, scope)

	// #3048: org-scoped read — bare, this matched 0 rows under
	// axonflow_app_role (mig 110 RLS) and every override GET 404'd. Same
	// scope key convention as createOverrideHandler (X-Org-ID falling back
	// to tenant).
	getScope := r.Header.Get("X-Org-ID")
	if getScope == "" {
		getScope = tenantID
	}
	var row overrideRow
	err := agent.WithOrgScope(r.Context(), usageDB, getScope, func(tx *sql.Tx) error {
		return tx.QueryRowContext(r.Context(), `
			SELECT id, policy_id, policy_type, tenant_id, org_id, tool_signature,
			       override_reason, expires_at, created_by, created_at, revoked_at, revoked_by
			FROM policy_overrides WHERE id = $1 AND tenant_id = $2
		`, overrideID, tenantID).Scan(
			&row.ID, &row.PolicyID, &row.PolicyType, &row.TenantID, &row.OrgID,
			&row.ToolSignature, &row.OverrideReason, &row.ExpiresAt,
			&row.CreatedBy, &row.CreatedAt, &row.RevokedAt, &row.RevokedBy,
		)
	})
	if err == sql.ErrNoRows {
		sendErrorResponse(w, "Override not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("override get: query failed: %v", err)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// #2922 role-scoped reads: a non-tenant-wide caller may fetch only
	// overrides they created. Same 404 as "no such id" — not 403 — so the
	// endpoint is not a cross-user existence oracle.
	if !scope.TenantWide {
		if scope.UserEmail == "" ||
			sharedidentity.CanonicalEmail(row.CreatedBy) != scope.UserEmail {
			sendErrorResponse(w, "Override not found", http.StatusNotFound)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(row)
}

// listOverridesHandler handles GET /api/v1/overrides.
// Filters: policy_id (UUID or slug/name), tenant_id (header-driven),
// include_revoked (bool).
func listOverridesHandler(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	policyIDParam := r.URL.Query().Get("policy_id")
	includeRevoked := r.URL.Query().Get("include_revoked") == "true"

	// Accept either the UUID or the human-readable slug/name on the filter,
	// matching the createOverride semantic. Users who grab policy_id from
	// a block response's policy_matches[] should be able to pass that
	// straight through to listOverrides without a side-channel lookup.
	// On resolve error we fall back to the raw param so a transient DB hiccup
	// doesn't surface as "no overrides" to the caller — but log it so the
	// degradation is visible in the orchestrator logs.
	policyUUID := policyIDParam
	if policyIDParam != "" {
		if uuid, err := resolvePolicyUUID(r.Context(), usageDB, tenantID, policyIDParam); err != nil {
			log.Printf("override list: resolvePolicyUUID(%q) failed, using raw param: %v",
				policyIDParam, err)
		} else if uuid != "" {
			policyUUID = uuid
		}
	}

	if tenantID == "" {
		sendErrorResponse(w, "X-Tenant-ID header required", http.StatusBadRequest)
		return
	}

	// #2922 role-scoped reads: session overrides are per-user grants keyed to
	// created_by (ADR-044) — a non-tenant-wide caller lists only the overrides
	// THEY created; admin/owner list the tenant's. Empty identity ⇒ empty list
	// (fail-closed). Exact canonical match; the write path stores the same
	// identity this scope compares against (see createOverrideHandler).
	//
	// #3060 (#2991 coverage gap): stamp the scope so the empty list below is
	// self-diagnosing rather than a bare 200 {"overrides":[],"count":0}.
	scopeUserEmail := ""
	scope := resolveCallerReadScope(r)
	applyReadScopeHeader(w, r, scope)
	if !scope.TenantWide {
		if scope.UserEmail == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"overrides": []struct{}{},
				"count":     0,
			})
			return
		}
		scopeUserEmail = scope.UserEmail
	}

	// Dynamic predicate builder (replaces the former 4-branch switch, which
	// would have needed 8 branches with the scope predicate).
	query := `
		SELECT id, policy_id, policy_type, tenant_id, override_reason, expires_at, revoked_at, created_at
		FROM policy_overrides WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if policyUUID != "" {
		args = append(args, policyUUID)
		query += fmt.Sprintf(" AND policy_id::text = $%d", len(args))
	}
	if scopeUserEmail != "" {
		args = append(args, strings.ToLower(scopeUserEmail))
		query += fmt.Sprintf(" AND LOWER(created_by) = $%d", len(args))
	}
	if !includeRevoked {
		query += " AND revoked_at IS NULL"
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := usageDB.Query(query, args...)
	if err != nil {
		log.Printf("override list: query failed: %v", err)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type overrideSummary struct {
		ID             string     `json:"id"`
		PolicyID       string     `json:"policy_id"`
		PolicyType     string     `json:"policy_type"`
		TenantID       *string    `json:"tenant_id,omitempty"`
		OverrideReason string     `json:"override_reason"`
		ExpiresAt      *time.Time `json:"expires_at,omitempty"`
		RevokedAt      *time.Time `json:"revoked_at,omitempty"`
		CreatedAt      time.Time  `json:"created_at"`
	}

	out := make([]overrideSummary, 0, 32)
	for rows.Next() {
		var s overrideSummary
		if err := rows.Scan(&s.ID, &s.PolicyID, &s.PolicyType, &s.TenantID,
			&s.OverrideReason, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt); err != nil {
			log.Printf("override list: scan failed: %v", err)
			continue
		}
		out = append(out, s)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"overrides": out,
		"count":     len(out),
	})
}

// nullableString returns a sql.NullString that is Valid only if the input is non-empty.
func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// nullableUUID was deleted here by #3334.
//
// It existed for ONE caller: the policy_overrides INSERT, whose
// organization_id column was typed uuid until migration core/133 retyped it
// to text. AxonFlow org ids are free-form strings from a signed licence
// ("local-dev-org"), so binding one into a uuid column threw
// `pq: invalid input syntax for type uuid` - shipped as a hard 500 in 9.3.0 -
// and this helper silently wrote NULL instead of erroring.
//
// That is a coping mechanism for a column with the wrong type, and it has an
// edge no reader would predict: an org id that HAPPENS to be UUID-shaped was
// stored, while every other org id became NULL, so the column's population
// depended on how a customer chose to name their organisation. Migration
// core/166 drops the column; the INSERT now writes org_id, which has been
// VARCHAR since core/110 and needs no coercion.
//
// The unit tests that pinned its three branches went with it. They tested a
// helper, not a behaviour, and the behaviour they protected - a non-UUID org
// id must not 500 the override create path - is now a property of the schema
// rather than of a function that can be called from somewhere new.
