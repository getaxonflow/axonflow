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
)

// Override TTL bounds per ADR-044.
// These are hard platform-level constants. Plugins may suggest shorter TTLs;
// the platform clamps on create.
const (
	OverrideDefaultTTL  = 60 * time.Minute
	OverrideHardCapTTL  = 24 * time.Hour
	OverrideMinTTL      = 1 * time.Minute  // prevent zero/negative TTLs
	OverrideReasonMaxLn = 500              // cap free-text to prevent abuse
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
func policyRiskAndOverride(db *sql.DB, policyID, policyType string) (string, bool, error) {
	var table string
	switch policyType {
	case "static":
		table = "static_policies"
	case "dynamic":
		table = "dynamic_policies"
	default:
		return "", false, fmt.Errorf("invalid policy_type: %s", policyType)
	}

	//nolint:gosec // table name is validated via switch above; value side is parameterized.
	// Lookup by the UUID id column, since policy_overrides.policy_id is UUID-
	// typed and the caller identifies the policy by its stable UUID — not the
	// human-readable slug stored in static_policies.policy_id. The ::text cast
	// lets callers pass either the raw UUID string or a slug-style id; the
	// cast will fail (no rows) for non-UUID input, producing a clean 404.
	query := fmt.Sprintf("SELECT risk_level, allow_override FROM %s WHERE id::text = $1 LIMIT 1", table)
	var riskLevel string
	var allowOverride bool
	err := db.QueryRow(query, policyID).Scan(&riskLevel, &allowOverride)
	if err != nil {
		return "", false, err
	}
	return riskLevel, allowOverride, nil
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
func invalidateCachedDeniedDecisions(ctx context.Context, db *sql.DB, tenantID, userEmail, policyID string) {
	if db == nil || policyID == "" {
		return
	}
	if tenantID == "" && userEmail == "" {
		// Refuse to delete without at least one scoping dimension — we will
		// not invalidate across the whole table.
		return
	}

	// Scope by workflows owned by this tenant/user. Match policy_id either in
	// policies_matched (array of PolicyMatch rows) or policies_evaluated (for
	// require_approval decisions where the blocking rule lives there).
	// @> is JSONB containment — the array contains an element with this id.
	result, err := db.ExecContext(ctx, `
		DELETE FROM workflow_steps
		WHERE id IN (
			SELECT ws.id
			FROM workflow_steps ws
			JOIN workflows w ON ws.workflow_id = w.workflow_id
			WHERE ($1 = '' OR w.tenant_id = $1)
			  AND ($2 = '' OR w.user_id = $2)
			  AND ws.decision IN ('block', 'require_approval')
			  AND (
			    ws.policies_matched @> jsonb_build_array(jsonb_build_object('policy_id', $3::text))
			    OR ws.policies_evaluated @> jsonb_build_array(jsonb_build_object('policy_id', $3::text))
			  )
		)
	`, tenantID, userEmail, policyID)
	if err != nil {
		log.Printf("override create: cache invalidation failed (tenant=%s user=%s policy=%s): %v",
			tenantID, userEmail, policyID, err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("override create: invalidated %d cached denied decisions for policy=%s", n, policyID)
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
	if userEmail == "" {
		sendErrorResponse(w, "Authenticated user identity required (X-User-Email header)", http.StatusUnauthorized)
		return
	}
	if tenantID == "" {
		sendErrorResponse(w, "Tenant identity required (X-Tenant-ID header)", http.StatusBadRequest)
		return
	}

	// ADR-044: critical risk policies cannot be overridden.
	riskLevel, allowOverride, err := policyRiskAndOverride(usageDB, req.PolicyID, req.PolicyType)
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

	//nolint:gosec // values are parameterized
	_, err = usageDB.Exec(`
		INSERT INTO policy_overrides (
			id, policy_id, policy_type, organization_id, tenant_id, tool_signature,
			action_override, override_reason, expires_at, created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'allow', $7, $8, $9, $10, $10)
	`, overrideID, req.PolicyID, req.PolicyType,
		nullableUUID(orgID), nullableString(tenantID), toolSig,
		req.OverrideReason, expiresAt, userEmail, now)
	if err != nil {
		log.Printf("override create: insert failed: %v", err)
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
	invalidateCachedDeniedDecisions(r.Context(), usageDB, tenantID, userEmail, req.PolicyID)

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
		sendErrorResponse(w, "Authenticated user identity required (X-User-Email header)", http.StatusUnauthorized)
		return
	}
	if tenantID == "" {
		sendErrorResponse(w, "Tenant identity required (X-Tenant-ID header)", http.StatusBadRequest)
		return
	}

	// SECURITY: Scope the lookup to the caller's tenant so tenant A cannot
	// revoke tenant B's overrides even if A knows the UUID. Also confirms
	// the override belongs to the caller's tenant before any write.
	var policyID string
	err := usageDB.QueryRow(
		"SELECT policy_id FROM policy_overrides WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
		overrideID, tenantID,
	).Scan(&policyID)
	if err == sql.ErrNoRows {
		sendErrorResponse(w, "Override not found or already revoked", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("override revoke: lookup failed: %v", err)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	// SECURITY: Tenant-scoped UPDATE guards against race where tenant changes
	// between SELECT and UPDATE. Belt + suspenders.
	_, err = usageDB.Exec(
		"UPDATE policy_overrides SET revoked_at = $1, revoked_by = $2, updated_at = $1, updated_by = $2 WHERE id = $3 AND tenant_id = $4",
		now, revokedBy, overrideID, tenantID,
	)
	if err != nil {
		log.Printf("override revoke: update failed: %v", err)
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

	var row overrideRow
	err := usageDB.QueryRow(`
		SELECT id, policy_id, policy_type, tenant_id, organization_id, tool_signature,
		       override_reason, expires_at, created_by, created_at, revoked_at, revoked_by
		FROM policy_overrides WHERE id = $1 AND tenant_id = $2
	`, overrideID, tenantID).Scan(
		&row.ID, &row.PolicyID, &row.PolicyType, &row.TenantID, &row.OrgID,
		&row.ToolSignature, &row.OverrideReason, &row.ExpiresAt,
		&row.CreatedBy, &row.CreatedAt, &row.RevokedAt, &row.RevokedBy,
	)
	if err == sql.ErrNoRows {
		sendErrorResponse(w, "Override not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("override get: query failed: %v", err)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(row)
}

// listOverridesHandler handles GET /api/v1/overrides.
// Filters: policy_id, tenant_id (header-driven), include_revoked (bool).
func listOverridesHandler(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	policyID := r.URL.Query().Get("policy_id")
	includeRevoked := r.URL.Query().Get("include_revoked") == "true"

	var rows *sql.Rows
	var err error
	switch {
	case policyID != "" && tenantID != "":
		if includeRevoked {
			rows, err = usageDB.Query(`
				SELECT id, policy_id, policy_type, tenant_id, override_reason, expires_at, revoked_at, created_at
				FROM policy_overrides WHERE policy_id = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT 100
			`, policyID, tenantID)
		} else {
			rows, err = usageDB.Query(`
				SELECT id, policy_id, policy_type, tenant_id, override_reason, expires_at, revoked_at, created_at
				FROM policy_overrides WHERE policy_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
				ORDER BY created_at DESC LIMIT 100
			`, policyID, tenantID)
		}
	case tenantID != "":
		if includeRevoked {
			rows, err = usageDB.Query(`
				SELECT id, policy_id, policy_type, tenant_id, override_reason, expires_at, revoked_at, created_at
				FROM policy_overrides WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100
			`, tenantID)
		} else {
			rows, err = usageDB.Query(`
				SELECT id, policy_id, policy_type, tenant_id, override_reason, expires_at, revoked_at, created_at
				FROM policy_overrides WHERE tenant_id = $1 AND revoked_at IS NULL
				ORDER BY created_at DESC LIMIT 100
			`, tenantID)
		}
	default:
		sendErrorResponse(w, "X-Tenant-ID header required", http.StatusBadRequest)
		return
	}
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

// nullableUUID returns a sql.NullString holding the input only if it parses
// as a UUID. Non-UUID identifiers (e.g. community-mode slugs like
// "local-dev-org") return an invalid NullString so the driver inserts NULL
// rather than erroring with "invalid input syntax for type uuid".
func nullableUUID(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	if _, err := uuid.Parse(s); err != nil {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
