// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"log"
	"time"

	"axonflow/platform/agent"
)

// ActiveOverride represents a single row from policy_overrides matched
// against a (user, tenant, policy, tool) scope at a specific moment.
type ActiveOverride struct {
	ID            string
	PolicyID      string
	PolicyType    string
	ToolSignature string // empty if override is not tool-scoped
	Reason        string
	ExpiresAt     *time.Time
}

// FindActiveOverride queries policy_overrides for a non-revoked, non-expired
// override matching the given scope. Returns (nil, nil) if none found.
// An override is a match when:
//   - revoked_at IS NULL
//   - expires_at IS NULL OR expires_at > NOW()
//   - created_by = userEmail
//   - tenant_id = tenantID (or NULL)
//   - policy_id = policyID
//   - tool_signature IS NULL OR matches toolSignature
//
// scopeOrg is the RLS scope key for the lookup (#3048 R3 HIGH-3): the
// caller's validated org when known, else the org_id==tenant_id identity.
// Override rows are stamped with createOverrideHandler's X-Org-ID-else-tenant
// key, so the same precedence applies here.
func FindActiveOverride(ctx context.Context, db *sql.DB, scopeOrg, tenantID, userEmail, policyID, toolSignature string) (*ActiveOverride, error) {
	if db == nil || userEmail == "" || policyID == "" {
		return nil, nil
	}

	// ADR-044 scope: tool-agnostic override (tool_signature IS NULL) matches any
	// tool call; tool-specific override (tool_signature = $4) matches only that
	// tool. When caller has no tool context ($4 = ''), only tool-agnostic
	// overrides match — a tool-scoped override shouldn't silently apply to a
	// non-tool step. ORDER BY prefers exact-tool match over tool-agnostic.
	//
	// #3048: policy_overrides is RLS-enabled (mig 110, app.current_org_id) —
	// the bare read matched 0 rows under axonflow_app_role, so an active
	// ADR-044 session override silently stopped flipping denies.
	if scopeOrg == "" {
		scopeOrg = tenantID
	}
	var ov ActiveOverride
	err := agent.WithOrgScope(ctx, db, scopeOrg, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
		SELECT id, policy_id, policy_type, COALESCE(tool_signature, ''), override_reason, expires_at
		FROM policy_overrides
		WHERE policy_id = $1
		  AND created_by = $2
		  AND (tenant_id = $3 OR tenant_id IS NULL)
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())
		  AND (tool_signature IS NULL OR tool_signature = $4)
		  -- ADR-044 allow-flip applies ONLY to session "allow" overrides.
		  -- policy_overrides is shared with action-overrides (agent static
		  -- warn/block/redact, and any future dynamic action-override), which must
		  -- NOT be mistaken for an allow-bypass — that would let a *tightening*
		  -- override (e.g. block) silently flip a deny to allow. createOverrideHandler
		  -- writes action_override='allow' for the session-override path; scope the
		  -- match to that (or a legacy NULL) so action-overrides never grant bypass.
		  AND (action_override IS NULL OR action_override = 'allow')
		ORDER BY
		  CASE WHEN tool_signature = $4 AND $4 <> '' THEN 0
		       WHEN tool_signature IS NULL THEN 1
		       ELSE 2 END,
		  created_at DESC
		LIMIT 1
	`, policyID, userEmail, tenantID, toolSignature).Scan(
			&ov.ID, &ov.PolicyID, &ov.PolicyType, &ov.ToolSignature, &ov.Reason, &ov.ExpiresAt)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ov, nil
}

// ApplyOverrideToResult attempts to apply a session override to a denied
// policy evaluation result. Returns (applied, override) — applied is true
// when the override flipped Allowed from false to true.
//
// Rules (ADR-044):
//   - Only applies when result.Allowed is false (otherwise no-op).
//   - Only applies when at least one matched policy has risk_level != critical
//     AND allow_override == true. Critical-risk or non-overridable policies
//     short-circuit the flip.
//   - Looks up the first overridable policy's active override by
//     (tenant, user, policy, tool). First match wins.
//   - On apply: sets OverrideApplied/OverrideID/OverrideReason on result,
//     flips Allowed to true, emits override_used audit event.
func ApplyOverrideToResult(
	ctx context.Context,
	db *sql.DB,
	logger *AuditLogger,
	result *PolicyEvaluationResult,
	tenantID, orgID, userEmail, toolSignature string,
) (bool, *ActiveOverride) {
	if result == nil || result.Allowed {
		return false, nil
	}
	if userEmail == "" {
		return false, nil
	}

	for _, p := range result.AppliedPoliciesDetail {
		if p.RiskLevel == "critical" || !p.AllowOverride {
			continue
		}

		ov, err := FindActiveOverride(ctx, db, orgID, tenantID, userEmail, p.PolicyID, toolSignature)
		if err != nil {
			log.Printf("override enforcement: lookup failed for policy=%s: %v", p.PolicyID, err)
			continue
		}
		if ov == nil {
			continue
		}

		// Flip the decision.
		result.Allowed = true
		result.OverrideApplied = true
		result.OverrideID = ov.ID
		result.OverrideReason = ov.Reason

		// Emit override_used audit event per ADR-044.
		if logger != nil {
			logger.LogOverrideEvent(ctx, AuditEventOverrideUsed, &OverrideAuditEntry{
				OverrideID:    ov.ID,
				PolicyIDs:     []string{p.PolicyID},
				TenantID:      tenantID,
				OrgID:         orgID,
				UserEmail:     userEmail,
				ToolSignature: toolSignature,
				Reason:        ov.Reason,
			})
		}

		return true, ov
	}

	return false, nil
}

// SelectOverridablePolicy returns the first policy in the list whose
// risk_level is not critical and allow_override is true, or nil if none
// qualify. Exposed for testing and for the explain handler.
func SelectOverridablePolicy(policies []AppliedPolicyDetail) *AppliedPolicyDetail {
	for i, p := range policies {
		if p.RiskLevel != "critical" && p.AllowOverride {
			return &policies[i]
		}
	}
	return nil
}
