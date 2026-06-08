// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// DecisionExplanation is the canonical payload returned by
// GET /api/v1/decisions/:id/explain. Shape frozen per ADR-043.
// Additive fields may be added with omitempty; renames/removals require
// a major version bump.
type DecisionExplanation struct {
	DecisionID                string          `json:"decision_id"`
	Timestamp                 time.Time       `json:"timestamp"`
	PolicyMatches             []ExplainPolicy `json:"policy_matches"`
	MatchedRules              []ExplainRule   `json:"matched_rules,omitempty"`
	Decision                  string          `json:"decision"` // "allow"|"deny"|"require_approval"
	Reason                    string          `json:"reason"`
	RiskLevel                 string          `json:"risk_level,omitempty"`
	OverrideAvailable         bool            `json:"override_available"`
	OverrideExistingID        string          `json:"override_existing_id,omitempty"`
	HistoricalHitCountSession int             `json:"historical_hit_count_session"`
	PolicySourceLink          string          `json:"policy_source_link,omitempty"`
	ToolSignature             string          `json:"tool_signature,omitempty"`

	// V1.1 forensic fields (ADR-043 amendment 2026-05-07). Both fields
	// are scoped to the FIRST matched policy. Both `omitempty` so pre-V1.1
	// audit rows + decisions that fired on dynamic policies (no version
	// surface) keep the original payload byte-shape.
	//
	// PolicyVersionAtDecision: the version of the matched policy that was
	// applied when this decision was made. Read from
	// `policy_details.policy_versions[first_match.policy_id]` which α1
	// (commit 8aae2e1f3) populates at decision-write time. 0 = unrecorded
	// (pre-α1 audit row OR dynamic-policy decision).
	//
	// LatestPolicyVersion: the current head of `static_policy_versions`
	// for the same policy_id. Lookup happens at explain-time. Lets the
	// caller answer "is this still the current policy, or has it been
	// updated since?" without a second round-trip.
	PolicyVersionAtDecision int `json:"policy_version_at_decision,omitempty"`
	LatestPolicyVersion     int `json:"latest_policy_version,omitempty"`

	// Context is the FULL sanitized request context the PEP attached to the
	// decision (canonical snake_case keys, string values), read from
	// policy_details->'context'. Unlike the LIST endpoint (which truncates to
	// 5 keys), the explain endpoint returns every persisted key (up to the
	// agent's 10-key cap) so an auditor gets the complete correlation set
	// (X-AI-Agent / X-Session-ID / X-Leader-Identity, x-tenant-*).
	// ContextTruncated reflects whether the agent dropped surplus keys at
	// write time. Both omitempty so pre-#2509 rows keep their byte-shape.
	// (#2509 / epic #2508)
	Context          map[string]string `json:"context,omitempty"`
	ContextTruncated bool              `json:"context_truncated,omitempty"`
}

// ExplainPolicy is a policy reference returned inside an explanation.
type ExplainPolicy struct {
	PolicyID          string `json:"policy_id"`
	PolicyName        string `json:"policy_name,omitempty"`
	Action            string `json:"action,omitempty"`
	RiskLevel         string `json:"risk_level,omitempty"`
	AllowOverride     bool   `json:"allow_override,omitempty"`
	PolicyDescription string `json:"policy_description,omitempty"`
}

// ExplainRule is the rule-level detail for an explanation.
type ExplainRule struct {
	PolicyID  string `json:"policy_id"`
	RuleID    string `json:"rule_id,omitempty"`
	RuleText  string `json:"rule_text,omitempty"`
	MatchedOn string `json:"matched_on,omitempty"`
}

// sessionHitCountWindow is how far back we count "historical hits for this
// rule this session" (ADR-043). Rolling 24h.
const sessionHitCountWindow = 24 * time.Hour

// explainDecisionHandler handles GET /api/v1/decisions/:id/explain.
// Looks up the audit record by decision_id, builds a DecisionExplanation.
func explainDecisionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	decisionID := strings.TrimSpace(vars["id"])
	if decisionID == "" {
		sendErrorResponse(w, "decision_id required", http.StatusBadRequest)
		return
	}

	callerEmail := r.Header.Get("X-User-Email")
	if callerEmail == "" {
		callerEmail = r.Header.Get("X-User-ID")
	}
	callerTenant := r.Header.Get("X-Tenant-ID")
	if callerTenant == "" {
		// Fail closed (#1623 retro): without a trusted tenant scope on the
		// request, post-fetch authorization could be bypassed by simply
		// omitting the header — the entryUserEmail==callerEmail short-circuit
		// would also pass for an attacker spoofing X-User-Email. Require the
		// header explicitly; the AxonFlow Agent gateway always sets it after
		// authentication.
		sendErrorResponse(w, "X-Tenant-ID header is required", http.StatusUnauthorized)
		return
	}

	// Look up the audit entry by (decision_id, tenant_id). Filtering tenant in
	// the SELECT makes cross-tenant reads structurally impossible — earlier
	// the WHERE was decision_id only and authorization was a post-fetch
	// comparison, which silently failed open whenever entryUserEmail was NULL
	// (no .Valid skip path) or whenever the same email existed across tenants.
	// policy_details JSONB contains decision_id; we use a functional index.
	// The reason string is kept inside policy_details → reason, not a direct
	// audit_logs column, so the SELECT list has five projections and the
	// reason is parsed out of the details JSON below.
	var (
		entryUserEmail sql.NullString
		entryTenant    sql.NullString
		entryTime      time.Time
		entryDecision  sql.NullString
		entryDetails   sql.NullString // policy_details JSON
	)

	err := usageDB.QueryRow(`
		SELECT user_email, tenant_id, timestamp, policy_decision, policy_details
		FROM audit_logs
		WHERE policy_details->>'decision_id' = $1
		  AND tenant_id = $2
		ORDER BY timestamp DESC LIMIT 1
	`, decisionID, callerTenant).Scan(&entryUserEmail, &entryTenant, &entryTime,
		&entryDecision, &entryDetails)

	if err == sql.ErrNoRows {
		// 404 (rather than 403) so the response shape is identical for
		// "decision doesn't exist in your tenant" and "decision exists in a
		// different tenant" — denies an enumeration oracle.
		sendErrorResponse(w, "Decision not found or past retention window", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("explain decision: lookup failed: %v", err)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Per-user authorization within the tenant: a caller can explain only their
	// own decisions, or any decision in the same tenant if they're a peer.
	// (Admin authz is deferred to a dedicated policy adapter.) The SELECT above
	// already guarantees same-tenant; this block is the additional within-
	// tenant scoping. Defense in depth: also reject if entryTenant somehow
	// disagrees with callerTenant (should be impossible after the WHERE clause,
	// but guards against a future SELECT change).
	if entryTenant.Valid && entryTenant.String != callerTenant {
		log.Printf("explain decision: SELECT/auth mismatch: entry_tenant=%q caller_tenant=%q",
			entryTenant.String, callerTenant)
		sendErrorResponse(w, "Not authorized to explain this decision", http.StatusForbidden)
		return
	}
	if entryUserEmail.Valid && entryUserEmail.String != callerEmail {
		// Different user inside the same tenant — for now treat as allowed
		// (peer visibility within a tenant is the existing contract).
		// Hook for stricter future enforcement: enforce here when the policy
		// adapter is wired.
		_ = entryUserEmail.String
	}

	// Parse policy_details JSON.
	var details map[string]interface{}
	if entryDetails.Valid {
		_ = json.Unmarshal([]byte(entryDetails.String), &details)
	}

	// Reason lives in policy_details.reason rather than a direct column.
	var reasonStr string
	if details != nil {
		if r, ok := details["reason"].(string); ok {
			reasonStr = r
		}
	}

	exp := buildExplanation(decisionID, entryTime,
		entryDecision.String, reasonStr, details)

	// Historical hit count for same (policy_id, user_email) in rolling 24h.
	exp.HistoricalHitCountSession = queryHistoricalHitCount(callerEmail, exp.PolicyMatches, entryTime)

	// V1.1: latest_policy_version. Single-row lookup against the FIRST
	// matched policy_id; matches the same "first match" anchoring rule
	// buildExplanation() uses for PolicyVersionAtDecision. Lookup is
	// deliberately separate from buildExplanation() because it touches the
	// DB and buildExplanation() is exposed for unit tests with table-driven
	// inputs that should NOT need a DB roundtrip. Failure is silent (logged,
	// returns 0 → omitempty); explain still returns the recorded version
	// even if the latest cannot be resolved.
	if len(exp.PolicyMatches) > 0 {
		exp.LatestPolicyVersion = queryLatestPolicyVersion(exp.PolicyMatches[0].PolicyID)
	}

	// Check for existing active override (drives override_available).
	// Pass the decision's tool_signature so override lookup matches the same
	// tool-scoped precedence as FindActiveOverride / ApplyOverrideToResult —
	// otherwise explain could surface an override scoped to tool A when the
	// user asks about a decision for tool B, which would be stricter than
	// runtime enforcement and mislead the unblock UX (reviewer-caught).
	exp.OverrideAvailable, exp.OverrideExistingID = checkOverrideAvailability(
		callerTenant, callerEmail, exp.ToolSignature, exp.PolicyMatches,
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exp)
}

// buildExplanation constructs a DecisionExplanation from a raw audit entry.
// Exposed for testing.
func buildExplanation(decisionID string, ts time.Time,
	decision, reason string, details map[string]interface{}) DecisionExplanation {

	exp := DecisionExplanation{
		DecisionID: decisionID,
		Timestamp:  ts,
		Decision:   decision,
		Reason:     reason,
	}

	if details == nil {
		exp.PolicyMatches = []ExplainPolicy{}
		return exp
	}

	if toolSig, ok := details["tool_signature"].(string); ok {
		exp.ToolSignature = toolSig
	}
	if risk, ok := details["risk_level"].(string); ok {
		exp.RiskLevel = risk
	}

	// Surface the FULL persisted request context (#2509). policy_details
	// JSON unmarshals string values as interface{}; coerce each to string
	// and drop non-string entries defensively (the agent only ever writes
	// strings, but explain must not panic on a hand-edited row).
	if rawCtx, ok := details["context"].(map[string]interface{}); ok && len(rawCtx) > 0 {
		ctx := make(map[string]string, len(rawCtx))
		for k, v := range rawCtx {
			if s, ok := v.(string); ok {
				ctx[k] = s
			}
		}
		if len(ctx) > 0 {
			exp.Context = ctx
		}
	}
	if truncated, ok := details["context_truncated"].(bool); ok {
		exp.ContextTruncated = truncated
	}

	// Extract policy_matches if present.
	if rawMatches, ok := details["policy_matches"].([]interface{}); ok {
		exp.PolicyMatches = make([]ExplainPolicy, 0, len(rawMatches))
		for _, raw := range rawMatches {
			m, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			ep := ExplainPolicy{}
			if v, ok := m["policy_id"].(string); ok {
				ep.PolicyID = v
			}
			if v, ok := m["policy_name"].(string); ok {
				ep.PolicyName = v
			}
			if v, ok := m["action"].(string); ok {
				ep.Action = v
			}
			if v, ok := m["risk_level"].(string); ok {
				ep.RiskLevel = v
			}
			if v, ok := m["allow_override"].(bool); ok {
				ep.AllowOverride = v
			}
			if v, ok := m["policy_description"].(string); ok {
				ep.PolicyDescription = v
			}
			exp.PolicyMatches = append(exp.PolicyMatches, ep)
		}
	} else {
		exp.PolicyMatches = []ExplainPolicy{}
	}

	// Fallback: if no structured matches but policy_ids present, surface IDs.
	if len(exp.PolicyMatches) == 0 {
		if ids, ok := details["policy_ids"].([]interface{}); ok {
			for _, id := range ids {
				if s, ok := id.(string); ok {
					exp.PolicyMatches = append(exp.PolicyMatches, ExplainPolicy{PolicyID: s})
				}
			}
		}
	}

	// V1.1: extract the first matched policy's version-at-decision-time from
	// the top-level `policy_versions` map α1 stores in policy_details. Use
	// the FIRST match because that's the same scope rule the rest of the
	// payload uses (HistoricalHitCountSession, override availability, etc.
	// all anchor on PolicyMatches[0]). For pre-α1 audit rows the key is
	// absent and the field stays at 0 → omitempty drops it from the JSON.
	if len(exp.PolicyMatches) > 0 {
		firstID := exp.PolicyMatches[0].PolicyID
		if firstID != "" {
			if pv, ok := details["policy_versions"].(map[string]interface{}); ok {
				if rawVer, present := pv[firstID]; present {
					// JSON numbers unmarshal as float64 through interface{};
					// cast and round.
					switch v := rawVer.(type) {
					case float64:
						exp.PolicyVersionAtDecision = int(v)
					case int:
						exp.PolicyVersionAtDecision = v
					}
				}
			}
		}
	}

	return exp
}

// queryLatestPolicyVersion returns the highest version number for the given
// policy_id in `static_policy_versions`. Returns 0 (and logs) on any error,
// including the row-not-found case (e.g. dynamic-only policy or policy
// deleted since the decision). 0 is omitempty in the response, so the
// caller surfaces "no latest version available" by absence rather than a
// zero value the consumer has to special-case.
func queryLatestPolicyVersion(policyID string) int {
	if policyID == "" {
		return 0
	}
	var version int
	err := usageDB.QueryRow(`
		SELECT version FROM static_policy_versions
		WHERE policy_id = $1
		ORDER BY version DESC
		LIMIT 1
	`, policyID).Scan(&version)
	if err == sql.ErrNoRows {
		return 0
	}
	if err != nil {
		log.Printf("explain decision: latest_policy_version lookup failed for %q: %v", policyID, err)
		return 0
	}
	return version
}

// queryHistoricalHitCount returns how many times the same (policy_id,
// user_email) combination appeared in audit_logs within the session window.
func queryHistoricalHitCount(userEmail string, matches []ExplainPolicy, anchorTime time.Time) int {
	if userEmail == "" || len(matches) == 0 {
		return 0
	}
	windowStart := anchorTime.Add(-sessionHitCountWindow)

	policyID := matches[0].PolicyID
	if policyID == "" {
		return 0
	}

	// Count audit entries in the window where policy_details.policy_ids
	// contains this exact policy_id. Uses the JSONB containment operator
	// (@>) instead of string LIKE — LIKE would have matched "pol-1" against
	// records containing "pol-10", which is wrong.
	var count int
	err := usageDB.QueryRow(`
		SELECT COUNT(*) FROM audit_logs
		WHERE user_email = $1
		  AND timestamp >= $2
		  AND (
		        policy_details->'policy_ids' @> to_jsonb($3::text)
		        OR policy_details->>'policy_id' = $3
		      )
	`, userEmail, windowStart, policyID).Scan(&count)
	if err != nil {
		log.Printf("historical hit count: query failed: %v", err)
		return 0
	}
	return count
}

// checkOverrideAvailability returns (available, existing_override_id) for
// the given caller, tool signature, and policy matches. Override is available
// if at least one match has allow_override=true AND risk_level != critical.
//
// toolSignature is the tool the decision was scoped to (may be empty if the
// decision had no tool context). Lookup follows the same scope rules as
// FindActiveOverride / ApplyOverrideToResult (ADR-044): tool-specific
// override wins over tool-agnostic when both exist for the same policy;
// when the decision has no tool context, only tool-agnostic overrides match.
func checkOverrideAvailability(tenantID, userEmail, toolSignature string, matches []ExplainPolicy) (bool, string) {
	if userEmail == "" || len(matches) == 0 {
		return false, ""
	}
	any := false
	for _, m := range matches {
		if m.RiskLevel != "critical" && m.AllowOverride {
			any = true
			break
		}
	}
	if !any {
		return false, ""
	}

	// Look for existing active override for first overridable match,
	// applying the same scope rules as runtime enforcement.
	for _, m := range matches {
		if m.RiskLevel == "critical" || !m.AllowOverride {
			continue
		}
		var id string
		err := usageDB.QueryRow(`
			SELECT id FROM policy_overrides
			WHERE policy_id = $1 AND created_by = $2 AND tenant_id = $3
			  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())
			  AND (tool_signature IS NULL OR tool_signature = $4)
			ORDER BY
			  CASE WHEN tool_signature = $4 AND $4 <> '' THEN 0
			       WHEN tool_signature IS NULL THEN 1
			       ELSE 2 END,
			  created_at DESC
			LIMIT 1
		`, m.PolicyID, userEmail, tenantID, toolSignature).Scan(&id)
		if err == nil {
			return true, id
		}
	}
	return true, ""
}
