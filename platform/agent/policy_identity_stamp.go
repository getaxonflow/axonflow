// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"

	sharedaudit "axonflow/platform/shared/audit"
	sharedpolicy "axonflow/platform/shared/policy"
)

// Writer-side policy identity stamping (#3365).
//
// The shared reader contract (platform/shared/audit/policy_identity.go, #3306)
// resolves a display name from policy_details->'policy_names' (array) or
// ->'policy_matches[*].policy_name', and a version from ->'policy_versions'
// (map keyed by policy id). Until #3365, only the MCP static-block writer
// (buildExplainableAuditDetails) and the fincrime seam stamped names/versions;
// every other canonical writer stamped policy_ids alone, so no reader could
// ever render a display name for those rows (the portal shows raw ids with an
// explicit "(name not recorded)" marker, #3359).
//
// The rules here mirror the reader's fabrication discipline:
//   - A REAL policy's name comes only from the evaluation-time match
//     (sharedpolicy.PolicyMatch.PolicyName, carried by the engine from the row
//     it matched). It is NEVER minted from a write-time catalog lookup: a
//     rename between evaluation and write would stamp a name the evaluated
//     policy never carried.
//   - A code-backed guard id (circuit_breaker, rbi_kill_switch, ...) has no
//     static_policies row and therefore no evaluation-time name; its display
//     name is the code-defined constant below, compiled WITH the guard, so it
//     cannot drift from what actually fired.
//   - An id that is neither (an evaluation path that did not thread its match,
//     or a foreign id merged in later) stays unnamed; the reader's explicit
//     marker is the honest rendering.
//   - Versions have no evaluation-time source (CompiledPolicy/PolicyMatch
//     carry no version; the compile-path loader does not select the column),
//     so they use the established best-effort write-time batch lookup
//     (lookupPolicyVersionsByID, #1983/#3048) the MCP check-output plane
//     already relies on, and only for ids that do not already carry one (the
//     fincrime seam's model/pack versions must win, see MergeAuditDetails).

// builtinPolicyDisplayNames maps every code-backed guard id an agent writer
// stamps into policy_ids (no static_policies row exists for these) to its
// code-defined display name. Keep entries factual: they render in the portal's
// Policy column and the compliance exports, so each names the guard that
// fired, not the event outcome.
//
// An id absent from this table and from the evaluation-time match map is
// deliberately left unnamed rather than guessed.
var builtinPolicyDisplayNames = map[string]string{
	// Identity / authentication guards
	"tenant_impersonation":  "Tenant impersonation guard",
	"org_impersonation":     "Organization impersonation guard",
	"user_token_rejected":   "User token validation guard",
	"user_token_invalid":    "User token validation guard",
	"tenant_mismatch":       "Tenant isolation guard",
	"tenant_id_missing":     "Tenant identity guard",
	"unauthenticated":       "Authentication guard",
	"authentication_error":  "Authentication guard",
	"session_authz":         "Session authorization guard",
	"mcp_permission_denied": "MCP permission guard",
	"client_disabled":       "Client enablement guard",

	// Platform protection guards
	"circuit_breaker":            "Circuit breaker guard",
	"rbi_kill_switch":            "RBI kill switch",
	"budget_exceeded":            "Budget limit guard",
	"daily_cap":                  "Daily usage cap guard",
	"tier_gate":                  "Tier access gate",
	"exfiltration_limit":         "Exfiltration volume guard",
	"segment_resolution_failed":  "Governance segment resolution guard",
	"dynamic_policy_unavailable": "Dynamic policy availability guard",
	"content_type_unsupported":   "Content type guard",
	"connector_error":            "Connector execution guard",
	"tool_error":                 "Tool execution guard",
	readOnlyPosturePolicyID:      "MCP read-only posture",

	// Validator-backed detectors (code-backed, not static_policies rows)
	"indonesia_pii_protection": "Indonesia PII protection (validator)",
	"rbi_pii_protection":       "RBI India PII protection (validator)",
	"sqli_response_scan":       "SQL injection response scan",

	// Aggregate/fallback sentinels
	"dynamic_policy":  "Dynamic policy (aggregate)",
	"hitl_compliance": "HITL compliance gate",
	"hitl_enterprise": "HITL compliance gate",
}

// policyNamesFromMatches returns the evaluation-time id -> display-name map
// for the given matches. Entries with an empty id or empty name are skipped:
// an empty name must fall through to the builtin table / unnamed rendering,
// never occupy the map.
func policyNamesFromMatches(matches []sharedpolicy.PolicyMatch) map[string]string {
	if len(matches) == 0 {
		return nil
	}
	out := make(map[string]string, len(matches))
	for i := range matches {
		if matches[i].PolicyID != "" && matches[i].PolicyName != "" {
			// First match wins per id, mirroring the reader's
			// policy_matches precedence (extractVersion / liftPolicyVersions).
			if _, exists := out[matches[i].PolicyID]; !exists {
				out[matches[i].PolicyID] = matches[i].PolicyName
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// policyNamesFromDynamic is policyNamesFromMatches for the dynamic-policy
// evaluator's match shape.
func policyNamesFromDynamic(info *sharedpolicy.DynamicPolicyInfo) map[string]string {
	if info == nil || len(info.MatchedPolicies) == 0 {
		return nil
	}
	out := make(map[string]string, len(info.MatchedPolicies))
	for i := range info.MatchedPolicies {
		m := &info.MatchedPolicies[i]
		if m.PolicyID != "" && m.PolicyName != "" {
			if _, exists := out[m.PolicyID]; !exists {
				out[m.PolicyID] = m.PolicyName
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergePolicyNames unions src into dst (dst entries win) and returns the
// result; either side may be nil.
func mergePolicyNames(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for id, name := range src {
		if _, exists := dst[id]; !exists {
			dst[id] = name
		}
	}
	return dst
}

// stampPolicyIdentityNames is the ONE writer-side name stamp shared by every
// canonical policy_details builder (buildDecisionAuditDetails,
// buildMCPDecisionAuditDetails). It emits policy_names as a flat display list
// in policy_ids order: the evaluation-time name when the caller threaded one,
// else the code-defined builtin guard name, else nothing for that id. The key
// is omitted entirely when no id resolves a name, so ids-only rows keep the
// reader's explicit "(name not recorded)" rendering instead of gaining an
// empty array.
//
// policy_names is NOT index-parallel to policy_ids (established by #3347/#3359:
// merged rows already carry differently-ordered arrays, and the fincrime seam
// appends de-duplicated names) - readers must and do treat it as a display
// list, pairing versions through the id-keyed policy_versions map instead.
func stampPolicyIdentityNames(details map[string]interface{}, policyIDs []string, names map[string]string) {
	if len(policyIDs) == 0 {
		return
	}
	resolved := make([]string, 0, len(policyIDs))
	seen := make(map[string]bool, len(policyIDs))
	for _, id := range policyIDs {
		if id == "" {
			continue
		}
		name := names[id]
		if name == "" {
			name = builtinPolicyDisplayNames[id]
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		resolved = append(resolved, name)
	}
	if len(resolved) > 0 {
		details["policy_names"] = resolved
	}
}

// actedAuditVerdict reports whether verdict (raw or canonical spelling)
// normalizes to an ACTED outcome: blocked, redacted, or needs_approval. The
// version lookup below is gated on it so terminal ALLOW rows on the hot paths
// do not pay two RLS-scoped read transactions per request for a version that
// only compliance artifacts and the portal's acted-row rendering consume
// (R3 round 1 finding: the #1983 precedent was check-output-only; extending
// it unconditionally to every plane priced every allow write).
func actedAuditVerdict(verdict string) bool {
	switch sharedaudit.Normalize(verdict) {
	case sharedaudit.DecisionBlocked, sharedaudit.DecisionRedacted, sharedaudit.DecisionNeedsApproval:
		return true
	default:
		return false
	}
}

// stampMissingPolicyVersions attaches the id-keyed policy_versions map for the
// row's policy_ids, best-effort, adding entries ONLY for ids that do not
// already carry one. It runs AFTER fincrime.MergeAuditDetails on purpose: the
// seam stamps model/pack version STRINGS (e.g. the scorer model version) that
// must not be displaced by the static_policies row version this lookup
// returns. Builtin guard ids have no row and are excluded from the query.
// Callers gate it on actedAuditVerdict: allow rows carry names but no
// row-version lookup (the fincrime seam's ctx-stamped versions still land on
// them through the merge).
//
// Version values here are the CURRENT static_policies.version at write time,
// the same best-effort semantics the MCP check-output plane has used since
// #1983 (lookupPolicyVersionsByID: single ANY($1) round trip, RLS two-scope,
// DB errors degrade to no policy_versions rather than failing the write).
func stampMissingPolicyVersions(ctx context.Context, db *sql.DB, details map[string]interface{}) {
	if db == nil || details == nil {
		return
	}
	ids := normalizeStampIDList(details["policy_ids"])
	if len(ids) == 0 {
		return
	}
	existing := normalizeStampVersionMap(details["policy_versions"])
	missing := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, has := existing[id]; has {
			continue
		}
		if _, builtin := builtinPolicyDisplayNames[id]; builtin {
			continue
		}
		missing = append(missing, id)
	}
	if len(missing) == 0 {
		return
	}
	looked := lookupPolicyVersionsByID(ctx, db, missing)
	if len(looked) == 0 {
		return
	}
	if existing == nil {
		existing = make(map[string]interface{}, len(looked))
	}
	for id, v := range looked {
		if _, has := existing[id]; !has {
			existing[id] = v
		}
	}
	details["policy_versions"] = existing
}

// normalizeStampIDList coerces a policy_ids entry ([]string from the pure
// builders, []interface{} after a JSON round trip) into []string.
func normalizeStampIDList(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// normalizeStampVersionMap coerces an existing policy_versions entry into a
// merge-friendly map WITHOUT changing the value types the original writer used
// (buildExplainableAuditDetails writes map[string]int; the fincrime seam
// writes string model/pack versions). Returns nil when absent so the caller
// can distinguish "no map yet" from "empty map".
func normalizeStampVersionMap(v interface{}) map[string]interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		return t
	case map[string]int:
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			out[k] = e
		}
		return out
	case map[string]string:
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			out[k] = e
		}
		return out
	default:
		return nil
	}
}
