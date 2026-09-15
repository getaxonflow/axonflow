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
//     already relies on, and only for ids that do not already carry one: a
//     version the writer recorded is never overwritten.

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
	"circuit_breaker":           "Circuit breaker guard",
	"rbi_kill_switch":           "RBI kill switch",
	"budget_exceeded":           "Budget limit guard",
	"daily_cap":                 "Daily usage cap guard",
	"tier_gate":                 "Tier access gate",
	"exfiltration_limit":        "Exfiltration volume guard",
	"segment_resolution_failed": "Governance segment resolution guard",
	// #3430: distinct from the guard above - resolution did not FAIL, there
	// was no per-user principal to resolve against while segment-scoped
	// policies exist. Different operator remedy, so a different name.
	"segment_identity_unresolved": "Governance segment identity guard",
	"dynamic_policy_unavailable":  "Dynamic policy availability guard",
	"content_type_unsupported":    "Content type guard",
	"connector_error":             "Connector execution guard",
	"tool_error":                  "Tool execution guard",
	readOnlyPosturePolicyID:       "MCP read-only posture",

	// Validator-backed detectors (code-backed, not static_policies rows)
	"indonesia_pii_protection": "Indonesia PII protection (validator)",
	"rbi_pii_protection":       "RBI India PII protection (validator)",
	"sqli_response_scan":       "SQL injection response scan",

	// Aggregate/fallback sentinels
	"dynamic_policy":  "Dynamic policy (aggregate)",
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

// PolicyIdentity is one matched policy as a typed decision names it on the wire
// beside evaluated_policies, and on the audit row (PRD v11 §1.14, #4127): its
// id, its own display name where it has one, whose it is (shipped,
// organization or pack), and - for an organization's own policy or an
// installed pack's - the version it was published at. A shipped control has no
// version: the bundle digest the wire and the row carry identifies it.
type PolicyIdentity struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Source  string `json:"source,omitempty"`
	Version int    `json:"version,omitempty"`
}

// alignPolicyIdentities orders identities as ids, the response's final
// evaluated_policies, entry for entry: hoisting the blocking policy to the
// front (hoistBlockingPolicy) can move or add an id. An id the seam did not
// name - a checksum validator's (#4122) - is named by its identifier alone.
func alignPolicyIdentities(ids []string, identities []PolicyIdentity) []PolicyIdentity {
	if len(ids) == 0 {
		return nil
	}
	byID := make(map[string]PolicyIdentity, len(identities))
	for _, p := range identities {
		byID[p.ID] = p
	}
	out := make([]PolicyIdentity, 0, len(ids))
	for _, id := range ids {
		p, ok := byID[id]
		if !ok {
			p = PolicyIdentity{ID: id}
		}
		out = append(out, p)
	}
	return out
}

// carryAnchoredIdentity puts on this row what the anchored engine named: each
// matched policy's display name, source and published version, the
// organization document's version, and the action's name. It REPLACES any
// display names threaded from the shared engine's evaluation: those map that
// engine's ids, and the ids this row records are the anchored decision's, so
// keeping them would caption one engine's verdict with another's names.
func (a *decisionAuditInput) carryAnchoredIdentity(enforced requestPassEnforcement) {
	a.policyNames = policyIdentityNames(enforced.policyIdentities)
	a.policyIdentities, a.documentVersion, a.actionName = enforced.policyIdentities, enforced.documentVersion, enforced.actionName
}

// policyIdentityNames maps each identity that carries a display name to it, nil
// when none does: the one source of the names an anchored decision's rows and
// bodies give its policies.
func policyIdentityNames(identities []PolicyIdentity) map[string]string {
	var out map[string]string
	for _, p := range identities {
		if p.Name == "" {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[p.ID] = p.Name
	}
	return out
}

// stampAnchoredIdentity writes what an anchored decision named onto its row,
// for the row's own policy_ids (PRD v11 §1.14): whose each is at
// policy_sources, and into the id-keyed policy_versions the version an
// organization's own policy or a pack's was published at. A shipped control
// gets no version; the row's policy_bundle identifies it. Beside them, the
// active organization document's version at document_version and the requested
// action's display name at action_name. An entry already on the row wins, and
// the writers run it before stampMissingPolicyVersions, whose static_policies
// lookup fills only an id that carries no version.
func stampAnchoredIdentity(details map[string]interface{}, identities []PolicyIdentity, documentVersion int, actionName string) {
	if details == nil {
		return
	}
	onRow := map[string]bool{}
	for _, id := range normalizeStampIDList(details["policy_ids"]) {
		onRow[id] = true
	}
	sources := map[string]string{}
	versions := normalizeStampVersionMap(details["policy_versions"])
	for _, p := range identities {
		if !onRow[p.ID] || p.Source == "" {
			continue
		}
		sources[p.ID] = p.Source
		if _, has := versions[p.ID]; p.Version > 0 && !has {
			if versions == nil {
				versions = map[string]interface{}{}
			}
			versions[p.ID] = p.Version
		}
	}
	if _, set := details["policy_sources"]; len(sources) > 0 && !set {
		details["policy_sources"] = sources
	}
	if len(versions) > 0 {
		details["policy_versions"] = versions
	}
	if _, set := details["document_version"]; documentVersion > 0 && !set {
		details["document_version"] = documentVersion
	}
	if _, set := details["action_name"]; actionName != "" && !set {
		details["action_name"] = actionName
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
// already carry one, so a version an earlier writer stamped is never displaced
// by the static_policies row version this lookup returns. Builtin guard ids
// have no row and are excluded from the query.
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
