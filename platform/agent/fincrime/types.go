// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package fincrime is the agent-side Engine A surface of the Fraud & Risk
// Add-on (ADR-061, #3328/#3329). It provides:
//
//   - typed extraction + validation of the documented `fincrime_transaction` /
//     `fincrime_cohort` request-context schema (ee/docs/fincrime/CONTEXT_SCHEMA.md),
//   - a pluggable Evaluator seam consulted from the shared evaluation path
//     (evaluateInputPolicies) after the static engine, and
//   - the Engine B scorer client (advisory-only, hard latency budget).
//
// The real implementation is enterprise-build-only (//go:build enterprise);
// the community build carries a no-op stub with the same surface. This file is
// untagged: it declares the types the untagged agent handlers reference under
// BOTH builds, plus the context-carried decision metadata and audit-detail
// merge used by the canonical audit writers.
package fincrime

import (
	"context"
	"sync"
)

// Context keys of the documented integration surface. Callers place these in
// DecideRequest.Context (the /decide plane) or in the request parameters map
// (the MCP planes). See ee/docs/fincrime/CONTEXT_SCHEMA.md. Untagged so the
// handlers can route the keys under both builds (the community build routes
// and ignores them).
const (
	TransactionContextKey = "fincrime_transaction"
	CohortContextKey      = "fincrime_cohort"
)

// Engine B scorer configuration env vars (untagged so both builds and docs
// reference one definition; the community build reads neither).
const (
	EnvScorerURL       = "AXONFLOW_FINCRIME_SCORER_URL"
	EnvScorerTimeoutMS = "AXONFLOW_FINCRIME_SCORER_TIMEOUT_MS"
)

// Policy identity constants stamped into audit_logs policy_details per the
// #3306 attribution contract. These are string policy ids, resolvable by
// platform/shared/audit.ExtractPolicyIdentity (policy_ids[0] arm).
const (
	// PolicyIDMandatoryFields is the code-backed protocol-integrity policy:
	// a request that opted into the fincrime_transaction schema but sent a
	// malformed shape cannot be risk-assessed and is stepped up to human
	// approval rather than silently allowed.
	PolicyIDMandatoryFields = "fincrime_mandatory_fields"
	// PolicyIDMLFraudScore attributes Engine B scored decisions.
	PolicyIDMLFraudScore = "fincrime_ml_fraud_score"
)

// MLStatus values stamped as ml_inference_layer_status on audit rows.
const (
	MLStatusScored      = "scored"
	MLStatusUnavailable = "unavailable"
)

// Input carries the request-shaped facts the seam hands the fincrime engine.
// All fields are optional; Parameters is the caller-supplied parameter map in
// which the fincrime_transaction / fincrime_cohort context objects ride.
type Input struct {
	TenantID      string
	OrgID         string
	UserID        string
	UserRole      string
	ConnectorName string
	ToolIdentity  string
	Operation     string
	AgentID       string
	SessionID     string
	Parameters    map[string]interface{}
}

// Result is what the fincrime seam returns to the shared evaluation path.
// A nil *Result means the seam had nothing to say (no fincrime context, no
// score, no evaluator finding) and the request proceeds bit-identically to a
// build without the add-on.
type Result struct {
	// RequiresApproval requests the needs_approval verdict on planes that
	// support it (advisory-only mapping: there is NO deny path from the
	// scorer, and MVP evaluators only do context validation).
	RequiresApproval bool

	// Reasons are human-readable governance reasons to surface on the verdict.
	Reasons []string

	// PolicyIDs / PolicyNames / PolicyVersions carry the #3306 attribution
	// for every fincrime detection on this decision. PolicyNames parallels
	// PolicyIDs (the writers' established policy_names shape is an array);
	// PolicyVersions is keyed by policy id (the established map shape).
	PolicyIDs      []string
	PolicyNames    []string
	PolicyVersions map[string]string

	// RiskScore is the structured Engine B score object persisted into
	// policy_details.risk_score on scored decisions (overall, per-model
	// scores, threshold, top_features, feature_coverage, model_version).
	// Nil when the scorer did not produce a score.
	RiskScore map[string]interface{}

	// MLStatus is stamped as policy_details.ml_inference_layer_status:
	// "scored" on success, "unavailable" on timeout/error/unreachable, and
	// "" when the scorer was not consulted at all.
	MLStatus string
}

// DecisionMeta identifies the decision the seam is evaluating for. Plane uses
// the scorer wire vocabulary ("decide" | "mcp"), not the audit_logs plane
// column vocabulary.
type DecisionMeta struct {
	Plane      string
	DecisionID string
}

// auditStamp is the mutable context-carried holder. The handler installs it
// via WithDecisionMeta BEFORE evaluation; the seam fills it after evaluation;
// the canonical audit writers merge it via MergeAuditDetails. Carrying the
// stamp on the context (rather than threading a parameter through every
// writer signature) keeps the seam edits additive: writers that never see a
// fincrime decision are byte-identical.
type auditStamp struct {
	meta DecisionMeta

	mu     sync.Mutex
	result *Result
}

type ctxKey int

const auditStampKey ctxKey = 0

// WithDecisionMeta returns a context carrying the decision identity for the
// fincrime seam plus an empty audit stamp the seam will fill. Callers set it
// immediately before calling the shared evaluation path and keep using the
// returned context through their audit writes.
func WithDecisionMeta(ctx context.Context, plane, decisionID string) context.Context {
	return context.WithValue(ctx, auditStampKey, &auditStamp{
		meta: DecisionMeta{Plane: plane, DecisionID: decisionID},
	})
}

// DecisionMetaFromContext returns the decision identity installed by
// WithDecisionMeta, or nil when the caller did not install one (in which case
// the scorer is not consulted: the frozen contract requires decision_id and
// plane on every scoring request).
func DecisionMetaFromContext(ctx context.Context) *DecisionMeta {
	if s, ok := ctx.Value(auditStampKey).(*auditStamp); ok {
		m := s.meta
		return &m
	}
	return nil
}

// stampResult records the seam result onto the context holder so the audit
// writers can merge it. No-op when the holder is absent.
func stampResult(ctx context.Context, r *Result) {
	if r == nil {
		return
	}
	if s, ok := ctx.Value(auditStampKey).(*auditStamp); ok {
		s.mu.Lock()
		s.result = r
		s.mu.Unlock()
	}
}

// stampedResult returns the recorded seam result, or nil.
func stampedResult(ctx context.Context) *Result {
	if s, ok := ctx.Value(auditStampKey).(*auditStamp); ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.result
	}
	return nil
}

// StampPackMatches records FinCrime Policy Pack row matches (already
// evaluated by the shared static engine) onto the context holder so audit
// writers that do not carry request-phase match ids on their terminal-allow
// rows (the managed MCP query/execute planes) still satisfy the #3306
// attribution contract for fincrime detections. Attribution-only: it never
// changes a verdict. ids and names are parallel slices; empty input or an
// absent holder is a no-op.
func StampPackMatches(ctx context.Context, ids, names []string) {
	if len(ids) == 0 {
		return
	}
	s, ok := ctx.Value(auditStampKey).(*auditStamp)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.result == nil {
		s.result = &Result{}
	}
	for i, id := range ids {
		name := ""
		if i < len(names) {
			name = names[i]
		}
		s.result.addAttributionLocked(id, name, "")
	}
}

// addAttributionLocked appends one policy attribution, deduplicating by id
// and keeping PolicyIDs/PolicyNames parallel. version "" adds no
// policy_versions entry. Callers must hold whatever synchronization the
// Result requires (the ctx holder's mutex, or exclusive ownership).
func (r *Result) addAttributionLocked(policyID, name, version string) {
	if policyID == "" {
		return
	}
	for _, existing := range r.PolicyIDs {
		if existing == policyID {
			return
		}
	}
	r.PolicyIDs = append(r.PolicyIDs, policyID)
	r.PolicyNames = append(r.PolicyNames, name)
	if version != "" {
		if r.PolicyVersions == nil {
			r.PolicyVersions = make(map[string]string, 2)
		}
		r.PolicyVersions[policyID] = version
	}
}

// MergeAuditDetails merges the fincrime attribution recorded on ctx into a
// canonical audit_logs policy_details map, per the #3306 contract:
//
//   - policy_ids: fincrime ids are APPENDED (deduplicated) to any existing
//     []string / []interface{} entry, never overwritten, so the blocking
//     policy hoisted to policy_ids[0] by the caller keeps its identity slot.
//   - policy_names: appended to the existing name array (the established
//     writer shape, cf. buildExplainableAuditDetails).
//   - policy_versions: merged into the existing {policy_id: version} map,
//     preserving any pre-existing entries and their value types.
//   - risk_score: set when the scorer produced a score.
//   - ml_inference_layer_status: set when the scorer was consulted.
//
// It returns the same map for call-site convenience. A context without a
// fincrime stamp (every non-fincrime decision) returns the map untouched.
func MergeAuditDetails(ctx context.Context, details map[string]interface{}) map[string]interface{} {
	r := stampedResult(ctx)
	if r == nil || details == nil {
		return details
	}
	if len(r.PolicyIDs) > 0 {
		existing := normalizeIDList(details["policy_ids"])
		seen := make(map[string]bool, len(existing)+len(r.PolicyIDs))
		for _, id := range existing {
			seen[id] = true
		}
		for _, id := range r.PolicyIDs {
			if id != "" && !seen[id] {
				existing = append(existing, id)
				seen[id] = true
			}
		}
		details["policy_ids"] = existing
	}
	if len(r.PolicyNames) > 0 {
		names := normalizeIDList(details["policy_names"])
		nameSeen := make(map[string]bool, len(names)+len(r.PolicyNames))
		for _, n := range names {
			nameSeen[n] = true
		}
		for _, n := range r.PolicyNames {
			if n != "" && !nameSeen[n] {
				names = append(names, n)
				nameSeen[n] = true
			}
		}
		details["policy_names"] = names
	}
	if len(r.PolicyVersions) > 0 {
		versions := normalizeVersionMap(details["policy_versions"])
		for id, v := range r.PolicyVersions {
			if _, exists := versions[id]; !exists {
				versions[id] = v
			}
		}
		details["policy_versions"] = versions
	}
	if r.RiskScore != nil {
		details["risk_score"] = r.RiskScore
	}
	if r.MLStatus != "" {
		details["ml_inference_layer_status"] = r.MLStatus
	}
	return details
}

// normalizeIDList coerces the pre-existing policy_ids / policy_names entry
// (written as []string by the pure builders, but tolerate []interface{}
// defensively) into a []string.
func normalizeIDList(v interface{}) []string {
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

// normalizeVersionMap coerces a pre-existing policy_versions entry into a
// merge-friendly map WITHOUT changing the value types the original writer
// used (buildExplainableAuditDetails writes map[string]int; the fincrime
// stamp writes string model/pack versions).
func normalizeVersionMap(v interface{}) map[string]interface{} {
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
		return map[string]interface{}{}
	}
}
