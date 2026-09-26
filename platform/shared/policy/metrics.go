// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"sync/atomic"
	"time"
)

// MetricsCollector collects and reports policy evaluation metrics.
// It integrates with the AuditQueue for async persistence.
type MetricsCollector struct {
	auditQueue AuditQueue

	// Counters (atomic for lock-free updates)
	requestEvaluations  int64
	responseEvaluations int64
	blockedRequests     int64
	blockedResponses    int64
	redactionsApplied   int64
	policiesMatched     int64

	// Timing (rolling average)
	requestTimeTotal  int64 // Microseconds
	responseTimeTotal int64 // Microseconds

	// Error counts
	loadErrors       int64
	evaluationErrors int64
	// emptySystemSetErrors counts loads that SUCCEEDED but returned zero
	// system-tier policies (#3048 item-10 — policy data unreachable, e.g.
	// an RLS-blind read on a mis-provisioned app-role deployment). Kept
	// distinct from loadErrors so operators can tell "DB down" apart from
	// "policy rows invisible".
	emptySystemSetErrors int64
}

// AuditQueue interface for async logging.
// This matches the existing AuditQueue in the agent package.
type AuditQueue interface {
	// LogViolation logs a policy violation for compliance
	LogViolation(entry AuditEntry) error

	// LogMetric logs a performance metric
	LogMetric(entry AuditEntry) error

	// LogPolicyEvaluation logs a policy evaluation event (optional, may not be implemented)
	// This is a new method for the unified policy engine
	LogPolicyEvaluation(entry PolicyEvaluationEntry) error
}

// AuditEntry represents a generic audit log entry.
//
// v9 Phase 8 #2384 PR-C1: OrgID is the multi-tenant scope key required by the
// agent's RLS-aware audit_queue persistence path (policy_metrics,
// policy_violations, agent_audit_logs are ENABLE-RLS'd in mig 018; INSERTs
// run under axonflow_app_role need SET LOCAL app.current_org_id to match the
// row's org_id column or WITH CHECK denies). Constructors should populate
// OrgID alongside TenantID — sharedpolicy.EvalOptions carries OrgID from the
// agent's request context for exactly this purpose.
type AuditEntry struct {
	Type      string
	Timestamp time.Time
	Severity  string
	UserID    string
	ClientID  string
	TenantID  string
	OrgID     string
	Details   map[string]interface{}
}

// PolicyEvaluationEntry represents a policy evaluation event.
//
// #4249 row 5705939628: the agent writes it as one policy_metrics row per
// matched policy, a daily hit count keyed by organization, policy and date.
// OrgID is the organization that row is written under: EvalOptions.OrgID, the
// same key and the same rule a violation row uses, never the policy-load scope
// OrganizationID (types.go's EvalOptions.OrgID explains why the two are not
// interchangeable). BlockedPolicies names the matched
// policies whose APPLIED action was block, so the row's block_count counts
// that policy's blocks and not another policy's.
type PolicyEvaluationEntry struct {
	Type              string
	Timestamp         time.Time
	TenantID          string
	OrganizationID    *string
	OrgID             string
	ConnectorName     string
	UserID            string
	PoliciesEvaluated int
	MatchedPolicies   []string
	BlockedPolicies   []string
	Blocked           bool
	BlockReason       string
	RedactionsApplied int
	ProcessingTimeMs  int64
}

// NewMetricsCollector creates a new metrics collector.
func NewMetricsCollector(auditQueue AuditQueue) *MetricsCollector {
	return &MetricsCollector{
		auditQueue: auditQueue,
	}
}

// RecordEvaluation records a policy evaluation for metrics.
// This is called asynchronously to avoid blocking the request path.
func (m *MetricsCollector) RecordEvaluation(
	ctx context.Context,
	phase string,
	opts EvalOptions,
	matches []PolicyMatch,
	blocked bool,
	processingTimeMs int64,
) {
	// Update counters atomically
	if phase == "request" {
		atomic.AddInt64(&m.requestEvaluations, 1)
		atomic.AddInt64(&m.requestTimeTotal, processingTimeMs*1000) // Convert to microseconds
		if blocked {
			atomic.AddInt64(&m.blockedRequests, 1)
		}
	} else {
		atomic.AddInt64(&m.responseEvaluations, 1)
		atomic.AddInt64(&m.responseTimeTotal, processingTimeMs*1000)
		if blocked {
			atomic.AddInt64(&m.blockedResponses, 1)
		}
	}

	atomic.AddInt64(&m.policiesMatched, int64(len(matches)))

	// Log to audit queue if available
	if m.auditQueue != nil {
		entry := PolicyEvaluationEntry{
			Type:              phase,
			Timestamp:         time.Now(),
			TenantID:          opts.TenantID,
			OrganizationID:    opts.OrgScope,
			OrgID:             opts.OrgID,
			ConnectorName:     opts.ConnectorName,
			UserID:            opts.UserID,
			PoliciesEvaluated: len(matches),
			MatchedPolicies:   extractPolicyIDs(matches),
			BlockedPolicies:   blockedPolicyIDs(matches),
			Blocked:           blocked,
			ProcessingTimeMs:  processingTimeMs,
		}

		// Non-blocking. The error is not dropped silently: the queue's
		// implementation counts and logs every entry it cannot keep (the
		// agent's SharedPolicyAuditAdapter, audit_drop.go), and this caller
		// runs on a goroutine with nobody to return it to.
		_ = m.auditQueue.LogPolicyEvaluation(entry)
	}
}

// RecordRedaction records a redaction event.
func (m *MetricsCollector) RecordRedaction(count int) {
	atomic.AddInt64(&m.redactionsApplied, int64(count))
}

// RecordViolation records a policy violation for compliance: one
// policy_violations row, a table regulator exports read (the EU AI Act export,
// the SEBI report) and keep for five years.
//
// THE ROW SAYS WHAT HAPPENED, IN THE PHASE IT HAPPENED (#4249 row 5705939628).
// It used to stamp the policy's REQUEST-phase action on every violation,
// response-phase ones included, so a response block was persisted with the
// request column's action (warn, for the shipped SSN row) or, where that column
// is NULL, the category fallback. Now:
//
//   - action is the detector layer's resolved action (match.Action: the
//     phase's stored action after EvalOptions.ActionOverrides), the action that
//     made this engine record a violation;
//   - stored_action is the phase's explicit stored column (match.StoredAction,
//     empty when the row stores NULL for that phase), so an override that
//     displaced it is visible;
//   - phase is the phase evaluated ("request" or "response");
//   - decided_by is "detector_layer". In v11 this engine authors no verdict: on
//     every enforcing plane its result is the anchored engine's input, and the
//     anchored engine's decision replaces it (the MCP response pass:
//     mcp_response_enforcing_seam.go enforceMCPResponse). The row records what
//     the detector layer resolved, and says so; the verdict the caller received
//     is the audit_logs decision row's.
//
// action keeps its name: the SEBI report reads details->>'action'.
//
// description is the policy's description (its name when it has none), so the
// column stops being NULL. The match text is deliberately NOT written: it is
// the content that matched (a card number, a statement), and this row outlives
// the request by five years in a table exported to regulators.
//
// No client id is set: EvalOptions carries none, so client_id stays empty.
func (m *MetricsCollector) RecordViolation(
	ctx context.Context,
	opts EvalOptions,
	policy *CompiledPolicy,
	match PolicyMatch,
	phase Phase,
) {
	if m.auditQueue == nil {
		return
	}

	description := policy.Description
	if description == "" {
		description = policy.Name
	}
	entry := AuditEntry{
		Type:      "violation",
		Timestamp: time.Now(),
		Severity:  string(policy.Severity),
		UserID:    opts.UserID,
		TenantID:  opts.TenantID,
		OrgID:     opts.OrgID,
		Details: map[string]interface{}{
			"policy_id":      policy.PolicyID,
			"policy_name":    policy.Name,
			"category":       string(policy.Category),
			"connector_name": opts.ConnectorName,
			"action":         string(match.Action),
			"stored_action":  string(match.StoredAction),
			"phase":          string(phase),
			"decided_by":     "detector_layer",
			"description":    description,
		},
	}

	// The error is counted and logged by the queue's implementation (the
	// agent's SharedPolicyAuditAdapter, audit_drop.go); the evaluation that
	// produced the violation does not fail on it.
	_ = m.auditQueue.LogViolation(entry)
}

// RecordError records an evaluation error.
func (m *MetricsCollector) RecordError(errorType string) {
	switch errorType {
	case "load":
		atomic.AddInt64(&m.loadErrors, 1)
	case "evaluation":
		atomic.AddInt64(&m.evaluationErrors, 1)
	case "load_empty_system_set":
		atomic.AddInt64(&m.emptySystemSetErrors, 1)
	}
}

// GetStats returns current metrics.
func (m *MetricsCollector) GetStats() map[string]interface{} {
	requestCount := atomic.LoadInt64(&m.requestEvaluations)
	responseCount := atomic.LoadInt64(&m.responseEvaluations)

	var avgRequestTime, avgResponseTime float64
	if requestCount > 0 {
		avgRequestTime = float64(atomic.LoadInt64(&m.requestTimeTotal)) / float64(requestCount) / 1000
	}
	if responseCount > 0 {
		avgResponseTime = float64(atomic.LoadInt64(&m.responseTimeTotal)) / float64(responseCount) / 1000
	}

	return map[string]interface{}{
		"request_evaluations":  requestCount,
		"response_evaluations": responseCount,
		"blocked_requests":     atomic.LoadInt64(&m.blockedRequests),
		"blocked_responses":    atomic.LoadInt64(&m.blockedResponses),
		"redactions_applied":   atomic.LoadInt64(&m.redactionsApplied),
		"policies_matched":     atomic.LoadInt64(&m.policiesMatched),
		"avg_request_time_ms":  avgRequestTime,
		"avg_response_time_ms": avgResponseTime,
		"load_errors":          atomic.LoadInt64(&m.loadErrors),
		"evaluation_errors":    atomic.LoadInt64(&m.evaluationErrors),
		// #3048 item-10: successful loads that returned zero system-tier
		// policies (fail-closed; distinct from load_errors).
		"policy_load_empty_system_set": atomic.LoadInt64(&m.emptySystemSetErrors),
	}
}

// Reset resets all metrics counters.
func (m *MetricsCollector) Reset() {
	atomic.StoreInt64(&m.requestEvaluations, 0)
	atomic.StoreInt64(&m.responseEvaluations, 0)
	atomic.StoreInt64(&m.blockedRequests, 0)
	atomic.StoreInt64(&m.blockedResponses, 0)
	atomic.StoreInt64(&m.redactionsApplied, 0)
	atomic.StoreInt64(&m.policiesMatched, 0)
	atomic.StoreInt64(&m.requestTimeTotal, 0)
	atomic.StoreInt64(&m.responseTimeTotal, 0)
	atomic.StoreInt64(&m.loadErrors, 0)
	atomic.StoreInt64(&m.evaluationErrors, 0)
	atomic.StoreInt64(&m.emptySystemSetErrors, 0)
}

// extractPolicyIDs extracts policy IDs from matches.
func extractPolicyIDs(matches []PolicyMatch) []string {
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.PolicyID
	}
	return ids
}

// blockedPolicyIDs extracts the ids of the matches whose applied action is block.
func blockedPolicyIDs(matches []PolicyMatch) []string {
	var ids []string
	for _, m := range matches {
		if m.Action == ActionBlock {
			ids = append(ids, m.PolicyID)
		}
	}
	return ids
}

// NoOpAuditQueue is a no-op implementation of AuditQueue for testing.
type NoOpAuditQueue struct{}

func (n *NoOpAuditQueue) LogViolation(entry AuditEntry) error                   { return nil }
func (n *NoOpAuditQueue) LogMetric(entry AuditEntry) error                      { return nil }
func (n *NoOpAuditQueue) LogPolicyEvaluation(entry PolicyEvaluationEntry) error { return nil }
