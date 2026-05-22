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
	loadErrors      int64
	evaluationErrors int64
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
type PolicyEvaluationEntry struct {
	Type              string
	Timestamp         time.Time
	TenantID          string
	OrganizationID    *string
	ConnectorName     string
	UserID            string
	PoliciesEvaluated int
	MatchedPolicies   []string
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
			OrganizationID:    opts.OrganizationID,
			ConnectorName:     opts.ConnectorName,
			UserID:            opts.UserID,
			PoliciesEvaluated: len(matches),
			MatchedPolicies:   extractPolicyIDs(matches),
			Blocked:           blocked,
			ProcessingTimeMs:  processingTimeMs,
		}

		// Non-blocking log (errors are ignored)
		_ = m.auditQueue.LogPolicyEvaluation(entry)
	}
}

// RecordRedaction records a redaction event.
func (m *MetricsCollector) RecordRedaction(count int) {
	atomic.AddInt64(&m.redactionsApplied, int64(count))
}

// RecordViolation records a policy violation for compliance.
func (m *MetricsCollector) RecordViolation(
	ctx context.Context,
	opts EvalOptions,
	policy *CompiledPolicy,
	matchText string,
) {
	if m.auditQueue == nil {
		return
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
			"action":         string(policy.GetActionForPhase(PhaseRequest)),
		},
	}

	_ = m.auditQueue.LogViolation(entry)
}

// RecordError records an evaluation error.
func (m *MetricsCollector) RecordError(errorType string) {
	switch errorType {
	case "load":
		atomic.AddInt64(&m.loadErrors, 1)
	case "evaluation":
		atomic.AddInt64(&m.evaluationErrors, 1)
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
		"request_evaluations":   requestCount,
		"response_evaluations":  responseCount,
		"blocked_requests":      atomic.LoadInt64(&m.blockedRequests),
		"blocked_responses":     atomic.LoadInt64(&m.blockedResponses),
		"redactions_applied":    atomic.LoadInt64(&m.redactionsApplied),
		"policies_matched":      atomic.LoadInt64(&m.policiesMatched),
		"avg_request_time_ms":   avgRequestTime,
		"avg_response_time_ms":  avgResponseTime,
		"load_errors":           atomic.LoadInt64(&m.loadErrors),
		"evaluation_errors":     atomic.LoadInt64(&m.evaluationErrors),
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
}

// extractPolicyIDs extracts policy IDs from matches.
func extractPolicyIDs(matches []PolicyMatch) []string {
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.PolicyID
	}
	return ids
}

// NoOpAuditQueue is a no-op implementation of AuditQueue for testing.
type NoOpAuditQueue struct{}

func (n *NoOpAuditQueue) LogViolation(entry AuditEntry) error                    { return nil }
func (n *NoOpAuditQueue) LogMetric(entry AuditEntry) error                       { return nil }
func (n *NoOpAuditQueue) LogPolicyEvaluation(entry PolicyEvaluationEntry) error { return nil }
