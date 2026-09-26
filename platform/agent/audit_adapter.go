// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"log"
	"time"

	sharedpolicy "axonflow/platform/shared/policy"
)

// SharedPolicyAuditAdapter adapts the agent's AuditQueue to the shared policy
// engine's AuditQueue interface. This allows the UnifiedPolicyEngine to log
// violations and metrics through the same audit infrastructure as the rest
// of the agent.
type SharedPolicyAuditAdapter struct {
	queue *AuditQueue
}

// Ensure SharedPolicyAuditAdapter implements sharedpolicy.AuditQueue
var _ sharedpolicy.AuditQueue = (*SharedPolicyAuditAdapter)(nil)

// LogViolation logs a policy violation through the agent's audit queue.
//
// v9 Phase 8 #2384 PR-C1: copies OrgID + TenantID from the shared entry so
// the downstream audit_queue persistence path can pin app.current_org_id
// via execWithRetryOrgScope. EvalOptions.OrgID at the request boundary is
// what populates sharedpolicy.AuditEntry.OrgID in metrics.RecordViolation.
func (a *SharedPolicyAuditAdapter) LogViolation(entry sharedpolicy.AuditEntry) error {
	if a.queue == nil {
		return nil
	}
	err := a.queue.LogViolation(AuditEntry{
		Type:      entry.Type,
		Timestamp: entry.Timestamp,
		Severity:  entry.Severity,
		UserID:    entry.UserID,
		ClientID:  entry.ClientID,
		OrgID:     entry.OrgID,
		TenantID:  entry.TenantID,
		Details:   entry.Details,
	})
	if err != nil {
		// The shared engine discards this error (it has nobody to return it
		// to), so this is where a violation that was not written is counted:
		// in compliance mode the write is synchronous and its failure, an
		// entry with no organization included, arrives here (#4249 row
		// 5705939628).
		recordAuditDrop(auditDropViolationWriteFailed, "policy_violations row for policy %v (org %q) was not written: %v",
			entry.Details["policy_id"], entry.OrgID, err)
	}
	return err
}

// LogMetric logs a performance metric through the agent's audit queue.
func (a *SharedPolicyAuditAdapter) LogMetric(entry sharedpolicy.AuditEntry) error {
	if a.queue == nil {
		return nil
	}
	return a.queue.LogMetric(AuditEntry{
		Type:      entry.Type,
		Timestamp: entry.Timestamp,
		Severity:  entry.Severity,
		UserID:    entry.UserID,
		ClientID:  entry.ClientID,
		OrgID:     entry.OrgID,
		TenantID:  entry.TenantID,
		Details:   entry.Details,
	})
}

// LogPolicyEvaluation writes a shared-engine evaluation as policy_metrics
// rows: one per matched policy, each a daily hit (and, when that policy's
// applied action was block, a block) for the evaluation's organization.
//
// #4249 row 5705939628: it used to build one entry with no policy_id and no
// organization, which flushMetricsBatch skips without a word, so no evaluation
// was ever recorded. policy_metrics is a daily aggregate keyed by (org_id,
// policy_id, date) (migrations/core/186), so the entry carries exactly the
// columns that key and its counts need; phase, connector and timing have no
// column there. A policy matched more than once in one evaluation (a response
// with the same PII in several fields) is one hit. An evaluation that matched
// nothing writes nothing. policy_evaluations is not written: nothing in the
// tree writes it, and that is a separate row on #4249.
func (a *SharedPolicyAuditAdapter) LogPolicyEvaluation(entry sharedpolicy.PolicyEvaluationEntry) error {
	if a.queue == nil {
		return nil
	}

	blocked := make(map[string]bool, len(entry.BlockedPolicies))
	for _, id := range entry.BlockedPolicies {
		blocked[id] = true
	}
	seen := make(map[string]bool, len(entry.MatchedPolicies))
	// A failed LogMetric does not stop the loop: the remaining matched
	// policies are still queued, and the first error is returned after them.
	var firstErr error
	for _, policyID := range entry.MatchedPolicies {
		if policyID == "" || seen[policyID] {
			continue
		}
		seen[policyID] = true
		// LogMetric counts its own drops (a full channel); flushMetricsBatch
		// counts an entry with no organization and a write that fails.
		if err := a.queue.LogMetric(AuditEntry{
			Type:      AuditTypeMetric,
			Timestamp: time.Now(),
			UserID:    entry.UserID,
			TenantID:  entry.TenantID,
			OrgID:     entry.OrgID,
			Details: map[string]interface{}{
				"policy_id": policyID,
				"blocked":   blocked[policyID],
			},
		}); err != nil {
			log.Printf("[AuditAdapter] Failed to log policy evaluation for policy %s: %v", policyID, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
	}
	return firstErr
}
