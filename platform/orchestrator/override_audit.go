// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"strings"
	"time"

	sharedaudit "axonflow/platform/shared/audit"
)

// Override audit event types (ADR-044).
// These strings are the canonical values written to audit_logs.request_type
// when override lifecycle events occur. Clients filtering audit search by
// request_type should use these constants.
const (
	AuditEventOverrideCreated = "override_created"
	AuditEventOverrideUsed    = "override_used"
	AuditEventOverrideExpired = "override_expired"
	AuditEventOverrideRevoked = "override_revoked"
)

// OverrideAuditEntry is a structured payload for override lifecycle audit
// events. All four event types share this shape — the RequestType field
// (at the AuditEntry level) discriminates which lifecycle transition
// occurred.
type OverrideAuditEntry struct {
	OverrideID string
	PolicyIDs  []string
	// PolicyNames are the evaluation-time display names for PolicyIDs
	// (#3365), threaded from AppliedPolicyDetail.PolicyName at the
	// override_used call site. Empty for created/revoked lifecycle events,
	// which have no evaluation in flight (their rows honestly render ids
	// only). Never populated from a write-time catalog lookup.
	PolicyNames   []string
	TenantID      string
	OrgID         string
	ClientID      string
	UserEmail     string
	ToolSignature string // optional, empty if not scoped
	Reason        string // free-text justification (required at creation)
	TTLSeconds    int64  // clamped server-side per ADR-044
	DecisionID    string // set only for override_used events
	RequestedTTL  int64  // original TTL requested by client (before clamping)
	Clamped       bool   // true if TTL was clamped from RequestedTTL
	RevokedBy     string // set only for override_revoked events
}

// LogOverrideEvent records an override lifecycle event to the audit log.
// eventType must be one of the AuditEventOverride* constants.
func (l *AuditLogger) LogOverrideEvent(ctx context.Context, eventType string, entry *OverrideAuditEntry) {
	if l == nil || entry == nil {
		return
	}

	policyDetails := map[string]interface{}{
		"override_id":   entry.OverrideID,
		"policy_ids":    entry.PolicyIDs,
		"reason":        entry.Reason,
		"ttl_seconds":   entry.TTLSeconds,
		"requested_ttl": entry.RequestedTTL,
		"clamped":       entry.Clamped,
	}
	// #3365: display names beside the ids so the portal resolver and the
	// exporters stop rendering raw ids for override_used rows (the agent-side
	// writeOverrideUsedEvent stamps the same). Empty entries are dropped; a
	// wholly-unnamed event omits the key so the reader's marker stays honest.
	if names := nonEmptyStrings(entry.PolicyNames); len(names) > 0 {
		policyDetails["policy_names"] = names
	}
	if entry.ToolSignature != "" {
		policyDetails["tool_signature"] = entry.ToolSignature
	}
	if entry.DecisionID != "" {
		policyDetails["decision_id"] = entry.DecisionID
	}
	if entry.RevokedBy != "" {
		policyDetails["revoked_by"] = entry.RevokedBy
	}

	// Recognized non-verdict marker in the shared vocabulary (platform/shared/audit,
	// #2638): an override grant/revoke is a lifecycle event, not a PEP verdict.
	// Included in the migration-123 CHECK set so these rows persist.
	policyDecision := sharedaudit.DecisionOverrideLifecycle

	auditEntry := &AuditEntry{
		ID:             generateAuditID(),
		RequestID:      entry.OverrideID,
		Timestamp:      time.Now().UTC(),
		UserEmail:      entry.UserEmail,
		ClientID:       entry.ClientID,
		TenantID:       entry.TenantID,
		OrgID:          entry.OrgID,
		RequestType:    eventType,
		Query:          entry.Reason,
		QueryHash:      hashQuery(entry.OverrideID + eventType),
		PolicyDecision: policyDecision,
		PolicyDetails:  policyDetails,
	}

	l.enqueueEntry(auditEntry)
}

// IsOverrideEventType returns true if the given RequestType is one of the
// four override lifecycle event types. Useful for audit-search filtering.
func IsOverrideEventType(eventType string) bool {
	switch eventType {
	case AuditEventOverrideCreated, AuditEventOverrideUsed,
		AuditEventOverrideExpired, AuditEventOverrideRevoked:
		return true
	}
	return false
}

// nonEmptyStrings returns in without empty/whitespace-only entries, nil when
// none survive.
func nonEmptyStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
