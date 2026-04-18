// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"time"
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
	OverrideID     string
	PolicyIDs      []string
	TenantID       string
	OrgID          string
	ClientID       string
	UserEmail      string
	ToolSignature  string // optional, empty if not scoped
	Reason         string // free-text justification (required at creation)
	TTLSeconds     int64  // clamped server-side per ADR-044
	DecisionID     string // set only for override_used events
	RequestedTTL   int64  // original TTL requested by client (before clamping)
	Clamped        bool   // true if TTL was clamped from RequestedTTL
	RevokedBy      string // set only for override_revoked events
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
	if entry.ToolSignature != "" {
		policyDetails["tool_signature"] = entry.ToolSignature
	}
	if entry.DecisionID != "" {
		policyDetails["decision_id"] = entry.DecisionID
	}
	if entry.RevokedBy != "" {
		policyDetails["revoked_by"] = entry.RevokedBy
	}

	policyDecision := "override_lifecycle"

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
