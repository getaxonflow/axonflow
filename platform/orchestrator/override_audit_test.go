// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
)

func TestIsOverrideEventType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"override_created matches", AuditEventOverrideCreated, true},
		{"override_used matches", AuditEventOverrideUsed, true},
		{"override_expired matches", AuditEventOverrideExpired, true},
		{"override_revoked matches", AuditEventOverrideRevoked, true},
		{"workflow_step_gate does not match", "workflow_step_gate", false},
		{"plan_created does not match", "plan_created", false},
		{"empty string does not match", "", false},
		{"similar-but-wrong does not match", "override_", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsOverrideEventType(tc.input)
			if got != tc.expected {
				t.Errorf("IsOverrideEventType(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestLogOverrideEvent_NilLoggerIsNoOp(t *testing.T) {
	var l *AuditLogger // nil
	// Must not panic
	l.LogOverrideEvent(nil, AuditEventOverrideCreated, &OverrideAuditEntry{
		OverrideID: "ov-1",
	})
}

func TestLogOverrideEvent_NilEntryIsNoOp(t *testing.T) {
	l := &AuditLogger{
		auditQueue: make(chan *AuditEntry, 1),
	}
	// Must not panic, must not enqueue
	l.LogOverrideEvent(nil, AuditEventOverrideCreated, nil)
	select {
	case entry := <-l.auditQueue:
		t.Errorf("expected no entry, got %+v", entry)
	default:
		// expected
	}
}

func TestLogOverrideEvent_EnqueuesWithCorrectFields(t *testing.T) {
	l := &AuditLogger{
		auditQueue: make(chan *AuditEntry, 1),
	}

	entry := &OverrideAuditEntry{
		OverrideID:    "ov-abc",
		PolicyIDs:     []string{"pol-1", "pol-2"},
		TenantID:      "tenant-x",
		OrgID:         "org-y",
		ClientID:      "client-z",
		UserEmail:     "dev@example.com",
		ToolSignature: "Bash",
		Reason:        "Debugging production issue",
		TTLSeconds:    3600,
		RequestedTTL:  7200,
		Clamped:       true,
	}

	l.LogOverrideEvent(nil, AuditEventOverrideCreated, entry)

	select {
	case got := <-l.auditQueue:
		if got.RequestType != AuditEventOverrideCreated {
			t.Errorf("RequestType = %q, want %q", got.RequestType, AuditEventOverrideCreated)
		}
		if got.UserEmail != "dev@example.com" {
			t.Errorf("UserEmail = %q, want %q", got.UserEmail, "dev@example.com")
		}
		if got.TenantID != "tenant-x" {
			t.Errorf("TenantID = %q, want %q", got.TenantID, "tenant-x")
		}
		if got.PolicyDetails["override_id"] != "ov-abc" {
			t.Errorf("PolicyDetails[override_id] = %v, want %q", got.PolicyDetails["override_id"], "ov-abc")
		}
		if got.PolicyDetails["tool_signature"] != "Bash" {
			t.Errorf("PolicyDetails[tool_signature] = %v, want %q", got.PolicyDetails["tool_signature"], "Bash")
		}
		if got.PolicyDetails["clamped"] != true {
			t.Errorf("PolicyDetails[clamped] = %v, want true", got.PolicyDetails["clamped"])
		}
		if got.PolicyDetails["reason"] != "Debugging production issue" {
			t.Errorf("PolicyDetails[reason] = %v, want 'Debugging production issue'", got.PolicyDetails["reason"])
		}
	default:
		t.Fatal("expected audit entry enqueued, got none")
	}
}

func TestLogOverrideEvent_UsedVariantIncludesDecisionID(t *testing.T) {
	l := &AuditLogger{
		auditQueue: make(chan *AuditEntry, 1),
	}

	entry := &OverrideAuditEntry{
		OverrideID: "ov-1",
		DecisionID: "dec-xyz",
		Reason:     "linked to decision",
	}

	l.LogOverrideEvent(nil, AuditEventOverrideUsed, entry)

	got := <-l.auditQueue
	if got.RequestType != AuditEventOverrideUsed {
		t.Errorf("RequestType = %q, want %q", got.RequestType, AuditEventOverrideUsed)
	}
	if got.PolicyDetails["decision_id"] != "dec-xyz" {
		t.Errorf("PolicyDetails[decision_id] = %v, want 'dec-xyz'", got.PolicyDetails["decision_id"])
	}
}

func TestLogOverrideEvent_RevokedVariantIncludesRevokedBy(t *testing.T) {
	l := &AuditLogger{
		auditQueue: make(chan *AuditEntry, 1),
	}

	entry := &OverrideAuditEntry{
		OverrideID: "ov-1",
		RevokedBy:  "admin@example.com",
		Reason:     "policy changed",
	}

	l.LogOverrideEvent(nil, AuditEventOverrideRevoked, entry)

	got := <-l.auditQueue
	if got.RequestType != AuditEventOverrideRevoked {
		t.Errorf("RequestType = %q, want %q", got.RequestType, AuditEventOverrideRevoked)
	}
	if got.PolicyDetails["revoked_by"] != "admin@example.com" {
		t.Errorf("PolicyDetails[revoked_by] = %v, want 'admin@example.com'", got.PolicyDetails["revoked_by"])
	}
}
