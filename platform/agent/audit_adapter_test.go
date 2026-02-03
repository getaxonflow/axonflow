// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"path/filepath"
	"testing"
	"time"

	sharedpolicy "axonflow/platform/shared/policy"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSharedPolicyAuditAdapter_LogViolation(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	tmpDir := t.TempDir()
	fallbackPath := filepath.Join(tmpDir, "audit_test.jsonl")
	queue, err := NewAuditQueue(AuditModePerformance, 100, 1, db, fallbackPath)
	if err != nil {
		t.Fatalf("Failed to create audit queue: %v", err)
	}

	adapter := &SharedPolicyAuditAdapter{queue: queue}

	entry := sharedpolicy.AuditEntry{
		Type:      "violation",
		Timestamp: time.Now(),
		Severity:  "critical",
		UserID:    "user1",
		ClientID:  "client1",
		TenantID:  "tenant1",
		Details:   map[string]interface{}{"policy_id": "test_policy"},
	}

	err = adapter.LogViolation(entry)
	if err != nil {
		t.Errorf("LogViolation failed: %v", err)
	}
}

func TestSharedPolicyAuditAdapter_LogMetric(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	tmpDir := t.TempDir()
	fallbackPath := filepath.Join(tmpDir, "audit_test.jsonl")
	queue, err := NewAuditQueue(AuditModePerformance, 100, 1, db, fallbackPath)
	if err != nil {
		t.Fatalf("Failed to create audit queue: %v", err)
	}

	adapter := &SharedPolicyAuditAdapter{queue: queue}

	entry := sharedpolicy.AuditEntry{
		Type:      "metric",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"latency_ms": 5},
	}

	err = adapter.LogMetric(entry)
	if err != nil {
		t.Errorf("LogMetric failed: %v", err)
	}
}

func TestSharedPolicyAuditAdapter_LogPolicyEvaluation(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	tmpDir := t.TempDir()
	fallbackPath := filepath.Join(tmpDir, "audit_test.jsonl")
	queue, err := NewAuditQueue(AuditModePerformance, 100, 1, db, fallbackPath)
	if err != nil {
		t.Fatalf("Failed to create audit queue: %v", err)
	}

	adapter := &SharedPolicyAuditAdapter{queue: queue}

	entry := sharedpolicy.PolicyEvaluationEntry{
		Type:              "request",
		Timestamp:         time.Now(),
		TenantID:          "tenant1",
		ConnectorName:     "proxy",
		PoliciesEvaluated: 150,
		MatchedPolicies:   []string{"sqli_001", "pii_ssn"},
		Blocked:           true,
		BlockReason:       "SQL injection detected",
		ProcessingTimeMs:  3,
	}

	err = adapter.LogPolicyEvaluation(entry)
	if err != nil {
		t.Errorf("LogPolicyEvaluation failed: %v", err)
	}
}

func TestSharedPolicyAuditAdapter_NilQueue(t *testing.T) {
	adapter := &SharedPolicyAuditAdapter{queue: nil}

	// All methods should be no-ops with nil queue
	if err := adapter.LogViolation(sharedpolicy.AuditEntry{}); err != nil {
		t.Errorf("Expected nil error for nil queue LogViolation, got: %v", err)
	}
	if err := adapter.LogMetric(sharedpolicy.AuditEntry{}); err != nil {
		t.Errorf("Expected nil error for nil queue LogMetric, got: %v", err)
	}
	if err := adapter.LogPolicyEvaluation(sharedpolicy.PolicyEvaluationEntry{}); err != nil {
		t.Errorf("Expected nil error for nil queue LogPolicyEvaluation, got: %v", err)
	}
}
