// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// #3430 R3: HasSegmentScopedPolicies answers the one question
// filterBySegments cannot - "can a verdict for this (tenant, org, phase)
// depend on the caller's governance-segment membership at all?" - so a plane
// whose caller has an INDETERMINATE segment set can tell a refusal it must
// make from one it must not. Both answers are load-bearing: a false positive
// denies traffic a deployment expects served, a false negative reopens the
// #3430 bypass.

// disabledSegmentRow is segmentRow with enabled = false.
func disabledSegmentRow(rows *sqlmock.Rows, policyID, tenantID, segmentID string, priority int) *sqlmock.Rows {
	return rows.AddRow(
		"uuid-"+policyID, policyID, "Policy "+policyID, "pii-us", "tenant",
		`\d{3}-\d{2}-\d{4}`, "high", nil, "request", "block", nil,
		false, priority, tenantID, segmentID, []byte(`{}`), time.Now().UTC(),
	)
}

func TestHasSegmentScopedPolicies_SegmentScopedRowPresent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectScopedLoadPass(mock, "tenant-1",
		segmentRow(sqlmock.NewRows(loaderTestCols()), "seg_finance_block", "tenant-1", "finance", 50))
	expectScopedLoadPass(mock, "global",
		systemRow(sqlmock.NewRows(loaderTestCols()), "sys_sqli_drop", 100))

	cfg := DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := NewUnifiedPolicyEngine(db, cfg, &NoOpAuditQueue{})
	defer engine.Stop()

	present, ok := engine.HasSegmentScopedPolicies(context.Background(), "tenant-1", nil, PhaseRequest)
	if !ok {
		t.Fatal("a successful load must report ok == true")
	}
	if !present {
		t.Fatal("an enabled segment-scoped row must be reported present - a false negative here reopens the #3430 bypass")
	}
}

func TestHasSegmentScopedPolicies_NoSegmentScopedRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectScopedLoadPass(mock, "tenant-1",
		tenantRow(sqlmock.NewRows(loaderTestCols()), "tenant_pii_block", "tenant-1", 50))
	expectScopedLoadPass(mock, "global",
		systemRow(sqlmock.NewRows(loaderTestCols()), "sys_sqli_drop", 100))

	cfg := DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := NewUnifiedPolicyEngine(db, cfg, &NoOpAuditQueue{})
	defer engine.Stop()

	present, ok := engine.HasSegmentScopedPolicies(context.Background(), "tenant-1", nil, PhaseRequest)
	if !ok {
		t.Fatal("a successful load must report ok == true")
	}
	if present {
		t.Fatal("a policy set with no segment-scoped row must report absent - a false positive denies traffic the deployment expects served")
	}
}

// TestHasSegmentScopedPolicies_DisabledSegmentScopedRowIsAbsent: a DISABLED
// segment-scoped row can never fire, so it must not trigger the refusal.
// filterBySegments would also never act on it (the loader's enabled filter and
// the evaluator both skip it), so counting it here would deny for a policy
// that is switched off.
func TestHasSegmentScopedPolicies_DisabledSegmentScopedRowIsAbsent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectScopedLoadPass(mock, "tenant-1",
		disabledSegmentRow(sqlmock.NewRows(loaderTestCols()), "seg_finance_block", "tenant-1", "finance", 50))
	expectScopedLoadPass(mock, "global",
		systemRow(sqlmock.NewRows(loaderTestCols()), "sys_sqli_drop", 100))

	cfg := DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := NewUnifiedPolicyEngine(db, cfg, &NoOpAuditQueue{})
	defer engine.Stop()

	present, ok := engine.HasSegmentScopedPolicies(context.Background(), "tenant-1", nil, PhaseRequest)
	if !ok {
		t.Fatal("a successful load must report ok == true")
	}
	if present {
		t.Fatal("a DISABLED segment-scoped row must not be reported present")
	}
}

// TestHasSegmentScopedPolicies_LoadError_ReportsUnknown is the fail-closed
// half: a load failure must be distinguishable from "no segment-scoped rows".
// A single bool would collapse the two into the fail-OPEN answer, which is
// exactly the trap PoliciesLoadable exists for on the response plane.
func TestHasSegmentScopedPolicies_LoadError_ReportsUnknown(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	// No expectations registered: the loader's first query is an unexpected
	// call, so GetPolicies errors.
	mock.MatchExpectationsInOrder(false)

	cfg := DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := NewUnifiedPolicyEngine(db, cfg, &NoOpAuditQueue{})
	defer engine.Stop()

	present, ok := engine.HasSegmentScopedPolicies(context.Background(), "tenant-unloadable", nil, PhaseRequest)
	if ok {
		t.Fatal("a load failure must report ok == false so the caller fails closed")
	}
	if present {
		t.Fatal("present must be false when the answer is unknown; ok is the signal callers act on")
	}
}
