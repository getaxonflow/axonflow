package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// #3048 loader tests: the two-scope read shape and the item-10 invariant
// guard (a SUCCESSFUL load with zero system-tier policies fails CLOSED with
// ErrEmptySystemPolicySet, routed through the same paths as a load error).

func loaderTestCols() []string {
	return []string{
		"id", "policy_id", "name", "category", "tier", "pattern", "severity",
		"description", "phase", "action_request", "action_response",
		"enabled", "priority", "tenant_id", "organization_id", "segment_id", "metadata",
		"created_at",
	}
}

func systemRow(rows *sqlmock.Rows, policyID string, priority int) *sqlmock.Rows {
	return rows.AddRow(
		"uuid-"+policyID, policyID, "Policy "+policyID, "security-sqli", "system",
		`(?i)\bDROP\s+TABLE\b`, "critical", nil, "request", "block", nil,
		true, priority, "global", nil, nil, []byte(`{}`), time.Now().UTC(),
	)
}

func tenantRow(rows *sqlmock.Rows, policyID, tenantID string, priority int) *sqlmock.Rows {
	return rows.AddRow(
		"uuid-"+policyID, policyID, "Policy "+policyID, "pii-us", "tenant",
		`\d{3}-\d{2}-\d{4}`, "high", nil, "request", "block", nil,
		true, priority, tenantID, nil, nil, []byte(`{}`), time.Now().UTC(),
	)
}

// segmentRow is tenantRow with a non-NULL segment_id, for the #3266 loader
// round-trip test (a segment-scoped row's segment_id must reach
// CompiledPolicy.SegmentID unchanged).
func segmentRow(rows *sqlmock.Rows, policyID, tenantID, segmentID string, priority int) *sqlmock.Rows {
	return rows.AddRow(
		"uuid-"+policyID, policyID, "Policy "+policyID, "pii-us", "tenant",
		`\d{3}-\d{2}-\d{4}`, "high", nil, "request", "block", nil,
		true, priority, tenantID, nil, segmentID, []byte(`{}`), time.Now().UTC(),
	)
}

// expectScopedLoadPass registers one WithOrgScope pass: BEGIN, set_config
// with the given scope, the loader query, COMMIT.
func expectScopedLoadPass(mock sqlmock.Sqlmock, scope string, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app\.current_org_id', \$1, true\)`).
		WithArgs(scope).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT`).WillReturnRows(rows)
	mock.ExpectCommit()
}

// TestLoader_TwoScopePasses_MergesTenantAndGlobal proves the #3048 read
// shape: the tenant scope's rows and the 'global' scope's system rows are
// both loaded and merged in priority order.
func TestLoader_TwoScopePasses_MergesTenantAndGlobal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectScopedLoadPass(mock, "tenant-1", tenantRow(sqlmock.NewRows(loaderTestCols()), "pii_custom", "tenant-1", 50))
	expectScopedLoadPass(mock, "global", systemRow(sqlmock.NewRows(loaderTestCols()), "sys_sqli_drop", 100))

	loader := NewPolicyLoader(db, NewPolicyCache(time.Minute, 10))
	policies, err := loader.GetPolicies(context.Background(), "tenant-1", nil, PhaseRequest)
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 merged policies (tenant + global), got %d", len(policies))
	}
	// priority DESC merge order: the system row (100) sorts first.
	if policies[0].PolicyID != "sys_sqli_drop" || policies[1].PolicyID != "pii_custom" {
		t.Errorf("merge order wrong: got [%s, %s]", policies[0].PolicyID, policies[1].PolicyID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestLoader_EmptySystemSet_FailsClosed is the #3048 item-10 unit test: a
// SUCCESSFUL load whose result carries ZERO system-tier policies is an
// impossible state on a healthy migrated deployment (mig 010/031 seeds always
// exist and cannot be disabled) — it must fail the load with the distinct
// sentinel so EvaluateRequest blocks (#2862) and EvaluateResponse withholds
// (#2820), and it must NOT be cached (a recovered DB serves the next request).
func TestLoader_EmptySystemSet_FailsClosed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// Tenant pass returns a tenant policy; global pass returns NOTHING —
	// the exact RLS-blind shape #3048 shipped with (the reads "succeed"
	// with zero system rows).
	expectScopedLoadPass(mock, "tenant-1", tenantRow(sqlmock.NewRows(loaderTestCols()), "pii_custom", "tenant-1", 50))
	expectScopedLoadPass(mock, "global", sqlmock.NewRows(loaderTestCols()))

	cache := NewPolicyCache(time.Minute, 10)
	loader := NewPolicyLoader(db, cache)
	_, err = loader.GetPolicies(context.Background(), "tenant-1", nil, PhaseRequest)
	if !errors.Is(err, ErrEmptySystemPolicySet) {
		t.Fatalf("expected ErrEmptySystemPolicySet, got %v", err)
	}
	// The fail-closed state must not be cached: no entry may exist.
	if _, found := cache.Get("tenant-1", nil, PhaseRequest); found {
		t.Error("empty-system-set result must NOT be cached (would stick past DB recovery)")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestEngine_EmptySystemSet_RequestBlocked routes the item-10 guard through
// the REQUEST plane: the gate must return Blocked=true with
// EvaluationError=true (availability failure, not a policy verdict) and the
// distinct empty-system-set metric must be recorded.
func TestEngine_EmptySystemSet_RequestBlocked(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectScopedLoadPass(mock, "tenant-1", sqlmock.NewRows(loaderTestCols()))
	expectScopedLoadPass(mock, "global", sqlmock.NewRows(loaderTestCols()))

	cfg := DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := NewUnifiedPolicyEngine(db, cfg, &NoOpAuditQueue{})
	defer engine.Stop()

	result := engine.EvaluateRequest(context.Background(),
		"DROP TABLE users; my SSN is 523-45-6789", EvalOptions{TenantID: "tenant-1"})

	if !result.Blocked {
		t.Fatal("request plane must fail CLOSED on an empty-system-set load — this is exactly how #3048 allowed everything")
	}
	if !result.EvaluationError {
		t.Error("EvaluationError must mark the block as an availability failure, not a policy verdict")
	}
	if result.PoliciesEvaluated != 0 {
		t.Errorf("PoliciesEvaluated = %d, want 0 (nothing was scanned)", result.PoliciesEvaluated)
	}

	stats := engine.metrics.GetStats()
	if got := stats["policy_load_empty_system_set"].(int64); got != 1 {
		t.Errorf("policy_load_empty_system_set metric = %d, want 1 (distinct from load_errors)", got)
	}
	if got := stats["load_errors"].(int64); got != 0 {
		t.Errorf("load_errors = %d, want 0 — the empty-system state must be distinguishable from a DB outage", got)
	}
}

// TestEngine_EmptySystemSet_ResponseFailsClosed routes the guard through the
// RESPONSE plane (#2820 semantics): without GracefulDegradation the content
// is blocked; EvaluationError is set either way so storage redactors can
// withhold.
func TestEngine_EmptySystemSet_ResponseFailsClosed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectScopedLoadPass(mock, "tenant-1", sqlmock.NewRows(loaderTestCols()))
	expectScopedLoadPass(mock, "global", sqlmock.NewRows(loaderTestCols()))

	cfg := DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	cfg.GracefulDegradation = false
	engine := NewUnifiedPolicyEngine(db, cfg, &NoOpAuditQueue{})
	defer engine.Stop()

	result := engine.EvaluateResponse(context.Background(),
		"customer SSN 523-45-6789", EvalOptions{TenantID: "tenant-1"})

	if !result.Blocked {
		t.Fatal("response plane must fail CLOSED on an empty-system-set load")
	}
	if !result.EvaluationError {
		t.Error("EvaluationError must be set (couldn't-scan signal for storage redactors)")
	}
}

// TestLoader_SegmentScopedRow_RoundTrips proves a non-NULL segment_id column
// value reaches CompiledPolicy.SegmentID unchanged (#3266), and a NULL
// segment_id round-trips as "". The loader SELECTs segment_id but does NOT
// filter on it (see loadFromDatabase's doc) — UnifiedPolicyEngine.
// filterBySegments applies the applicability rule at evaluation time using
// this field, per caller, via EvalOptions.Segments.
func TestLoader_SegmentScopedRow_RoundTrips(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectScopedLoadPass(mock, "tenant-1",
		segmentRow(sqlmock.NewRows(loaderTestCols()), "seg_finance_block", "tenant-1", "finance", 50))
	expectScopedLoadPass(mock, "global",
		systemRow(sqlmock.NewRows(loaderTestCols()), "sys_sqli_drop", 100))

	loader := NewPolicyLoader(db, NewPolicyCache(time.Minute, 10))
	policies, err := loader.GetPolicies(context.Background(), "tenant-1", nil, PhaseRequest)
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}

	var segPolicy, sysPolicy *CompiledPolicy
	for i := range policies {
		switch policies[i].PolicyID {
		case "seg_finance_block":
			segPolicy = &policies[i]
		case "sys_sqli_drop":
			sysPolicy = &policies[i]
		}
	}
	if segPolicy == nil {
		t.Fatal("segment-scoped policy row missing from loaded set")
	}
	if segPolicy.SegmentID != "finance" {
		t.Errorf("segment-scoped row: SegmentID = %q, want %q", segPolicy.SegmentID, "finance")
	}
	if sysPolicy == nil {
		t.Fatal("system policy row missing from loaded set")
	}
	if sysPolicy.SegmentID != "" {
		t.Errorf("non-segment-scoped row: SegmentID = %q, want empty", sysPolicy.SegmentID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestLoader_BlankTenant_GlobalPassOnly: a blank tenant historically matched
// nothing on the tenant leg — the read degrades to the 'global' pass alone
// (an empty string is not a valid org scope key).
func TestLoader_BlankTenant_GlobalPassOnly(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectScopedLoadPass(mock, "global", systemRow(sqlmock.NewRows(loaderTestCols()), "sys_sqli_drop", 100))

	loader := NewPolicyLoader(db, NewPolicyCache(time.Minute, 10))
	policies, err := loader.GetPolicies(context.Background(), "", nil, PhaseRequest)
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}
	if len(policies) != 1 || policies[0].PolicyID != "sys_sqli_drop" {
		t.Fatalf("blank tenant must load the global pass alone; got %d policies", len(policies))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
