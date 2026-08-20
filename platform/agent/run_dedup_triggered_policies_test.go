// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// #3296 Slice 2 Step D: Phase 1 (the shared engine) and Phase 2 (the
// tier-aware engine) both read static_policies and can each independently
// match the SAME policy — their category coverage overlaps by design
// (Phase 2 has no category filter at all). Before appendTriggeredPolicyID
// (run.go), a policy matched non-blockingly by BOTH phases appeared TWICE in
// triggered_policies / matched_policies. These tests are the named
// regressions.

// dupTestPolicyID is a policy_id present in BOTH the Phase-1 fixture (below)
// and the Phase-2 fixture, with a non-blocking action ("warn") so neither
// phase short-circuits the other — Phase 2 only runs when Phase 1 did not
// block (clientRequestHandler / policyTestHandler both gate Phase 2 on
// `!blocked`), so a duplicate can only be observed via two non-blocking
// matches.
const dupTestPolicyID = "dup_test_policy"

// installSharedEngineWithNonBlockingWarnPolicy swaps the global shared-policy
// engine for one backed by sqlmock serving ONE tenant-tier, NON-segment-scoped
// "warn" policy matching pattern literally, in category compliance-rbi (in
// proxyPolicyCategories and, per run_shared_engine_segment_gate_test.go,
// unmodified by ModeDetectionConfig.BuildActionOverrides), plus the mandatory
// system-tier row (#3048 zero-system-tier fail-closed guard).
func installSharedEngineWithNonBlockingWarnPolicy(t *testing.T, tenantID, pattern string) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)

	// The loader issues TWO disjoint scoped passes per load (#3048): tenant
	// scope (tenant_id = $1 = tenantID) and 'global' scope (tenant_id =
	// 'global'). Each pass's expectation is pinned by .WithArgs to its own
	// scope's row set — returning the dup_test_policy tenant row from BOTH
	// passes (as an args-blind mock would) would make the loader itself
	// double-load it, an artifact this test must not manufacture.
	for i := 0; i < 4; i++ { // headroom: allow up to 4 loads of each scope
		tenantRows := sqlmock.NewRows(policytest.LoaderCols()).AddRow(
			"dup-uuid-1", dupTestPolicyID, "Dup Test Policy", "compliance-rbi", "tenant",
			pattern, "low", nil, "request", "warn", nil,
			true, 100, tenantID, nil, nil, []byte(`{}`),
			time.Now().UTC(),
		)
		mockSQL.ExpectQuery("SELECT").WithArgs(tenantID).WillReturnRows(tenantRows)

		globalRows := policytest.SystemPolicyRow(sqlmock.NewRows(policytest.LoaderCols()),
			"sys-never-matches", "sys_test_never_matches",
			"security-sqli", "ZZ_NEVER_MATCHES_ZZ", "low", "request", "block", 1)
		mockSQL.ExpectQuery("SELECT").WithArgs("global").WillReturnRows(globalRows)
	}
	policytest.ScopedTxPlumbing(mockSQL, 8)

	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, cfg, &sharedpolicy.NoOpAuditQueue{})
	t.Cleanup(engine.Stop)
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })
}

// effectiveWarnRowForDupTest builds the Phase-2 (GetEffective) row matching
// dupTestPolicyID with the same non-blocking "warn" action, non-segment-scoped.
func effectiveWarnRowForDupTest(tenantID, pattern string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(effectiveCols()).AddRow(
		"dup-uuid-1", dupTestPolicyID, "Dup Test Policy", "compliance-rbi",
		pattern, "low",
		"", "warn", "tenant", 100, true,
		nil, tenantID, nil, nil,
		"[]", "{}", 1,
		now, now, "admin", "admin",
	)
}

// TestClientRequestHandler_NoDuplicateTriggeredPolicies proves the SAME
// policy_id matched non-blockingly by both Phase 1 and Phase 2 appears
// EXACTLY ONCE in the response's triggered/matched policies.
func TestClientRequestHandler_NoDuplicateTriggeredPolicies(t *testing.T) {
	tierDB, tierMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer tierDB.Close()

	tenantID, orgID, email := "dup-tp-tenant", "dup-tp-org", "frank@corp.example"
	const pattern = "confidential_ledger"
	userToken := segmentPolicyTestSetup(t, tierDB, tenantID, orgID, email)
	installSharedEngineWithNonBlockingWarnPolicy(t, tenantID, pattern)

	// Org-only: zero group memberships (a legitimate, successfully-resolved
	// empty segment set) — isolates the assertion from segment behavior.
	fake := &fakeSegmentResolver{}
	withFleetSegmentResolver(t, fake)

	tenantRows := effectiveWarnRowForDupTest(tenantID, pattern)
	globalRows := sqlmock.NewRows(effectiveCols())
	expectEffectiveTwoPass(tierMock, orgID, tenantRows, emptyOverrideRows(), globalRows, nil)

	clientID := "test-client-seg-" + tenantID
	testLicenseKey := knownClients[clientID].LicenseKey

	w := doSegmentPolicyRequest(t, clientID, userToken, testLicenseKey,
		"please read the confidential_ledger for Q3")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (warn is non-blocking), got %d: %s", w.Code, w.Body.String())
	}

	count := 0

	// Decode the raw response body's policy_info.matched_policies (the field
	// clientRequestHandler actually serializes triggered_policies into on a
	// non-blocking allow — see ClientResponse/PolicyEvaluationInfo).
	var resp struct {
		PolicyInfo struct {
			MatchedPolicies []string `json:"matched_policies"`
		} `json:"policy_info"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, id := range resp.PolicyInfo.MatchedPolicies {
		if id == dupTestPolicyID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("#3296: expected %q exactly once in matched_policies (Phase 1 + Phase 2 both matched it non-blockingly), got %d occurrences: %+v",
			dupTestPolicyID, count, resp.PolicyInfo.MatchedPolicies)
	}
	if err := tierMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet tier-aware mock expectations: %v", err)
	}
}

// TestPolicyTestHandler_NoDuplicateTriggeredPolicies is
// TestClientRequestHandler_NoDuplicateTriggeredPolicies's companion for the
// policyTestHandler preview endpoint, which has the identical Phase 1/Phase 2
// duplication shape (run.go ~3232-3246).
func TestPolicyTestHandler_NoDuplicateTriggeredPolicies(t *testing.T) {
	tierDB, tierMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer tierDB.Close()

	originalEngine := tierAwarePolicyEngine
	t.Cleanup(func() { tierAwarePolicyEngine = originalEngine })
	tierAwarePolicyEngine = NewTierAwarePolicyEngine(tierDB, nil)

	const orgID = "dup-tp-preview-org"
	const pattern = "confidential_ledger"
	installSharedEngineWithNonBlockingWarnPolicy(t, orgID, pattern)

	fake := &fakeSegmentResolver{}
	withFleetSegmentResolver(t, fake)

	tenantRows := effectiveWarnRowForDupTest(orgID, pattern)
	globalRows := sqlmock.NewRows(effectiveCols())
	expectEffectiveTwoPass(tierMock, orgID, tenantRows, emptyOverrideRows(), globalRows, nil)

	resp := doPolicyTestPreviewRequest(t, orgID, orgID, "grace@corp.example",
		"please read the confidential_ledger for Q3")

	if resp.Blocked {
		t.Fatalf("sanity: warn is non-blocking, expected blocked=false, got %+v", resp)
	}
	count := 0
	for _, id := range resp.TriggeredPolicies {
		if id == dupTestPolicyID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("#3296: expected %q exactly once in triggered_policies (Phase 1 + Phase 2 both matched it non-blockingly), got %d occurrences: %+v",
			dupTestPolicyID, count, resp.TriggeredPolicies)
	}
	if err := tierMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet tier-aware mock expectations: %v", err)
	}
}
