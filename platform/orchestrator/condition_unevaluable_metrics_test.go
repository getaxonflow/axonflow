// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	sharedpolicy "axonflow/platform/shared/policy"
)

// This file is the #3296 Slice 2 / epic #3293 DoD test set: one test per
// Reason* constant, proving axonflow_policy_condition_unevaluable_total
// actually increments at the exact call site the reason is documented to
// come from (condition_evaluator.go's "Unevaluable conditions" doc section,
// and this package's condition_unevaluable_metrics.go). Follows the
// testutil.ToFloat64-delta pattern already used by
// TestCountActiveTenantPolicies_FailOpenWithErrorMetric
// (platform/agent/mcp_v1_pro_tools_test.go) for
// axonflow_active_policy_count_errors_total.

func unevaluableCount(reason, plane string) float64 {
	return testutil.ToFloat64(promPolicyConditionUnevaluableTotal.WithLabelValues(reason, plane))
}

// ---------------------------------------------------------------------------
// Zero conditions vacuously matches, on every one of the four planes. This
// is the restored semantics — AND over an empty set is true — after a brief,
// withdrawn attempt (formerly convergence 6) at making every plane behave
// like the MCP handler's old #3061 fail-safe (no-match). See
// condition_evaluator.go's "Withdrawn" doc section. ReasonEmptyConditions is
// recorded ONLY where a stored EXPLICITLY-EMPTY `[]` array (#3384,
// update-gap residue) is excluded — the cache conversion, the
// EvaluateDynamicPolicies enforcement loop, and the TestPolicy preview —
// and never for the legitimate condition-LESS shape (JSON null / absent
// key) these tests exercise, so they assert the metric does NOT move on a
// vacuous match. Each exclusion site's own recording is asserted in
// TestCachedPolicyToDynamicPolicy_LegacyEmptyArraySkipped,
// TestEvaluateDynamicPolicies_LegacyEmptyArrayNotEnforced, and
// TestTestPolicy_LegacyEmptyArrayExcludedFromPreview.
// ---------------------------------------------------------------------------

func TestConditionUnevaluableMetrics_EmptyConditionsVacuouslyMatch_MemoryPlane(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "memory")

	engine := &DynamicPolicyEngine{}
	matched := engine.evaluatePolicy(context.Background(), DynamicPolicy{}, OrchestratorRequest{}, &PolicyEvaluationResult{})

	if !matched {
		t.Fatalf("a zero-condition policy must match (applies to everything), got false")
	}
	if after := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "memory"); after != before {
		t.Fatalf("a legitimate zero-condition match must not record empty_conditions: before=%v after=%v", before, after)
	}
}

func TestConditionUnevaluableMetrics_EmptyConditionsVacuouslyMatch_DatabasePlane(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		metricsDB:    db,
		policies:     make(map[string]interface{}),
		cacheTimeout: 30 * time.Second,
	}
	engine.mu.Lock()
	engine.policies["no_conditions_policy"] = map[string]interface{}{
		"name": "no_conditions_policy",
		"_metadata": map[string]interface{}{
			"tenant_id": "global",
		},
		// No "conditions" key at all -> the parsed []map[string]interface{}
		// stays zero-length.
	}
	engine.lastRefresh = time.Now()
	engine.mu.Unlock()

	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs(sqlmock.AnyArg(), true, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	result := engine.EvaluateDynamicPolicies(context.Background(), OrchestratorRequest{Query: "anything"})
	found := false
	for _, name := range result.AppliedPolicies {
		if name == "no_conditions_policy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a zero-condition policy must be applied (matches everything), AppliedPolicies=%v", result.AppliedPolicies)
	}
	if after := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database"); after != before {
		t.Fatalf("a legitimate zero-condition match must not record empty_conditions: before=%v after=%v", before, after)
	}
}

func TestConditionUnevaluableMetrics_EmptyConditionsVacuouslyMatch_MCPPlane(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "mcp")

	handler := NewMCPDynamicPolicyHandler(nil)
	matched, _, _ := handler.evaluateConditions(DynamicPolicy{Type: "mcp"}, MCPPolicyEvaluationRequest{})

	if !matched {
		t.Fatalf("a zero-condition policy must match (applies to everything), got false")
	}
	if after := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "mcp"); after != before {
		t.Fatalf("a legitimate zero-condition match must not record empty_conditions: before=%v after=%v", before, after)
	}
}

func TestConditionUnevaluableMetrics_EmptyConditionsVacuouslyMatch_PolicyTestPlane(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "policy_test")

	s := &PolicyService{}
	matched := s.evaluateConditions(nil, &TestPolicyRequest{})

	if !matched {
		t.Fatalf("a zero-condition policy must match (applies to everything), got false")
	}
	if after := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "policy_test"); after != before {
		t.Fatalf("a legitimate zero-condition match must not record empty_conditions: before=%v after=%v", before, after)
	}
}

// ---------------------------------------------------------------------------
// ReasonFieldUnresolved — only the MCP handler and the policy-test evaluator
// short-circuit BEFORE calling Match (condition_evaluator.go: "Field
// resolution is NOT part of this evaluator").
// ---------------------------------------------------------------------------

func TestConditionUnevaluableMetrics_FieldUnresolved_MCPPlane(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonFieldUnresolved, "mcp")

	handler := NewMCPDynamicPolicyHandler(nil)
	cond := PolicyCondition{Field: "totally_unrecognized_field", Operator: "equals", Value: "x"}
	got := handler.evaluateCondition(cond, MCPPolicyEvaluationRequest{})

	if got {
		t.Fatalf("an unresolvable field must not match, got true")
	}
	if after := unevaluableCount(sharedpolicy.ReasonFieldUnresolved, "mcp"); after != before+1 {
		t.Fatalf("axonflow_policy_condition_unevaluable_total{reason=field_unresolved,plane=mcp} did not increment: before=%v after=%v", before, after)
	}
}

func TestConditionUnevaluableMetrics_FieldUnresolved_PolicyTestPlane(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonFieldUnresolved, "policy_test")

	s := &PolicyService{}
	cond := PolicyCondition{Field: "totally_unrecognized_field", Operator: "equals", Value: "x"}
	got := s.evaluateCondition(cond, &TestPolicyRequest{})

	if got {
		t.Fatalf("an unresolvable field must not match, got true")
	}
	if after := unevaluableCount(sharedpolicy.ReasonFieldUnresolved, "policy_test"); after != before+1 {
		t.Fatalf("axonflow_policy_condition_unevaluable_total{reason=field_unresolved,plane=policy_test} did not increment: before=%v after=%v", before, after)
	}
}

// ---------------------------------------------------------------------------
// ReasonConditionsUnmarshalFailed — this is the safety property the whole
// restored-vacuous-truth change depends on: a policy whose stored conditions
// JSON is malformed must be excluded entirely, never cached/surfaced as
// indistinguishable from a genuinely condition-less (now vacuously-matching)
// policy. cachedPolicyToDynamicPolicy returns ok=false for it, and the
// caller must not evaluate it. See that function's own doc comment.
// ---------------------------------------------------------------------------

func TestCachedPolicyToDynamicPolicy_MalformedConditions_ExcludedNotEvaluated(t *testing.T) {
	beforeUnmarshalFailed := unevaluableCount(sharedpolicy.ReasonConditionsUnmarshalFailed, "database")

	malformed, ok := cachedPolicyToDynamicPolicy("malformed-policy", map[string]interface{}{
		"conditions": json.RawMessage(`{not valid json`),
	})
	if ok {
		t.Fatalf("malformed conditions JSON must be excluded (ok=false), got ok=true, policy=%+v", malformed)
	}
	if after := unevaluableCount(sharedpolicy.ReasonConditionsUnmarshalFailed, "database"); after != beforeUnmarshalFailed+1 {
		t.Fatalf("axonflow_policy_condition_unevaluable_total{reason=conditions_unmarshal_failed,plane=database} did not increment on malformed JSON: before=%v after=%v", beforeUnmarshalFailed, after)
	}

	// #3384 inverted the second half of this test: a stored `[]` is a clean
	// unmarshal but NOT a legitimate policy — every released create rejected
	// len==0 conditions, so `[]` can only be residue of the released
	// update-API gap, and under restored vacuous-match it would arm as
	// match-everything on the MCP plane at upgrade. It is now EXCLUDED
	// (ok=false) and counted under the reserved empty_conditions label —
	// distinctly from unmarshal_failed, which must NOT move: corruption and
	// legacy emptiness are different defects with different remediations.
	// The legitimate "applies to everything" shape (JSON null / absent key)
	// is asserted in TestCachedPolicyToDynamicPolicy_NullConditionsPasses.
	afterMalformed := unevaluableCount(sharedpolicy.ReasonConditionsUnmarshalFailed, "database")
	beforeEmpty := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database")
	empty, ok := cachedPolicyToDynamicPolicy("empty-array-policy", map[string]interface{}{
		"conditions": json.RawMessage(`[]`),
	})
	if ok {
		t.Fatalf("a stored `[]` conditions array must be excluded (#3384 update-gap residue), got ok=true policy=%+v", empty)
	}
	if after := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database"); after != beforeEmpty+1 {
		t.Fatalf("the `[]` skip must be counted under empty_conditions: before=%v after=%v", beforeEmpty, after)
	}
	if after := unevaluableCount(sharedpolicy.ReasonConditionsUnmarshalFailed, "database"); after != afterMalformed {
		t.Fatalf("a stored `[]` must NOT be counted as conditions_unmarshal_failed (it is not corrupt): before=%v after=%v", afterMalformed, after)
	}
}

// ---------------------------------------------------------------------------
// ReasonUnknownOperator / ReasonNonNumericOperand / ReasonNonStringPattern —
// these three come from inside ConditionEvaluator.Match itself
// (condition_evaluator.go), so any single wired call site proves the
// plumbing; the operator semantics themselves are exhaustively covered by
// platform/shared/policy/condition_evaluator_test.go. Exercised here through
// the memory plane (DynamicPolicyEngine), the lightest of the four callers
// to construct directly.
// ---------------------------------------------------------------------------

func TestConditionUnevaluableMetrics_UnknownOperator_MemoryPlane(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonUnknownOperator, "memory")

	engine := &DynamicPolicyEngine{}
	policy := DynamicPolicy{
		Conditions: []PolicyCondition{{Field: "query", Operator: "starts_with", Value: "x"}},
	}
	matched := engine.evaluatePolicy(context.Background(), policy, OrchestratorRequest{Query: "xyz"}, &PolicyEvaluationResult{})

	if matched {
		t.Fatalf("an unknown operator must not match, got true")
	}
	if after := unevaluableCount(sharedpolicy.ReasonUnknownOperator, "memory"); after != before+1 {
		t.Fatalf("axonflow_policy_condition_unevaluable_total{reason=unknown_operator,plane=memory} did not increment: before=%v after=%v", before, after)
	}
}

func TestConditionUnevaluableMetrics_NonNumericOperand_MemoryPlane(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonNonNumericOperand, "memory")

	engine := &DynamicPolicyEngine{}
	policy := DynamicPolicy{
		Conditions: []PolicyCondition{{Field: "query", Operator: "greater_than", Value: -1.0}},
	}
	matched := engine.evaluatePolicy(context.Background(), policy, OrchestratorRequest{Query: "not-a-number"}, &PolicyEvaluationResult{})

	if matched {
		t.Fatalf("a non-numeric operand must not match, got true")
	}
	if after := unevaluableCount(sharedpolicy.ReasonNonNumericOperand, "memory"); after != before+1 {
		t.Fatalf("axonflow_policy_condition_unevaluable_total{reason=non_numeric_operand,plane=memory} did not increment: before=%v after=%v", before, after)
	}
}

func TestConditionUnevaluableMetrics_NonStringPattern_MemoryPlane(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonNonStringPattern, "memory")

	engine := &DynamicPolicyEngine{}
	policy := DynamicPolicy{
		Conditions: []PolicyCondition{{Field: "query", Operator: "regex", Value: 42}},
	}
	matched := engine.evaluatePolicy(context.Background(), policy, OrchestratorRequest{Query: "42"}, &PolicyEvaluationResult{})

	if matched {
		t.Fatalf("a non-string regex pattern must not match, got true")
	}
	if after := unevaluableCount(sharedpolicy.ReasonNonStringPattern, "memory"); after != before+1 {
		t.Fatalf("axonflow_policy_condition_unevaluable_total{reason=non_string_pattern,plane=memory} did not increment: before=%v after=%v", before, after)
	}
}

// ---------------------------------------------------------------------------
// #3384: the ONE recording site for ReasonEmptyConditions. A stored
// EXPLICITLY-EMPTY conditions array (`[]`) is update-gap residue — every
// released create rejected len==0 — and must be skipped at the conversion
// layer, or it arms as match-everything on the MCP plane the old #3061
// guard used to protect. JSON `null` (platform-seeded intent) must keep
// passing through unrecorded. The two are distinguishable by construction:
// json.Unmarshal leaves the slice nil for `null`, allocates empty non-nil
// for `[]`.
// ---------------------------------------------------------------------------

func TestCachedPolicyToDynamicPolicy_LegacyEmptyArraySkipped(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database")

	dp, ok := cachedPolicyToDynamicPolicy("legacy-empty", map[string]interface{}{
		"name":       "legacy-empty",
		"policy_id":  "legacy-empty-id",
		"conditions": json.RawMessage(`[]`),
		"actions":    json.RawMessage(`[{"type":"block"}]`),
	})

	if ok {
		t.Fatalf("a stored `[]` conditions array must be skipped (update-gap residue), got ok=true dp=%+v", dp)
	}
	if after := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database"); after != before+1 {
		t.Fatalf("the `[]` skip must record empty_conditions on the database plane: before=%v after=%v", before, after)
	}
}

func TestCachedPolicyToDynamicPolicy_NullConditionsPasses(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database")

	dp, ok := cachedPolicyToDynamicPolicy("seeded-null", map[string]interface{}{
		"name":       "seeded-null",
		"policy_id":  "seeded-null-id",
		"conditions": json.RawMessage(`null`),
	})

	if !ok {
		t.Fatal("JSON null conditions (platform-seeded 'applies to everything') must pass conversion")
	}
	if dp.Conditions != nil {
		t.Fatalf("null conditions must convert to a nil slice, got %+v", dp.Conditions)
	}
	if after := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database"); after != before {
		t.Fatalf("null conditions must not record empty_conditions: before=%v after=%v", before, after)
	}
}

// TestListActivePoliciesForTenant_LegacyEmptyArrayExcluded drives the skip
// through the exact read path the MCP handler uses, so the assertion is on
// the plane where the hazard lives: the `[]` row must be absent from the
// result while a sibling null-conditions row survives.
func TestListActivePoliciesForTenant_LegacyEmptyArrayExcluded(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies:     make(map[string]interface{}),
		cacheTimeout: 30 * time.Second,
	}
	engine.mu.Lock()
	engine.policies["legacy-empty-id"] = map[string]interface{}{
		"name":       "legacy-empty",
		"policy_id":  "legacy-empty-id",
		"conditions": json.RawMessage(`[]`),
		"actions":    json.RawMessage(`[{"type":"block"}]`),
		"_metadata":  map[string]interface{}{"tenant_id": "tenant-a"},
	}
	engine.policies["seeded-null-id"] = map[string]interface{}{
		"name":       "seeded-null",
		"policy_id":  "seeded-null-id",
		"conditions": json.RawMessage(`null`),
		"_metadata":  map[string]interface{}{"tenant_id": "tenant-a"},
	}
	engine.lastRefresh = time.Now()
	engine.mu.Unlock()

	got := engine.ListActivePoliciesForTenant("tenant-a", nil)

	for _, p := range got {
		if p.ID == "legacy-empty-id" {
			t.Fatalf("legacy `[]` row must be excluded from the MCP read path, got %+v", got)
		}
	}
	foundNull := false
	for _, p := range got {
		if p.ID == "seeded-null-id" {
			foundNull = true
		}
	}
	if !foundNull {
		t.Fatalf("null-conditions sibling must survive the same read path, got %+v", got)
	}
}

// TestEvaluateDynamicPolicies_LegacyEmptyArrayNotEnforced pins the
// ENFORCEMENT side of the #3384 exclusion — the /api/request plane. This is
// the one plane no other test can see: the list/enforce parity gate's
// enforcement leg probes dbCachedPolicyAppliesToTenant (which runs before
// the conditions parse), the e2e's check-input leg drives the MCP handler
// (which reads through the conversion layer), and the conversion unit tests
// never call EvaluateDynamicPolicies. Without this test, reverting the
// enforcement-side skip leaves every suite green while `[]` rows arm as
// match-everything on /api/request (R3 finding HIGH-2). Both storable
// explicit-empty shapes are pinned: raw `[]` bytes and a pre-parsed empty
// []interface{} (the convention-only arm).
func TestEvaluateDynamicPolicies_LegacyEmptyArrayNotEnforced(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		metricsDB:    db,
		policies:     make(map[string]interface{}),
		cacheTimeout: 30 * time.Second,
	}

	engine.mu.Lock()
	engine.policies["legacy_empty_block"] = map[string]interface{}{
		"name":       "legacy_empty_block",
		"policy_id":  "legacy_empty_block",
		"_metadata":  map[string]interface{}{"tenant_id": "global"},
		"conditions": json.RawMessage(`[]`),
		"actions": []interface{}{
			map[string]interface{}{"type": "block", "config": map[string]interface{}{"reason": "must never fire"}},
		},
	}
	engine.policies["legacy_empty_preparsed"] = map[string]interface{}{
		"name":       "legacy_empty_preparsed",
		"policy_id":  "legacy_empty_preparsed",
		"_metadata":  map[string]interface{}{"tenant_id": "global"},
		"conditions": []interface{}{},
		"actions": []interface{}{
			map[string]interface{}{"type": "block", "config": map[string]interface{}{"reason": "must never fire"}},
		},
	}
	// Null-conditions sibling: proves the run evaluates policies at all, so
	// the two absences above cannot pass because of a broken engine.
	engine.policies["null_cond_log"] = map[string]interface{}{
		"name":      "null_cond_log",
		"policy_id": "null_cond_log",
		"_metadata": map[string]interface{}{"tenant_id": "global"},
		"actions": []interface{}{
			map[string]interface{}{"type": "log", "config": map[string]interface{}{}},
		},
	}
	engine.lastRefresh = time.Now()
	engine.mu.Unlock()

	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs(sqlmock.AnyArg(), true, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	result := engine.EvaluateDynamicPolicies(context.Background(), OrchestratorRequest{Query: "any query at all"})

	if !result.Allowed {
		t.Fatalf("a legacy []-conditions block policy must NOT enforce, got Allowed=false (required_actions=%v)", result.RequiredActions)
	}
	foundNull := false
	for _, name := range result.AppliedPolicies {
		if name == "legacy_empty_block" || name == "legacy_empty_preparsed" {
			t.Fatalf("legacy explicit-empty policy %q must not be applied, AppliedPolicies=%v", name, result.AppliedPolicies)
		}
		if name == "null_cond_log" {
			foundNull = true
		}
	}
	if !foundNull {
		t.Fatalf("null-conditions sibling must still apply (engine-liveness control), AppliedPolicies=%v", result.AppliedPolicies)
	}
	if after := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "database"); after != before+2 {
		t.Fatalf("both explicit-empty shapes must record empty_conditions: before=%v after=%v", before, after)
	}
}

// TestTestPolicy_LegacyEmptyArrayExcludedFromPreview pins the #3384
// exclusion on the policy-TEST preview plane, which reads the row via
// repo.GetByID rather than the cache converter (R3 finding HIGH-1: without
// this exclusion the preview told an operator a legacy `[]` row "matches
// everything, would block" while no engine enforces it).
func TestTestPolicy_LegacyEmptyArrayExcludedFromPreview(t *testing.T) {
	before := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "policy_test")

	s := &PolicyService{}
	// Drive the exclusion branch exactly as TestPolicy does after GetByID:
	// a non-nil empty Conditions slice on the stored row.
	policy := &PolicyResource{
		Name:       "legacy-empty-preview",
		Conditions: []PolicyCondition{},
		Actions:    []PolicyAction{{Type: "block"}},
	}
	resp := s.testPolicyVerdictForStoredRow(policy)
	if resp == nil {
		t.Fatal("expected an exclusion verdict for a stored []-conditions row, got nil (would fall through to vacuous match)")
	}
	if resp.Matched || resp.Blocked {
		t.Fatalf("preview of a legacy []-conditions row must report Matched=false Blocked=false, got %+v", resp)
	}
	if resp.Explanation == "" {
		t.Fatal("exclusion verdict must explain itself")
	}
	if after := unevaluableCount(sharedpolicy.ReasonEmptyConditions, "policy_test"); after != before+1 {
		t.Fatalf("preview exclusion must record empty_conditions on the policy_test plane: before=%v after=%v", before, after)
	}

	// The legitimate condition-LESS shape (nil) must NOT take the exclusion
	// branch - it falls through to the engines' vacuous-match semantics.
	nilRow := &PolicyResource{Name: "null-preview", Conditions: nil}
	if v := s.testPolicyVerdictForStoredRow(nilRow); v != nil {
		t.Fatalf("nil-conditions row must not be excluded from preview, got %+v", v)
	}
}

// TestTestPolicy_LegacyEmptyArrayExcluded_LivePath drives the FULL
// TestPolicy path (GetByID via sqlmock -> verdict helper) rather than the
// classifier alone, so deleting the helper's call site in TestPolicy - the
// "fixing the classifier is not fixing the guard" refactor hazard (R3
// round-2 NEW-1) - fails THIS test even while the helper-level test stays
// green. The mock follows the rls_session_test.go precedent for
// WithOrgScope's transaction shape.
func TestTestPolicy_LegacyEmptyArrayExcluded_LivePath(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT policy_id, name, description, policy_type`).
		WithArgs("legacy-empty-id", "tenant-a").
		WillReturnRows(sqlmock.NewRows([]string{
			"policy_id", "name", "description", "policy_type", "category", "tier",
			"conditions", "actions", "tenant_id", "organization_id",
			"priority", "enabled", "version", "created_by", "updated_by",
			"created_at", "updated_at",
		}).AddRow(
			"legacy-empty-id", "legacy-empty", "residue row", "content", "", "tenant",
			[]byte(`[]`), []byte(`[{"type":"block"}]`), "tenant-a", "",
			100, true, 1, "", "",
			now, now,
		))
	mock.ExpectCommit()

	s := &PolicyService{repo: NewPolicyRepository(db)}
	resp, err := s.TestPolicy(context.Background(), "tenant-a", "legacy-empty-id", &TestPolicyRequest{Query: "anything"})
	if err != nil {
		t.Fatalf("TestPolicy: %v", err)
	}
	if resp.Matched || resp.Blocked {
		t.Fatalf("live TestPolicy path must exclude a stored []-conditions row (Matched=false Blocked=false), got %+v", resp)
	}
	if resp.Explanation == "" || !strings.Contains(resp.Explanation, "EXCLUDED") {
		t.Fatalf("live-path exclusion must explain itself, got explanation=%q", resp.Explanation)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet mock expectations (GetByID shape drifted?): %v", err)
	}
}
