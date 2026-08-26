// Copyright 2025 AxonFlow
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
	"strings"
	"testing"
	"time"
)

// #3321 — coverage for the restored platform-computed "risk_score" condition
// field on DatabaseDynamicPolicyEngine.EvaluateDynamicPolicies. Companion to
// risk_calculator_test.go (the CalculateRiskScore unit tests) and the
// getFieldValue/evaluateCondition call-site fixes in db_dynamic_policies_test.go.

// dynSysHighRiskBlockPolicy reproduces the shape of the seeded
// sys_dyn_high_risk_block policy (migrations/core/031_seed_system_policies.sql):
// block when risk_score > 0.8.
func dynSysHighRiskBlockPolicy() map[string]interface{} {
	return map[string]interface{}{
		"name": "sys_dyn_high_risk_block",
		"_metadata": map[string]interface{}{
			"tenant_id": "global",
			"org_id":    "global",
		},
		"conditions": []interface{}{
			map[string]interface{}{"field": "risk_score", "operator": "greater_than", "value": 0.8},
		},
		"actions": []interface{}{
			map[string]interface{}{"type": "block", "config": map[string]interface{}{"reason": "Query risk score exceeds safety threshold"}},
		},
	}
}

// TestEvaluateDynamicPolicies_SysDynHighRiskBlock_FiresOnSQLi is the
// acceptance case from #3321: the seeded sys_dyn_high_risk_block policy
// (risk_score greater_than 0.8) must fire on an SQLi-shaped query (computed
// score 0.9 > 0.8) and must not fire on a benign one.
func TestEvaluateDynamicPolicies_SysDynHighRiskBlock_FiresOnSQLi(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies:     map[string]interface{}{"sys_dyn_high_risk_block": dynSysHighRiskBlockPolicy()},
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(),
	}

	t.Run("SQLi-shaped query is blocked", func(t *testing.T) {
		req := OrchestratorRequest{
			Query: "1' OR '1'='1' --",
			User:  UserContext{Role: "viewer"},
		}
		result := engine.EvaluateDynamicPolicies(context.Background(), req)
		if result.Allowed {
			t.Fatal("expected sys_dyn_high_risk_block to fire and deny an SQLi-shaped query")
		}
		if len(result.AppliedPolicies) != 1 || result.AppliedPolicies[0] != "sys_dyn_high_risk_block" {
			t.Errorf("expected sys_dyn_high_risk_block in AppliedPolicies, got %v", result.AppliedPolicies)
		}
	})

	t.Run("benign query is not blocked", func(t *testing.T) {
		req := OrchestratorRequest{
			Query: "what is the weather today",
			User:  UserContext{Role: "viewer"},
		}
		result := engine.EvaluateDynamicPolicies(context.Background(), req)
		if !result.Allowed {
			t.Fatal("expected sys_dyn_high_risk_block to NOT fire on a benign query")
		}
		if len(result.AppliedPolicies) != 0 {
			t.Errorf("expected no applied policies for a benign query, got %v", result.AppliedPolicies)
		}
	})
}

// TestEvaluateDynamicPolicies_RiskScoreIgnoresConflictingContext is the
// severity-defusing regression test: before #3321 the bare "risk_score"
// field resolved req.Context["risk_score"], making it a caller-asserted
// value rather than a platform-computed one. This proves the computed value
// wins even when the caller supplies a conflicting context.risk_score.
func TestEvaluateDynamicPolicies_RiskScoreIgnoresConflictingContext(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies:     map[string]interface{}{"sys_dyn_high_risk_block": dynSysHighRiskBlockPolicy()},
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(),
	}

	t.Run("computed high risk fires despite a low caller-supplied context value", func(t *testing.T) {
		req := OrchestratorRequest{
			Query:   "1' OR '1'='1' --", // computed risk_score = 0.9
			User:    UserContext{Role: "viewer"},
			Context: map[string]interface{}{"risk_score": 0.1}, // caller asserts low risk
		}
		result := engine.EvaluateDynamicPolicies(context.Background(), req)
		if result.Allowed {
			t.Fatal("the computed risk_score (0.9) must govern the block, not the caller-supplied context value (0.1)")
		}
	})

	t.Run("computed low risk does not fire despite a high caller-supplied context value", func(t *testing.T) {
		req := OrchestratorRequest{
			Query:   "what is the weather today", // computed risk_score = 0.0
			User:    UserContext{Role: "viewer"},
			Context: map[string]interface{}{"risk_score": 0.95}, // caller asserts high risk
		}
		result := engine.EvaluateDynamicPolicies(context.Background(), req)
		if !result.Allowed {
			t.Fatal("a caller-supplied context.risk_score must not be able to trigger the block on its own — " +
				"the bare risk_score field must be platform-computed, not caller-suppliable")
		}
	})
}

// TestEvaluateDynamicPolicies_ContextRiskScoreStillResolves proves
// "context.risk_score" remains available as its own, distinct,
// caller-asserted field — #3321 explicitly rejected carving this field out
// or excluding it from the generic "context.*" resolution branch.
func TestEvaluateDynamicPolicies_ContextRiskScoreStillResolves(t *testing.T) {
	policy := map[string]interface{}{
		"name": "context_risk_score_policy",
		"_metadata": map[string]interface{}{
			"tenant_id": "global",
			"org_id":    "global",
		},
		"conditions": []interface{}{
			map[string]interface{}{"field": "context.risk_score", "operator": "greater_than", "value": 0.5},
		},
		"actions": []interface{}{
			map[string]interface{}{"type": "block", "config": map[string]interface{}{"reason": "caller-asserted risk"}},
		},
	}
	engine := &DatabaseDynamicPolicyEngine{
		policies:     map[string]interface{}{"context_risk_score_policy": policy},
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(),
	}

	// Computed risk_score for this query is 0.0 (no SQLi/sensitive/admin/
	// select* factors) — only the explicit context.risk_score should drive
	// this policy.
	req := OrchestratorRequest{
		Query:   "what is the weather today",
		User:    UserContext{Role: "viewer"},
		Context: map[string]interface{}{"risk_score": 0.9},
	}
	result := engine.EvaluateDynamicPolicies(context.Background(), req)
	if result.Allowed {
		t.Fatal("expected context.risk_score to still resolve the caller-supplied value under its own field name")
	}
}

// TestEvaluateDynamicPolicies_RiskScoreOrderDependence pins the consequence
// #3321 explicitly accepted as restoration (not novelty): once the resolver
// reads result.RiskScore, an earlier-evaluated policy's modify_risk
// escalation becomes visible to a later-evaluated policy's own risk_score
// condition — the retired in-memory engine's semantics.
//
// This must be a DETERMINISTIC property, not merely an order-dependent one.
// e.policies is a map[string]interface{}, and a bare `range` over it would
// make "which policy runs first" a function of Go's randomized map
// iteration — so the SAME request could reach a DIFFERENT verdict from one
// call to the next, which is worse than the dormancy #3321 set out to fix:
// a customer could not reproduce their own enforcement. The retired
// in-memory engine never had this problem — it held its policies as a
// SLICE, sourced from a query already carrying
// `ORDER BY priority DESC, created_at DESC`
// (dynamicPoliciesQueryWithSegment/WithoutSegment,
// platform/shared/policy/loader.go) — so its evaluation order was
// deterministic by construction. sortedDynamicPolicyEntries
// (db_dynamic_policies.go) reproduces that exact ordering over the
// map-backed cache, so "which policy runs first" is a function of priority
// (then created_at, then cacheKey), never of map iteration. These two
// sub-tests assert the two fixed outcomes that ordering guarantees — run
// each with -count=5 to confirm the determinism holds, not just "usually
// holds."
func TestEvaluateDynamicPolicies_RiskScoreOrderDependence(t *testing.T) {
	req := OrchestratorRequest{
		Query:       "what is the weather today", // computed floor risk_score = 0.0
		RequestType: "llm",
		User:        UserContext{Role: "viewer"},
	}

	// escalator always matches and adds 0.9 to the running risk_score via
	// modify_risk. reader only matches once risk_score has been escalated
	// above 0.5 — the computed floor for this request is 0.0, so reader
	// firing is proof it saw escalator's effect.
	escalator := func(priority int) map[string]interface{} {
		return map[string]interface{}{
			"name":     "escalator",
			"priority": priority,
			"_metadata": map[string]interface{}{
				"tenant_id": "global",
				"org_id":    "global",
			},
			"conditions": []interface{}{
				map[string]interface{}{"field": "request_type", "operator": "equals", "value": "llm"},
			},
			"actions": []interface{}{
				map[string]interface{}{"type": "modify_risk", "config": map[string]interface{}{"add": 0.9}},
			},
		}
	}
	reader := func(priority int) map[string]interface{} {
		return map[string]interface{}{
			"name":     "reader",
			"priority": priority,
			"_metadata": map[string]interface{}{
				"tenant_id": "global",
				"org_id":    "global",
			},
			"conditions": []interface{}{
				map[string]interface{}{"field": "risk_score", "operator": "greater_than", "value": 0.5},
			},
			"actions": []interface{}{
				map[string]interface{}{"type": "log", "config": map[string]interface{}{}},
			},
		}
	}

	appliedNames := func(result *PolicyEvaluationResult) (readerFired, escalatorFired bool) {
		for _, name := range result.AppliedPolicies {
			switch name {
			case "reader":
				readerFired = true
			case "escalator":
				escalatorFired = true
			}
		}
		return
	}

	t.Run("escalator at higher priority: reader sees the escalated score", func(t *testing.T) {
		engine := &DatabaseDynamicPolicyEngine{
			policies: map[string]interface{}{
				"escalator": escalator(100), // evaluated FIRST (priority DESC)
				"reader":    reader(1),
			},
			cacheTimeout: 30 * time.Second,
			lastRefresh:  time.Now(),
		}
		result := engine.EvaluateDynamicPolicies(context.Background(), req)
		readerFired, escalatorFired := appliedNames(result)
		if !escalatorFired {
			t.Fatal("escalator has an unconditionally-true condition and must always apply")
		}
		if !readerFired {
			t.Errorf("reader did not fire: with escalator at higher priority it is evaluated first, "+
				"so reader's risk_score condition must see the escalated value (0.9 > 0.5). AppliedPolicies=%v",
				result.AppliedPolicies)
		}
	})

	t.Run("escalator at lower priority: reader does not see the escalated score", func(t *testing.T) {
		engine := &DatabaseDynamicPolicyEngine{
			policies: map[string]interface{}{
				"escalator": escalator(1),
				"reader":    reader(100), // evaluated FIRST (priority DESC)
			},
			cacheTimeout: 30 * time.Second,
			lastRefresh:  time.Now(),
		}
		result := engine.EvaluateDynamicPolicies(context.Background(), req)
		readerFired, escalatorFired := appliedNames(result)
		if !escalatorFired {
			t.Fatal("escalator has an unconditionally-true condition and must always apply")
		}
		if readerFired {
			t.Errorf("reader fired: with escalator at lower priority it is evaluated AFTER reader, "+
				"so reader's risk_score condition must see only the unescalated floor (0.0, not > 0.5). AppliedPolicies=%v",
				result.AppliedPolicies)
		}
	})
}

// TestEvaluateDynamicPolicies_ComputedRiskScoreMatchesCalculatorDirectly
// proves the value EvaluateDynamicPolicies seeds onto the result is exactly
// RiskCalculator.CalculateRiskScore(req) — the same computation the
// simulate (policy_simulation_handler.go) and WCP/HITL
// (wcp_policy_adapter.go, map_hitl_adapter.go) planes observe, because they
// all call this same EvaluateDynamicPolicies method rather than computing
// independently. Seeding at ingress instead of inside the evaluator would
// let those planes diverge (the #3283 class of defect); seeding here, once,
// structurally prevents that.
func TestEvaluateDynamicPolicies_ComputedRiskScoreMatchesCalculatorDirectly(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies:     map[string]interface{}{},
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(),
	}
	req := OrchestratorRequest{
		Query: "1' OR '1'='1' --",
		User:  UserContext{Role: "admin"},
	}

	want := NewRiskCalculator().CalculateRiskScore(req)

	result1 := engine.EvaluateDynamicPolicies(context.Background(), req)
	result2 := engine.EvaluateDynamicPolicies(context.Background(), req)

	if result1.RiskScore != want {
		t.Errorf("EvaluateDynamicPolicies seeded RiskScore = %v, want %v (RiskCalculator.CalculateRiskScore(req))", result1.RiskScore, want)
	}
	if result2.RiskScore != want {
		t.Errorf("second call seeded RiskScore = %v, want %v — computation must be deterministic and identical across calls (enforcement vs. simulate)", result2.RiskScore, want)
	}
}

// TestSortedDynamicPolicyEntries_TotalOrder pins the three-key sort
// (priority DESC, created_at DESC, cacheKey ASC) directly, independent of
// EvaluateDynamicPolicies, including the total-order guarantee: two entries
// tied on both priority and created_at must still resolve to a single fixed
// sequence via the cacheKey tiebreaker, run after run.
func TestSortedDynamicPolicyEntries_TotalOrder(t *testing.T) {
	entry := func(priority int, createdAt time.Time) map[string]interface{} {
		return map[string]interface{}{
			"priority": priority,
			"_metadata": map[string]interface{}{
				"created_at": createdAt,
			},
		}
	}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	policies := map[string]interface{}{
		"low_priority":          entry(1, t0),
		"high_priority":         entry(100, t0),
		"mid_priority_newer":    entry(50, t1),
		"mid_priority_older":    entry(50, t0),
		"tied_b_priority_50_t0": entry(50, t0), // ties mid_priority_older on both priority and created_at
	}

	for i := 0; i < 5; i++ {
		got := sortedDynamicPolicyEntries(policies)
		if len(got) != len(policies) {
			t.Fatalf("run %d: expected %d entries, got %d", i, len(policies), len(got))
		}
		wantOrder := []string{
			"high_priority",         // priority 100
			"mid_priority_newer",    // priority 50, created_at t1
			"mid_priority_older",    // priority 50, created_at t0, cacheKey "mid_priority_older" < "tied_b..."
			"tied_b_priority_50_t0", // priority 50, created_at t0, cacheKey tiebreak loses to the above
			"low_priority",          // priority 1
		}
		for j, key := range wantOrder {
			if got[j].cacheKey != key {
				t.Fatalf("run %d: position %d = %q, want %q (full order: %v)", i, j, got[j].cacheKey, key, entryKeys(got))
			}
		}
	}
}

// TestEvaluateDynamicPolicies_RiskScoreClampsAfterModifyRisk pins the #3321
// follow-up fix: RiskScore is clamped to the documented [0,1] range AFTER
// the policy loop completes, not inside modify_risk's own arm. Before this
// fix, an SQLi-detected computed floor of 0.9 plus one +0.2 modify_risk
// action produced RiskScore=1.1, outside the documented range, flowing
// verbatim into audit rows and the compliance evidence export.
func TestEvaluateDynamicPolicies_RiskScoreClampsAfterModifyRisk(t *testing.T) {
	// A modify_risk policy that always matches (request_type == "llm") and
	// adds 0.2 to whatever the running score already is.
	modifyRiskPolicy := map[string]interface{}{
		"name": "modify_risk_adder",
		"_metadata": map[string]interface{}{
			"tenant_id": "global",
			"org_id":    "global",
		},
		"conditions": []interface{}{
			map[string]interface{}{"field": "request_type", "operator": "equals", "value": "llm"},
		},
		"actions": []interface{}{
			map[string]interface{}{"type": "modify_risk", "config": map[string]interface{}{"add": 0.2}},
		},
	}
	engine := &DatabaseDynamicPolicyEngine{
		policies:     map[string]interface{}{"modify_risk_adder": modifyRiskPolicy},
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(),
	}

	// Computed floor 0.9 (SQLi, via the shared sqli scanner) + 0.2
	// (modify_risk) = 1.1 pre-clamp.
	req := OrchestratorRequest{
		Query:       "1' OR '1'='1' --",
		RequestType: "llm",
		User:        UserContext{Role: "viewer"},
	}
	result := engine.EvaluateDynamicPolicies(context.Background(), req)
	if result.RiskScore != 1.0 {
		t.Errorf("expected RiskScore to clamp to 1.0 (0.9 computed + 0.2 modify_risk = 1.1 pre-clamp), got %v", result.RiskScore)
	}
}

// TestEvaluateDynamicPolicies_WarnActionAllowsAndAnnotates proves the "warn"
// action arm (added alongside the #3321 follow-up work) is allow-but-
// annotate, the same shape as the neighbouring "log"/"alert" arms: a
// matching "warn" policy does NOT flip Allowed to false, but does record a
// RequiredActions entry so the warning is visible in the audit trail. Before
// this arm existed, "warn" fell through the action-type switch with no
// matching case and applied nothing at all — silently inert, which is
// exactly what happened to sys_dyn_high_risk_block after migration 036
// downgraded it from "block" to "warn".
func TestEvaluateDynamicPolicies_WarnActionAllowsAndAnnotates(t *testing.T) {
	warnPolicy := map[string]interface{}{
		"name": "sys_dyn_high_risk_block",
		"_metadata": map[string]interface{}{
			"tenant_id": "global",
			"org_id":    "global",
		},
		"conditions": []interface{}{
			map[string]interface{}{"field": "risk_score", "operator": "greater_than", "value": 0.8},
		},
		"actions": []interface{}{
			map[string]interface{}{"type": "warn", "config": map[string]interface{}{"reason": "Query risk score exceeds safety threshold"}},
		},
	}
	engine := &DatabaseDynamicPolicyEngine{
		policies:     map[string]interface{}{"sys_dyn_high_risk_block": warnPolicy},
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(),
	}

	req := OrchestratorRequest{
		Query: "1' OR '1'='1' --", // computed risk_score = 0.9 > 0.8
		User:  UserContext{Role: "viewer"},
	}
	result := engine.EvaluateDynamicPolicies(context.Background(), req)

	if !result.Allowed {
		t.Fatal("expected a \"warn\" action to allow the request (allow-but-annotate), got Allowed=false")
	}
	if len(result.AppliedPolicies) != 1 || result.AppliedPolicies[0] != "sys_dyn_high_risk_block" {
		t.Errorf("expected sys_dyn_high_risk_block in AppliedPolicies, got %v", result.AppliedPolicies)
	}
	foundWarn := false
	for _, action := range result.RequiredActions {
		if strings.HasPrefix(action, "warn:") {
			foundWarn = true
			break
		}
	}
	if !foundWarn {
		t.Errorf("expected a \"warn: ...\" entry in RequiredActions, got %v", result.RequiredActions)
	}
}

func entryKeys(entries []dynamicPolicyCacheEntry) []string {
	keys := make([]string, len(entries))
	for i, e := range entries {
		keys[i] = e.cacheKey
	}
	return keys
}
