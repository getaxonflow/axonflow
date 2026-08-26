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

// #3319: relocated from dynamic_policy_engine_test.go, which was deleted
// along with the retired in-memory DynamicPolicyEngine. Both tests below
// exercise DatabaseDynamicPolicyEngine — the surviving engine — and were
// simply misfiled; they are production-incident regression tests, not
// coverage of the retired engine, so they are ported verbatim rather than
// dropped. Kept in a dedicated file (not db_dynamic_policies_test.go, which
// this consolidation pass does not own) so ownership stays unambiguous.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDatabaseDynamicPolicyEngine_StepGateEvaluation(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	metricsDB, metricsMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create metrics sqlmock: %v", err)
	}
	defer metricsDB.Close()

	// Expect metrics insert (happens async, may or may not execute before test ends)
	metricsMock.ExpectExec("INSERT INTO policy_metrics").
		WillReturnResult(sqlmock.NewResult(1, 1))

	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		metricsDB:    metricsDB,
		policies:     make(map[string]interface{}),
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(),
		stopCh:       make(chan struct{}),
	}

	// Manually populate the cache exactly as refreshPolicies() would.
	// This simulates a policy loaded from DB with:
	//   name: "demo-block-bulk-email"
	//   conditions: [{"field": "step_input.recipient_count", "operator": "greater_than", "value": 1000}]
	//   actions: [{"type": "block", "config": {"reason": "Email blocked: recipient count exceeds 1000"}}]
	//   tenant_id: "travel-us"
	conditionsJSON := `[{"field": "step_input.recipient_count", "operator": "greater_than", "value": 1000}]`
	actionsJSON := `[{"type": "block", "config": {"reason": "Email blocked: recipient count exceeds 1000"}}]`

	policyData := map[string]interface{}{
		"policy_id":  "148f22f0-test",
		"name":       "demo-block-bulk-email",
		"type":       "content",
		"category":   "dynamic-risk",
		"conditions": json.RawMessage(conditionsJSON),
		"actions":    json.RawMessage(actionsJSON),
		"tenant_id":  "travel-us",
		"priority":   50,
		"_metadata": map[string]interface{}{
			"name":      "demo-block-bulk-email",
			"tenant_id": "travel-us",
			"org_id":    "travel-us",
			"priority":  50,
			"loaded_at": time.Now().Unix(),
		},
	}

	engine.policies = map[string]interface{}{
		"demo-block-bulk-email": policyData,
	}

	// Build the OrchestratorRequest exactly as WCPPolicyAdapter.convertToOrchestratorRequest() would.
	// StepInput: {"recipient_count": 5000, "tool": "email_sender", "action": "send_bulk"}
	// These get merged as "step_input.recipient_count", "step_input.tool", etc.
	contextData := map[string]interface{}{
		"workflow_id":                "wf_test",
		"workflow_name":              "support-automation",
		"source":                     "api",
		"step_id":                    "step-2",
		"step_name":                  "Send Email",
		"step_type":                  "tool_call",
		"step_index":                 2,
		"model":                      "",
		"provider":                   "",
		"step_input.tool":            "email_sender",
		"step_input.action":          "send_bulk",
		"step_input.recipient_count": float64(5000),
		"step_input.subject":         "Support case update",
		"tool_name":                  "email_sender",
		"tool_type":                  "function",
	}

	req := OrchestratorRequest{
		RequestID:   "wf_test_step-2",
		RequestType: "workflow_step_gate",
		User: UserContext{
			TenantID: "travel-us",
		},
		Client: ClientContext{
			ID:       "travel-us",
			TenantID: "travel-us",
			OrgID:    "travel-us",
		},
		Context: contextData,
	}

	result := engine.EvaluateDynamicPolicies(context.Background(), req)

	// The policy should match and block
	if result.Allowed {
		t.Errorf("Expected blocked (Allowed=false), got Allowed=true")
		t.Logf("AppliedPolicies: %v", result.AppliedPolicies)
		t.Logf("RequiredActions: %v", result.RequiredActions)

		// Debug: manually trace the evaluation
		t.Log("--- Manual trace ---")
		for name, policy := range engine.policies {
			policyMap, ok := policy.(map[string]interface{})
			if !ok {
				t.Logf("Policy %q: not a map", name)
				continue
			}
			metadata, ok := policyMap["_metadata"].(map[string]interface{})
			if ok {
				policyTenant, _ := metadata["tenant_id"].(string)
				t.Logf("Policy %q: tenant=%q (request tenant=%q)", name, policyTenant, "travel-us")
			}
			condRaw := policyMap["conditions"]
			t.Logf("Policy %q: conditions type=%T, value=%v", name, condRaw, condRaw)

			// Try to parse conditions
			if raw, ok := condRaw.(json.RawMessage); ok {
				var conditions []map[string]interface{}
				if err := json.Unmarshal(raw, &conditions); err != nil {
					t.Logf("Failed to parse: %v", err)
				} else {
					for _, cond := range conditions {
						field, _ := cond["field"].(string)
						operator, _ := cond["operator"].(string)
						value := cond["value"]
						fieldValue := engine.getFieldValue(field, req, nil)
						t.Logf("  Condition: field=%q op=%q value=%v(%T) -> fieldValue=%v(%T)",
							field, operator, value, value, fieldValue, fieldValue)
					}
				}
			}
		}
	}

	if len(result.AppliedPolicies) != 1 || result.AppliedPolicies[0] != "demo-block-bulk-email" {
		t.Errorf("Expected AppliedPolicies=[demo-block-bulk-email], got %v", result.AppliedPolicies)
	}

	// Wait briefly for async metrics goroutine
	time.Sleep(50 * time.Millisecond)
}

// TestDatabaseDynamicPolicyEngine_CrossTenantCacheCollision verifies that policies with
// the same name across different tenants don't overwrite each other in the cache.
// This was the root cause of the step gate returning "allow" instead of "block" in production:
// a stale vc-demo tenant policy overwrote the travel-us policy because both were named
// "demo-block-bulk-email" and the cache was keyed by name.
func TestDatabaseDynamicPolicyEngine_CrossTenantCacheCollision(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	metricsDB, metricsMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create metrics sqlmock: %v", err)
	}
	defer metricsDB.Close()

	metricsMock.ExpectExec("INSERT INTO policy_metrics").
		WillReturnResult(sqlmock.NewResult(1, 1))

	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		metricsDB:    metricsDB,
		policies:     make(map[string]interface{}),
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(),
		stopCh:       make(chan struct{}),
	}

	conditionsJSON := `[{"field": "step_input.recipient_count", "operator": "greater_than", "value": 1000}]`
	actionsJSON := `[{"type": "block", "config": {"reason": "Email blocked: recipient count exceeds 1000"}}]`

	// Simulate two policies with the SAME name but different tenants and different policy_ids.
	// With the old name-keyed cache, the second would overwrite the first.
	// With the policy_id-keyed cache, both coexist.
	travelPolicy := map[string]interface{}{
		"policy_id":  "policy-travel-001",
		"name":       "demo-block-bulk-email",
		"type":       "content",
		"category":   "dynamic-risk",
		"conditions": json.RawMessage(conditionsJSON),
		"actions":    json.RawMessage(actionsJSON),
		"tenant_id":  "travel-us",
		"priority":   50,
		"_metadata": map[string]interface{}{
			"name":      "demo-block-bulk-email",
			"tenant_id": "travel-us",
			"org_id":    "travel-us",
			"priority":  50,
			"loaded_at": time.Now().Unix(),
		},
	}

	// Stale policy from vc-demo tenant — same name, different tenant, different conditions
	staleDemoPolicy := map[string]interface{}{
		"policy_id":  "policy-vcdemo-999",
		"name":       "demo-block-bulk-email",
		"type":       "content",
		"category":   "dynamic-risk",
		"conditions": json.RawMessage(`[{"field": "step_input.recipient_count", "operator": "greater_than", "value": 10000}]`),
		"actions":    json.RawMessage(actionsJSON),
		"tenant_id":  "vc-demo",
		"priority":   50,
		"_metadata": map[string]interface{}{
			"name":      "demo-block-bulk-email",
			"tenant_id": "vc-demo",
			"org_id":    "vc-demo",
			"priority":  50,
			"loaded_at": time.Now().Unix(),
		},
	}

	// Cache keyed by policy_id — both policies coexist
	engine.policies = map[string]interface{}{
		"policy-travel-001": travelPolicy,
		"policy-vcdemo-999": staleDemoPolicy,
	}

	// Request from travel-us tenant with 5000 recipients
	req := OrchestratorRequest{
		RequestID:   "wf_test_step-2",
		RequestType: "workflow_step_gate",
		User: UserContext{
			TenantID: "travel-us",
		},
		Client: ClientContext{
			ID:       "travel-us",
			TenantID: "travel-us",
			OrgID:    "travel-us",
		},
		Context: map[string]interface{}{
			"step_input.recipient_count": float64(5000),
			"step_input.tool":            "email_sender",
			"tool_name":                  "email_sender",
		},
	}

	result := engine.EvaluateDynamicPolicies(context.Background(), req)

	// The travel-us policy (threshold 1000) should match and block
	if result.Allowed {
		t.Errorf("Expected blocked (Allowed=false), got Allowed=true — cross-tenant collision likely")
	}

	if len(result.AppliedPolicies) != 1 || result.AppliedPolicies[0] != "demo-block-bulk-email" {
		t.Errorf("Expected AppliedPolicies=[demo-block-bulk-email], got %v", result.AppliedPolicies)
	}

	// Also verify GetPolicy finds the travel policy by name
	policy, found := engine.GetPolicy("demo-block-bulk-email")
	if !found {
		t.Error("GetPolicy('demo-block-bulk-email') returned not found")
	} else if policy["policy_id"] != "policy-travel-001" && policy["policy_id"] != "policy-vcdemo-999" {
		t.Errorf("GetPolicy returned unexpected policy_id: %v", policy["policy_id"])
	}

	// Verify both policies exist in cache (not overwritten)
	// GetAllPolicies adds a "database_accessed" key, so expect 3 entries (2 policies + marker)
	allPolicies := engine.GetAllPolicies()
	if len(allPolicies) != 3 {
		t.Errorf("Expected 3 entries in GetAllPolicies (2 policies + database_accessed marker), got %d", len(allPolicies))
	}
	if _, ok := allPolicies["policy-travel-001"]; !ok {
		t.Error("travel-us policy missing from cache — name collision likely overwrote it")
	}
	if _, ok := allPolicies["policy-vcdemo-999"]; !ok {
		t.Error("vc-demo policy missing from cache — name collision likely overwrote it")
	}

	time.Sleep(50 * time.Millisecond)
}
