// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Evaluation-tier example for Issue #1673: retry-aware policy authoring.
//
// Exercises the policy engine side of retry_context — the Community-tier
// primitives (counters, status, idempotency_key) are always visible; what
// the Evaluation tier unlocks is the ability to write policy conditions
// against them:
//
//   step.gate_count                 (int)
//   step.completion_count           (int)
//   step.prior_completion_status    ("none" | "completed" | "gated_not_completed")
//   step.prior_output_available     (bool)
//   step.last_decision              ("allow" | "block" | "require_approval")
//   step.first_attempt_age_seconds  (int)
//   step.idempotency_key            (string, equals/regex)
//
// The demo creates a dynamic policy —
//     "if step.gate_count > 1 AND step.prior_completion_status ==
//      'gated_not_completed' AND tool_name == 'core_banking_transfer',
//      then require_approval"
// — that only fires on the uncertain-territory retry case. We then:
//   1. Verify first gate: policy does NOT fire (gate_count == 1).
//   2. Skip /complete (simulate agent crash between gate and complete).
//   3. Re-gate same step: policy NOW fires, returns require_approval.
//
// ⚠️ EVALUATION OR ENTERPRISE LICENSE REQUIRED
// Dynamic-policy authoring is gated at the Evaluation tier and above.
// On Community, this example will fail on policy creation with a
// tier-denial error. Use `./scripts/setup-e2e-testing.sh evaluation`
// or `enterprise` to boot a stack that accepts this flow.
//
// Usage:
//   ./scripts/setup-e2e-testing.sh enterprise
//   source /tmp/axonflow-e2e-env.sh
//   export AXONFLOW_BASE_URL=http://localhost:8080
//   cd examples/wcp-retry-idempotency/evaluation/http
//   go run main.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type client struct {
	baseURL      string
	clientID     string
	clientSecret string
	http         *http.Client
}

func (c *client) auth(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.clientID, c.clientSecret)
}

func (c *client) do(method, path string, body interface{}) (int, []byte) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.baseURL+path, rdr)
	c.auth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		fail(method + " " + path + ": " + err.Error())
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// createRetryAwarePolicy authors a dynamic policy that require_approval's
// ANY retry on a core_banking_transfer step where no prior /complete landed.
// Returns the policy_id so we can delete it at teardown.
func createRetryAwarePolicy(c *client) string {
	body := map[string]interface{}{
		"name":        "Retry on gated-not-completed wire requires approval",
		"description": "Human verification required before re-executing a wire when the prior attempt never completed.",
		"type":        "context_aware",
		"priority":    100,
		"enabled":     true,
		"conditions": []map[string]interface{}{
			{"field": "step.gate_count", "operator": "greater_than", "value": 1},
			{"field": "step.prior_completion_status", "operator": "equals", "value": "gated_not_completed"},
			{"field": "context.tool_name", "operator": "equals", "value": "core_banking_transfer"},
		},
		"actions": []map[string]interface{}{
			{
				"type": "require_approval",
				"config": map[string]string{
					"reason":   "Retry on un-completed wire — verify with bank before re-execution",
					"severity": "high",
				},
			},
		},
	}
	code, raw := c.do("POST", "/api/v1/policies", body)
	if code != http.StatusCreated && code != http.StatusOK {
		fail(fmt.Sprintf("create policy: status=%d body=%s", code, raw))
	}
	var resp struct {
		Policy struct {
			ID string `json:"id"`
		} `json:"policy"`
	}
	_ = json.Unmarshal(raw, &resp)
	if resp.Policy.ID == "" {
		fail(fmt.Sprintf("create policy: empty policy.id in response, body=%s", raw))
	}
	fmt.Printf("  policy created: %s\n", resp.Policy.ID)
	return resp.Policy.ID
}

func deletePolicy(c *client, policyID string) {
	c.do("DELETE", "/api/v1/policies/"+url.PathEscape(policyID), nil)
}

func createWorkflow(c *client, name string) string {
	code, raw := c.do("POST", "/api/v1/workflows", map[string]string{"workflow_name": name})
	if code != http.StatusOK && code != http.StatusCreated {
		fail(fmt.Sprintf("create workflow: status=%d body=%s", code, raw))
	}
	var resp struct {
		WorkflowID string `json:"workflow_id"`
	}
	_ = json.Unmarshal(raw, &resp)
	return resp.WorkflowID
}

type gateResponse struct {
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	Cached         bool   `json:"cached"`
	DecisionSource string `json:"decision_source"`
	RetryContext   struct {
		GateCount             int    `json:"gate_count"`
		CompletionCount       int    `json:"completion_count"`
		PriorCompletionStatus string `json:"prior_completion_status"`
		LastDecision          string `json:"last_decision"`
	} `json:"retry_context"`
}

// gate sends a /gate call. retryPolicy is the value for the `retry_policy`
// request field — empty string means server default ("idempotent"). Callers
// that want retry-aware policies to fire MUST pass "reevaluate" on retries,
// otherwise the server returns the cached decision without running the
// policy engine.
func gate(c *client, wfID, stepID, retryPolicy string) *gateResponse {
	body := map[string]interface{}{
		"step_name": "Initiate Wire",
		"step_type": "tool_call",
		"step_input": map[string]interface{}{
			"amount_eur":  750,
			"to_account":  "1234",
			"description": "retry-aware-policy demo",
		},
		"tool_context": map[string]string{
			"tool_name": "core_banking_transfer",
			"tool_type": "api",
		},
	}
	if retryPolicy != "" {
		body["retry_policy"] = retryPolicy
	}
	code, raw := c.do("POST", "/api/v1/workflows/"+url.PathEscape(wfID)+"/steps/"+url.PathEscape(stepID)+"/gate", body)
	if code != http.StatusOK {
		fail(fmt.Sprintf("gate %s/%s: status=%d body=%s", wfID, stepID, code, raw))
	}
	var g gateResponse
	if err := json.Unmarshal(raw, &g); err != nil {
		fail("gate unmarshal: " + err.Error())
	}
	return &g
}

func main() {
	baseURL := envOrDefault("AXONFLOW_BASE_URL", "http://localhost:8080")
	c := &client{
		baseURL:      baseURL,
		clientID:     mustEnv("AXONFLOW_CLIENT_ID"),
		clientSecret: mustEnv("AXONFLOW_CLIENT_SECRET"),
		http:         &http.Client{Timeout: 10 * time.Second},
	}

	banner("Retry-aware policy (Evaluation tier)")

	// Setup: author the retry-aware policy. Clean up at the end even if
	// assertions fail partway — leaving a stray policy around breaks later
	// runs.
	policyID := createRetryAwarePolicy(c)
	defer deletePolicy(c, policyID)

	wfID := createWorkflow(c, "retry-aware-policy-demo")
	fmt.Printf("  workflow: %s\n", wfID)

	// 1. First gate — policy does NOT fire because step.gate_count == 1.
	//    Uses default retry_policy (idempotent); policy engine runs because
	//    there's no cached decision yet.
	resp := gate(c, wfID, "step-1", "")
	if resp.Decision != "allow" {
		fail(fmt.Sprintf("first gate: want allow (gate_count=1, policy shouldn't fire), got %s (%s)", resp.Decision, resp.Reason))
	}
	if resp.RetryContext.GateCount != 1 {
		fail(fmt.Sprintf("first gate: gate_count want 1, got %d", resp.RetryContext.GateCount))
	}
	fmt.Println("  first gate: allow (gate_count=1, policy doesn't fire) ✔")

	// 2. Demonstrate the cache-bypass pitfall: default retry_policy on retry
	//    returns the cached decision without consulting the policy engine,
	//    so retry-aware conditions DO NOT fire even if their conditions
	//    would match. This assertion locks the current semantics — if a
	//    future change makes retry-aware policies fire on cached retries,
	//    this line will fail and prompt a deliberate update.
	cached := gate(c, wfID, "step-1", "")
	if !cached.Cached {
		fail("second gate should be cached under default retry_policy")
	}
	if cached.Decision != "allow" {
		fail(fmt.Sprintf("second gate (cached): want allow (cached bypasses policy), got %s (%s)", cached.Decision, cached.Reason))
	}
	if cached.RetryContext.GateCount != 2 {
		fail(fmt.Sprintf("second gate: gate_count want 2, got %d", cached.RetryContext.GateCount))
	}
	fmt.Println("  second gate cached: still allow (cache bypasses policy) ✔")

	// 3. Reevaluate — NO /complete, so prior_completion_status is
	//    gated_not_completed. With retry_policy=reevaluate the policy
	//    engine runs fresh and the retry-aware condition fires.
	resp = gate(c, wfID, "step-1", "reevaluate")
	if resp.Cached {
		fail("third gate should not be cached (retry_policy=reevaluate)")
	}
	if resp.RetryContext.GateCount != 3 {
		fail(fmt.Sprintf("third gate: gate_count want 3, got %d", resp.RetryContext.GateCount))
	}
	if resp.RetryContext.PriorCompletionStatus != "gated_not_completed" {
		fail(fmt.Sprintf("third gate: prior_completion_status want gated_not_completed, got %s", resp.RetryContext.PriorCompletionStatus))
	}
	if resp.Decision != "require_approval" {
		fail(fmt.Sprintf("third gate: want require_approval (retry-aware policy fires on reevaluate), got %s (%s)", resp.Decision, resp.Reason))
	}
	fmt.Println("  third gate (reevaluate): require_approval (retry-aware policy FIRED) ✔")

	banner("Evaluation-tier policy demo passed ✔")
}

func envOrDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fail("missing env: " + k)
	}
	return v
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "FAIL: "+msg)
	os.Exit(1)
}

func banner(s string) {
	fmt.Println()
	fmt.Println("━━━", s, "━━━")
}
