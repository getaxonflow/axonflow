// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Evaluation-tier example (Go SDK variant) for Issue #1673 retry-aware
// dynamic policy. See ../http/main.go for the rationale; this program does
// the same thing through the axonflow-sdk-go client, with the policy
// created via a raw HTTP call (the Go SDK does not expose a
// createPolicy helper).
//
// ⚠️ Evaluation or Enterprise license required — dynamic policy creation
// has tier limits; Community licenses may hit the policy-count cap.
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

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
)

const policyName = "Retry on gated-not-completed wire requires approval"

type policyCreateResp struct {
	Policy struct {
		ID string `json:"id"`
	} `json:"policy"`
}

func createRetryAwarePolicy(baseURL, clientID, clientSecret string) string {
	body := map[string]interface{}{
		"name":        policyName,
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
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", baseURL+"/api/v1/policies", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		fail("create policy: " + err.Error())
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		fail(fmt.Sprintf("create policy: status=%d body=%s", resp.StatusCode, data))
	}
	var pr policyCreateResp
	_ = json.Unmarshal(data, &pr)
	if pr.Policy.ID == "" {
		fail(fmt.Sprintf("create policy: empty policy.id in response, body=%s", data))
	}
	return pr.Policy.ID
}

func deletePolicy(baseURL, clientID, clientSecret, policyID string) {
	req, _ := http.NewRequest("DELETE", baseURL+"/api/v1/policies/"+url.PathEscape(policyID), nil)
	req.SetBasicAuth(clientID, clientSecret)
	resp, _ := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if resp != nil {
		resp.Body.Close()
	}
}

func main() {
	baseURL := envOrDefault("AXONFLOW_BASE_URL", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "demo")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret")

	banner("Retry-aware policy (Go SDK, Evaluation tier)")

	policyID := createRetryAwarePolicy(baseURL, clientID, clientSecret)
	fmt.Printf("  policy created: %s\n", policyID)
	defer deletePolicy(baseURL, clientID, clientSecret, policyID)

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: baseURL, ClientID: clientID, ClientSecret: clientSecret,
	})

	wf, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "eval-retry-aware-go",
	})
	must(err, "create workflow")
	fmt.Printf("  workflow: %s\n", wf.WorkflowID)

	toolCtx := &axonflow.ToolContext{
		ToolName: "core_banking_transfer", ToolType: "api",
	}
	req := axonflow.StepGateRequest{
		StepName: "Initiate Wire", StepType: axonflow.StepTypeToolCall,
		StepInput:   map[string]interface{}{"amount_eur": 750, "to_account": "1234"},
		ToolContext: toolCtx,
	}

	// 1) First gate — allow.
	first, err := client.StepGate(wf.WorkflowID, "step-1", req)
	must(err, "first gate")
	if first.Decision != axonflow.GateDecisionAllow {
		fail(fmt.Sprintf("first gate: want allow, got %s", first.Decision))
	}
	fmt.Println("  first gate: allow (gate_count=1, policy doesn't fire) ✔")

	// 2) Second gate, default retry_policy — cached allow, policy bypassed.
	cached, err := client.StepGate(wf.WorkflowID, "step-1", req)
	must(err, "cached gate")
	if !cached.Cached {
		fail("second gate should be cached")
	}
	if cached.Decision != axonflow.GateDecisionAllow {
		fail(fmt.Sprintf("second gate: want allow (cache bypasses policy), got %s", cached.Decision))
	}
	fmt.Println("  second gate cached: still allow (cache bypasses policy) ✔")

	// 3) Reevaluate — retry-aware policy fires.
	reevaluate := req
	reevaluate.RetryPolicy = axonflow.RetryPolicyReevaluate
	third, err := client.StepGate(wf.WorkflowID, "step-1", reevaluate)
	must(err, "reevaluate gate")
	if third.Cached {
		fail("reevaluate gate should not be cached")
	}
	if third.Decision != axonflow.GateDecisionRequireApproval {
		fail(fmt.Sprintf("reevaluate gate: want require_approval (retry-aware policy), got %s (%s)", third.Decision, third.Reason))
	}
	fmt.Println("  third gate (reevaluate): require_approval (policy FIRED) ✔")

	banner("Evaluation-tier Go SDK demo passed ✔")
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

func getEnv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func must(err error, label string) {
	if err != nil {
		fail(label + ": " + err.Error())
	}
}
func fail(msg string) { fmt.Fprintln(os.Stderr, "FAIL: "+msg); os.Exit(1) }
func banner(s string) { fmt.Println(); fmt.Println("━━━", s, "━━━") }
