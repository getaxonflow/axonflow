// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// WCP retry_context + idempotency_key demo (Issue #1673 Phase 1 + Phase 2)
//
// Demonstrates the two new primitives together, using raw HTTP so the wire
// shape is obvious. Every assertion is checked — the example exits 1 on any
// contract deviation.
//
// The story:
//
//   Act 1 — retry_context exposes first-class state
//     1. Create a workflow, call /gate on step-1. Assert retry_context has
//        gate_count=1, completion_count=0, prior_completion_status=none,
//        last_decision=decision (first-call invariant).
//     2. Call /complete for step-1. Then re-gate step-1. Assert
//        gate_count=2, completion_count=1, prior_completion_status=completed,
//        prior_output_available=true.
//     3. On a DIFFERENT step, call /gate only (simulating agent crash between
//        gate and complete). Re-gate. Assert prior_completion_status=
//        gated_not_completed — the state an agent sees when it must reconcile
//        with the downstream system before re-executing.
//     4. Re-gate with ?include_prior_output=true on the completed step and
//        assert prior_output is populated with the payload from /complete.
//
//   Act 2 — idempotency_key as a first-class business-level key
//     5. Create a new workflow, gate step-1 with idempotency_key="payment:K1".
//        Assert retry_context.idempotency_key echoes back.
//     6. Re-gate step-1 with a DIFFERENT key "payment:K2" and assert the
//        server returns 409 IDEMPOTENCY_KEY_MISMATCH with expected/received
//        keys on the error envelope.
//     7. /complete step-1 with the matching original key and assert success.
//
// Usage:
//
//   # Boot enterprise stack via the E2E setup script
//   ./scripts/setup-e2e-testing.sh
//   # Then (the script exports these into your shell):
//   export AXONFLOW_BASE_URL=http://localhost:8080
//   export AXONFLOW_CLIENT_ID=demo-org
//   export AXONFLOW_CLIENT_SECRET="<license key from setup-e2e-testing.sh>"
//   go run main.go
//
// Auth: HTTP Basic with client_id + client_secret, the same scheme the
// AxonFlow SDKs use. The agent validates Basic credentials against the
// license database, then injects X-Tenant-ID / X-Org-ID / X-User-ID when
// proxying to the orchestrator.
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

// --- wire types mirror platform/orchestrator/workflow_control/types.go ---

type stepGateRequest struct {
	StepName       string      `json:"step_name,omitempty"`
	StepType       string      `json:"step_type"`
	StepInput      interface{} `json:"step_input,omitempty"`
	ToolContext    interface{} `json:"tool_context,omitempty"`
	RetryPolicy    string      `json:"retry_policy,omitempty"`
	IdempotencyKey string      `json:"idempotency_key,omitempty"`
}

type retryContext struct {
	GateCount             int                    `json:"gate_count"`
	CompletionCount       int                    `json:"completion_count"`
	PriorCompletionStatus string                 `json:"prior_completion_status"`
	PriorOutputAvailable  bool                   `json:"prior_output_available"`
	PriorOutput           map[string]interface{} `json:"prior_output"`
	PriorCompletionAt     *time.Time             `json:"prior_completion_at"`
	FirstAttemptAt        time.Time              `json:"first_attempt_at"`
	LastAttemptAt         time.Time              `json:"last_attempt_at"`
	LastDecision          string                 `json:"last_decision"`
	IdempotencyKey        string                 `json:"idempotency_key,omitempty"`
}

type stepGateResponse struct {
	Decision       string       `json:"decision"`
	StepID         string       `json:"step_id"`
	Reason         string       `json:"reason"`
	Cached         bool         `json:"cached"`
	DecisionSource string       `json:"decision_source"`
	RetryContext   retryContext `json:"retry_context"`
}

type stepCompleteRequest struct {
	Output         map[string]interface{} `json:"output,omitempty"`
	IdempotencyKey string                 `json:"idempotency_key,omitempty"`
}

type apiErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details struct {
			WorkflowID             string `json:"workflow_id"`
			StepID                 string `json:"step_id"`
			ExpectedIdempotencyKey string `json:"expected_idempotency_key"`
			ReceivedIdempotencyKey string `json:"received_idempotency_key"`
		} `json:"details"`
	} `json:"error"`
}

// --- demo ---

func main() {
	baseURL := envOrDie("AXONFLOW_BASE_URL", "http://localhost:8080")
	clientID := envOrDie("AXONFLOW_CLIENT_ID")
	clientSecret := envOrDie("AXONFLOW_CLIENT_SECRET")

	c := &client{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		http:         &http.Client{Timeout: 10 * time.Second},
	}

	banner("Act 1 — retry_context")
	act1(c)

	banner("Act 2 — idempotency_key")
	act2(c)

	banner("All assertions passed ✔")
}

func act1(c *client) {
	wfID := c.createWorkflow("retry-context-demo")
	fmt.Printf("workflow: %s\n", wfID)

	// 1. First gate on step-1
	resp := c.gate(wfID, "step-1", stepGateRequest{StepType: "tool_call", StepName: "first-step"}, false)
	assertRetryContext("first gate", resp.RetryContext, expect{
		gateCount:             1,
		completionCount:       0,
		priorCompletionStatus: "none",
		lastDecision:          resp.Decision, // first-call invariant
	})
	assert(!resp.Cached, "first gate: want cached=false")

	// 2. Complete step-1, then re-gate
	c.complete(wfID, "step-1", stepCompleteRequest{Output: map[string]interface{}{
		"transfer_id": "TXN-retry-demo-1",
		"amount":      500,
	}})
	resp = c.gate(wfID, "step-1", stepGateRequest{StepType: "tool_call"}, false)
	assertRetryContext("re-gate post-complete", resp.RetryContext, expect{
		gateCount:             2,
		completionCount:       1,
		priorCompletionStatus: "completed",
		priorOutputAvailable:  true,
	})
	assert(resp.Cached, "re-gate post-complete: want cached=true")
	assert(resp.RetryContext.PriorOutput == nil,
		"re-gate without include_prior_output: PriorOutput must be nil")

	// 3. Gate on step-2 WITHOUT complete — simulate agent crash
	c.gate(wfID, "step-2", stepGateRequest{StepType: "tool_call", StepName: "second-step"}, false)
	resp = c.gate(wfID, "step-2", stepGateRequest{StepType: "tool_call"}, false)
	assertRetryContext("re-gate without complete", resp.RetryContext, expect{
		gateCount:             2,
		completionCount:       0,
		priorCompletionStatus: "gated_not_completed",
	})

	// 4. Re-gate step-1 with include_prior_output=true
	resp = c.gate(wfID, "step-1", stepGateRequest{StepType: "tool_call"}, true)
	assert(resp.RetryContext.PriorOutput != nil,
		"include_prior_output=true: prior_output must be populated")
	assertEqual("prior_output.transfer_id", "TXN-retry-demo-1",
		fmt.Sprint(resp.RetryContext.PriorOutput["transfer_id"]))
	fmt.Println("  prior_output payload recovered across retry ✔")
}

func act2(c *client) {
	wfID := c.createWorkflow("idempotency-key-demo")
	fmt.Printf("workflow: %s\n", wfID)

	originalKey := "payment:wire:invoice-1"

	// 5. First gate with key — echoed back
	resp := c.gate(wfID, "step-1",
		stepGateRequest{StepType: "tool_call", StepName: "wire", IdempotencyKey: originalKey}, false)
	assertEqual("gate 1 retry_context.idempotency_key", originalKey, resp.RetryContext.IdempotencyKey)

	// 6. Re-gate with different key → 409
	code, body := c.gateRaw(wfID, "step-1",
		stepGateRequest{StepType: "tool_call", IdempotencyKey: "payment:wire:invoice-2"}, false)
	assertEqual("mismatch status", "409", fmt.Sprintf("%d", code))
	var errEnv apiErrorResponse
	if err := json.Unmarshal(body, &errEnv); err != nil {
		fail("mismatch body unmarshal: " + err.Error())
	}
	assertEqual("mismatch error.code", "IDEMPOTENCY_KEY_MISMATCH", errEnv.Error.Code)
	assertEqual("mismatch expected_key", originalKey, errEnv.Error.Details.ExpectedIdempotencyKey)
	assertEqual("mismatch received_key", "payment:wire:invoice-2", errEnv.Error.Details.ReceivedIdempotencyKey)
	assertEqual("mismatch workflow_id", wfID, errEnv.Error.Details.WorkflowID)
	assertEqual("mismatch step_id", "step-1", errEnv.Error.Details.StepID)
	fmt.Println("  409 envelope shape verified ✔")

	// 7. Complete with matching key
	c.complete(wfID, "step-1", stepCompleteRequest{
		Output:         map[string]interface{}{"transfer_id": "TXN-K1"},
		IdempotencyKey: originalKey,
	})
	fmt.Println("  complete with matching key succeeded ✔")
}

// --- http helper ---

type client struct {
	baseURL      string
	clientID     string
	clientSecret string
	http         *http.Client
}

// authHeaders applies Basic auth + Content-Type on a prepared request.
// This matches what the AxonFlow SDKs do internally (see
// axonflow-sdk-go's http.Request.SetBasicAuth usage).
func (c *client) authHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.clientID, c.clientSecret)
}

func (c *client) createWorkflow(name string) string {
	body, _ := json.Marshal(map[string]string{"workflow_name": name})
	req, _ := http.NewRequest(http.MethodPost, c.baseURL+"/api/v1/workflows", bytes.NewReader(body))
	c.authHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		fail("createWorkflow: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		fail(fmt.Sprintf("createWorkflow status=%d body=%s", resp.StatusCode, string(raw)))
	}
	var wf struct {
		WorkflowID string `json:"workflow_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&wf)
	if wf.WorkflowID == "" {
		fail("createWorkflow: empty workflow_id")
	}
	return wf.WorkflowID
}

func (c *client) gate(wfID, stepID string, req stepGateRequest, includePriorOutput bool) *stepGateResponse {
	code, body := c.gateRaw(wfID, stepID, req, includePriorOutput)
	if code != http.StatusOK {
		fail(fmt.Sprintf("gate status=%d body=%s", code, string(body)))
	}
	var resp stepGateResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fail("gate unmarshal: " + err.Error())
	}
	return &resp
}

func (c *client) gateRaw(wfID, stepID string, req stepGateRequest, includePriorOutput bool) (int, []byte) {
	body, _ := json.Marshal(req)
	u := fmt.Sprintf("%s/api/v1/workflows/%s/steps/%s/gate",
		c.baseURL, url.PathEscape(wfID), url.PathEscape(stepID))
	if includePriorOutput {
		u += "?include_prior_output=true"
	}
	httpReq, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	c.authHeaders(httpReq)
	resp, err := c.http.Do(httpReq)
	if err != nil {
		fail("gate: " + err.Error())
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func (c *client) complete(wfID, stepID string, req stepCompleteRequest) {
	body, _ := json.Marshal(req)
	u := fmt.Sprintf("%s/api/v1/workflows/%s/steps/%s/complete",
		c.baseURL, url.PathEscape(wfID), url.PathEscape(stepID))
	httpReq, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	c.authHeaders(httpReq)
	resp, err := c.http.Do(httpReq)
	if err != nil {
		fail("complete: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(resp.Body)
		fail(fmt.Sprintf("complete status=%d body=%s", resp.StatusCode, string(raw)))
	}
}

// --- tiny assertion helpers ---

type expect struct {
	gateCount             int
	completionCount       int
	priorCompletionStatus string
	priorOutputAvailable  bool
	lastDecision          string
}

func assertRetryContext(label string, rc retryContext, want expect) {
	if rc.GateCount != want.gateCount {
		fail(fmt.Sprintf("%s: gate_count want %d, got %d", label, want.gateCount, rc.GateCount))
	}
	if rc.CompletionCount != want.completionCount {
		fail(fmt.Sprintf("%s: completion_count want %d, got %d", label, want.completionCount, rc.CompletionCount))
	}
	if rc.PriorCompletionStatus != want.priorCompletionStatus {
		fail(fmt.Sprintf("%s: prior_completion_status want %q, got %q", label, want.priorCompletionStatus, rc.PriorCompletionStatus))
	}
	if want.priorOutputAvailable != rc.PriorOutputAvailable {
		fail(fmt.Sprintf("%s: prior_output_available want %v, got %v", label, want.priorOutputAvailable, rc.PriorOutputAvailable))
	}
	if want.lastDecision != "" && rc.LastDecision != want.lastDecision {
		fail(fmt.Sprintf("%s: last_decision want %q, got %q", label, want.lastDecision, rc.LastDecision))
	}
	fmt.Printf("  %s: gate_count=%d completion_count=%d status=%s ✔\n",
		label, rc.GateCount, rc.CompletionCount, rc.PriorCompletionStatus)
}

func assert(cond bool, msg string) {
	if !cond {
		fail(msg)
	}
}

func assertEqual(label, want, got string) {
	if want != got {
		fail(fmt.Sprintf("%s: want %q, got %q", label, want, got))
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "FAIL: "+msg)
	os.Exit(1)
}

func banner(s string) {
	fmt.Println()
	fmt.Println("━━━", s, "━━━")
}

func envOrDie(key string, optionalDefault ...string) string {
	v := os.Getenv(key)
	if v != "" {
		return v
	}
	if len(optionalDefault) > 0 {
		return optionalDefault[0]
	}
	fail("missing required env var: " + key)
	return "" // unreachable
}
