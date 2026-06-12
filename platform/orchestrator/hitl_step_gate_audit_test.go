// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"testing"

	sharedaudit "axonflow/platform/shared/audit"
)

// #2693 — legacy in-memory HITL gate-decision audit. The HITLWorkflowEngine
// (AXONFLOW_HITL_ENABLED, default-OFF) ENFORCES block / require_approval policy
// verdicts — failing the workflow on block, pausing on require_approval — but
// previously left no audit row, asymmetric with the WCP path. These tests prove
// each gated verdict now emits a canonical step_gate audit_logs entry via the
// established LogWorkflowOperation writer (no new writer/table), mapped onto the
// canonical policy_decision vocabulary. Red-on-revert: drop the auditStepGate
// call from a switch arm and the entry count assertion fails.

// recordingHITLAudit captures the WorkflowAuditEntry the engine emits, so the
// step_gate decision can be asserted deterministically with no async worker or
// database. It satisfies the engine's hitlAuditLogger interface.
type recordingHITLAudit struct {
	entries []*WorkflowAuditEntry
}

func (r *recordingHITLAudit) LogWorkflowOperation(_ context.Context, e *WorkflowAuditEntry) {
	r.entries = append(r.entries, e)
}

func newGateTestEngine() *WorkflowEngine {
	return &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}
}

func gateTestWorkflow() Workflow {
	return Workflow{
		Metadata: WorkflowMetadata{Name: "wf-gate"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{{Name: "step1", Type: "llm-call"}},
		},
	}
}

func gateTestUser() UserContext {
	return UserContext{TenantID: "tenant-1", OrgID: "org-1", Email: "user@org-1.example", Role: "analyst"}
}

func TestHITLWorkflowEngine_Block_WritesStepGateAudit(t *testing.T) {
	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{
		Allowed:    false,
		Action:     "block",
		PolicyID:   "policy-456",
		PolicyName: "SQL Injection",
		Reason:     "SQL injection detected",
		Severity:   "critical",
	})
	hitlEngine := NewHITLWorkflowEngine(newGateTestEngine(), checker, nil)
	rec := &recordingHITLAudit{}
	hitlEngine.SetAuditLogger(rec)

	_, err := hitlEngine.ExecuteWithHITL(context.Background(), gateTestWorkflow(), map[string]interface{}{}, gateTestUser())
	if err == nil {
		t.Fatal("expected a block error from ExecuteWithHITL")
	}

	if len(rec.entries) != 1 {
		t.Fatalf("block must emit exactly one step_gate audit entry, got %d", len(rec.entries))
	}
	e := rec.entries[0]
	assertGateEntry(t, e, "block", sharedaudit.DecisionBlocked)
}

func TestHITLWorkflowEngine_RequireApproval_WritesStepGateAudit(t *testing.T) {
	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{
		Allowed:    false,
		Action:     "require_approval",
		PolicyID:   "policy-123",
		PolicyName: "High Risk Query",
		Reason:     "Query requires human oversight",
		Severity:   "high",
	})
	hitlEngine := NewHITLWorkflowEngine(newGateTestEngine(), checker, NewMockApprovalService())
	rec := &recordingHITLAudit{}
	hitlEngine.SetAuditLogger(rec)

	exec, err := hitlEngine.ExecuteWithHITL(context.Background(), gateTestWorkflow(), map[string]interface{}{}, gateTestUser())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exec.Status != StatusPaused {
		t.Fatalf("status = %q, want paused", exec.Status)
	}

	if len(rec.entries) != 1 {
		t.Fatalf("require_approval must emit exactly one step_gate audit entry, got %d", len(rec.entries))
	}
	assertGateEntry(t, rec.entries[0], "require_approval", sharedaudit.DecisionNeedsApproval)
}

// TestHITLWorkflowEngine_Allowed_NoStepGateAudit: an allowed workflow gates
// nothing, so no step_gate row is written (audit is reserved for the
// block/require_approval terminal verdicts).
func TestHITLWorkflowEngine_Allowed_NoStepGateAudit(t *testing.T) {
	checker := NewMockPolicyChecker() // default → Allowed:true
	engine := newGateTestEngine()
	engine.stepProcessors["llm-call"] = &gateNoopProcessor{}
	hitlEngine := NewHITLWorkflowEngine(engine, checker, nil)
	rec := &recordingHITLAudit{}
	hitlEngine.SetAuditLogger(rec)

	exec, err := hitlEngine.ExecuteWithHITL(context.Background(), gateTestWorkflow(), map[string]interface{}{}, gateTestUser())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exec.Status != "completed" {
		t.Fatalf("status = %q, want completed", exec.Status)
	}
	if len(rec.entries) != 0 {
		t.Fatalf("allowed workflow must emit no step_gate audit, got %d", len(rec.entries))
	}
}

// TestHITLWorkflowEngine_Block_NoAuditLogger_NoPanic: with no audit logger wired
// (the default state), a block path must still enforce without panicking.
func TestHITLWorkflowEngine_Block_NoAuditLogger_NoPanic(t *testing.T) {
	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{Allowed: false, Action: "block", PolicyName: "p"})
	hitlEngine := NewHITLWorkflowEngine(newGateTestEngine(), checker, nil)
	// SetAuditLogger intentionally NOT called.

	if _, err := hitlEngine.ExecuteWithHITL(context.Background(), gateTestWorkflow(), map[string]interface{}{}, gateTestUser()); err == nil {
		t.Fatal("expected a block error")
	}
}

// TestHITLWorkflowEngine_PolicyError_WritesErrorStepGateAudit (#2698): when the
// policy checker returns an ERROR, the engine fails OPEN (proceeds for
// availability) — but the errored governance verdict must no longer be lost. It
// now emits a canonical `error` step_gate audit row, while the workflow still
// runs to completion (fail-open behavior unchanged). Red-on-revert: drop the
// auditStepGateError call and the entry-count assertion fails.
func TestHITLWorkflowEngine_PolicyError_WritesErrorStepGateAudit(t *testing.T) {
	checker := NewMockPolicyChecker()
	checker.SetError(errors.New("policy engine unreachable"))
	engine := newGateTestEngine()
	engine.stepProcessors["llm-call"] = &gateNoopProcessor{}
	hitlEngine := NewHITLWorkflowEngine(engine, checker, nil)
	rec := &recordingHITLAudit{}
	hitlEngine.SetAuditLogger(rec)

	exec, err := hitlEngine.ExecuteWithHITL(context.Background(), gateTestWorkflow(), map[string]interface{}{}, gateTestUser())
	if err != nil {
		t.Fatalf("fail-open: expected no error from ExecuteWithHITL, got %v", err)
	}
	if exec.Status != "completed" {
		t.Fatalf("fail-open must proceed to completion, status = %q", exec.Status)
	}

	if len(rec.entries) != 1 {
		t.Fatalf("a policy-check error must emit exactly one error step_gate audit entry, got %d", len(rec.entries))
	}
	e := rec.entries[0]
	if e.Operation != "step_gate" {
		t.Errorf("Operation = %q, want step_gate", e.Operation)
	}
	if e.Decision != "error" {
		t.Errorf("Decision = %q, want error", e.Decision)
	}
	if got := workflowAuditDecision(e.Decision); got != sharedaudit.DecisionError {
		t.Errorf("canonical decision = %q, want %q (must NOT default to allowed)", got, sharedaudit.DecisionError)
	}
	if e.TenantID != "tenant-1" || e.OrgID != "org-1" {
		t.Errorf("tenant/org = %q/%q, want tenant-1/org-1", e.TenantID, e.OrgID)
	}
	if fo, ok := e.Metadata["fail_open"].(bool); !ok || !fo {
		t.Errorf("Metadata[fail_open] = %v, want true", e.Metadata["fail_open"])
	}
}

// TestHITLWorkflowEngine_PolicyError_NoAuditLogger_NoPanic (#2698): with no audit
// logger wired (the default state), the fail-open error path must still proceed
// without panicking.
func TestHITLWorkflowEngine_PolicyError_NoAuditLogger_NoPanic(t *testing.T) {
	checker := NewMockPolicyChecker()
	checker.SetError(errors.New("policy engine unreachable"))
	engine := newGateTestEngine()
	engine.stepProcessors["llm-call"] = &gateNoopProcessor{}
	hitlEngine := NewHITLWorkflowEngine(engine, checker, nil)
	// SetAuditLogger intentionally NOT called.

	exec, err := hitlEngine.ExecuteWithHITL(context.Background(), gateTestWorkflow(), map[string]interface{}{}, gateTestUser())
	if err != nil {
		t.Fatalf("fail-open with no logger: expected no error, got %v", err)
	}
	if exec.Status != "completed" {
		t.Fatalf("status = %q, want completed", exec.Status)
	}
}

// TestWorkflowAuditDecision_ErrorMapsToCanonicalError (#2698): the `error`
// decision token must map to the canonical DecisionError, never fall through to
// the `allowed` default (which would inflate the allowed/compliance counts).
func TestWorkflowAuditDecision_ErrorMapsToCanonicalError(t *testing.T) {
	if got := workflowAuditDecision("error"); got != sharedaudit.DecisionError {
		t.Errorf("workflowAuditDecision(error) = %q, want %q", got, sharedaudit.DecisionError)
	}
	// Guard the existing mappings stay intact.
	if got := workflowAuditDecision("block"); got != sharedaudit.DecisionBlocked {
		t.Errorf("workflowAuditDecision(block) = %q, want %q", got, sharedaudit.DecisionBlocked)
	}
	if got := workflowAuditDecision("anything-else"); got != sharedaudit.DecisionAllowed {
		t.Errorf("workflowAuditDecision(unknown) = %q, want %q (default)", got, sharedaudit.DecisionAllowed)
	}
}

func assertGateEntry(t *testing.T, e *WorkflowAuditEntry, wantDecision, wantCanonical string) {
	t.Helper()
	if e.Operation != "step_gate" {
		t.Errorf("Operation = %q, want step_gate", e.Operation)
	}
	if e.Decision != wantDecision {
		t.Errorf("Decision = %q, want %q", e.Decision, wantDecision)
	}
	if got := workflowAuditDecision(e.Decision); got != wantCanonical {
		t.Errorf("canonical decision = %q, want %q", got, wantCanonical)
	}
	if e.WorkflowName != "wf-gate" || e.StepName != "step1" {
		t.Errorf("workflow/step = %q/%q, want wf-gate/step1", e.WorkflowName, e.StepName)
	}
	if e.TenantID != "tenant-1" || e.OrgID != "org-1" {
		t.Errorf("tenant/org = %q/%q, want tenant-1/org-1", e.TenantID, e.OrgID)
	}
	if e.UserEmail != "user@org-1.example" {
		t.Errorf("UserEmail = %q", e.UserEmail)
	}
}

// gateNoopProcessor is a StepProcessor that completes immediately, used to drive
// the allowed (no-gate) path to completion.
type gateNoopProcessor struct{}

func (gateNoopProcessor) ExecuteStep(_ context.Context, _ WorkflowStep, _ map[string]interface{}, _ *WorkflowExecution) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}
