// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

// #3281 (ADR-060 #2989 P3b) - threading tests for the trust-gated caller
// email from the HTTP request through to StepGateContext, which the
// orchestrator's WCPPolicyAdapter (platform/orchestrator/wcp_policy_adapter.go)
// consumes to resolve governance segments. This package cannot exercise
// segment resolution itself (that lives in the orchestrator package, see
// wcp_policy_adapter_segment_3281_test.go there) - these tests pin the
// wiring on THIS side of the package boundary: X-User-Email header ->
// StepGateRequest.Email -> StepGateContext.Email, and that GateOverride
// still bypasses the evaluator entirely even when Email is populated.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gorilla/mux"
)

// (v) GateOverride != nil still short-circuits and does not resolve: the
// evaluator (the only thing that could reach segment resolution) must never
// be called on this path, regardless of whether a verified Email is present
// on the request. A regression here would mean MAP confirm/step mode
// started resolving/denying based on segments, which is explicitly out of
// scope for #3281 (see resumePlanHandler / service.go's GateOverride
// short-circuit).
func TestStepGate_GateOverride_DoesNotInvokeEvaluator_WithEmailSet(t *testing.T) {
	counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	svc, _ := setupTestService(counter)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	override := GateDecisionRequireApproval
	resp, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType:     StepTypeToolCall,
		GateOverride: &override,
		Email:        "alice@example.com", // verified identity present, but must be irrelevant here
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}
	if resp.Decision != GateDecisionRequireApproval {
		t.Errorf("expected require_approval from override, got %s", resp.Decision)
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("expected evaluator to NOT be called with GateOverride set (segment resolution must not run), was called %d times", calls)
	}
}

// Baseline: with NO override, the same Email DOES reach the evaluator via
// StepGateContext - proves the two tests together actually distinguish
// "override skips evaluation" from "Email is silently dropped some other
// way" rather than both vacuously passing.
func TestStepGate_NoOverride_EmailReachesEvaluator(t *testing.T) {
	evaluator := &contextCapturingEvaluator{decision: GateDecisionAllow}
	svc, _ := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
		Email:    "alice@example.com",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}
	if evaluator.lastCtx == nil {
		t.Fatal("evaluator was not called")
	}
	if evaluator.lastCtx.Email != "alice@example.com" {
		t.Errorf("StepGateContext.Email = %q, want alice@example.com", evaluator.lastCtx.Email)
	}
}

func setupTestHandlerWithEvaluator(evaluator PolicyEvaluator) (*Handler, *Service) {
	repo := NewMockRepository()
	svc := NewService(repo, evaluator, nil)
	handler := NewHandler(svc)
	return handler, svc
}

// TestStepGateHandler_ThreadsXUserEmailIntoStepGateContext proves the HTTP
// handler reads X-User-Email directly (not via getUserID, whose fallback
// chain can return a non-email X-User-ID) and threads it all the way to the
// StepGateContext the policy evaluator receives.
func TestStepGateHandler_ThreadsXUserEmailIntoStepGateContext(t *testing.T) {
	evaluator := &contextCapturingEvaluator{decision: GateDecisionAllow}
	handler, svc := setupTestHandlerWithEvaluator(evaluator)
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "wf"},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow failed: %v", err)
	}

	body, _ := json.Marshal(StepGateRequest{StepName: "s", StepType: StepTypeLLMCall})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/workflows/"+wf.WorkflowID+"/steps/step-1/gate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "12345") // numeric attribution id - must NOT be read as email
	req.Header.Set("X-User-Email", "verified@example.com")
	req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "step-1"})

	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if evaluator.lastCtx == nil {
		t.Fatal("evaluator was not called")
	}
	if evaluator.lastCtx.Email != "verified@example.com" {
		t.Errorf("StepGateContext.Email = %q, want verified@example.com", evaluator.lastCtx.Email)
	}
	// getUserID's own fallback (X-User-ID present) must still populate
	// UserID for attribution - this test is about ADDING Email, not
	// changing UserID's existing resolution.
	if evaluator.lastCtx.UserID != "12345" {
		t.Errorf("StepGateContext.UserID = %q, want 12345 (attribution unaffected by this change)", evaluator.lastCtx.UserID)
	}
}

// TestStepGateHandler_NoXUserEmailHeader_EmptyEmail proves the absence of a
// verified identity is threaded as an empty string (the safe "no identity"
// input to segment resolution - org-only, never a failure), not left unset
// in some other way or defaulted from X-User-ID.
func TestStepGateHandler_NoXUserEmailHeader_EmptyEmail(t *testing.T) {
	evaluator := &contextCapturingEvaluator{decision: GateDecisionAllow}
	handler, svc := setupTestHandlerWithEvaluator(evaluator)
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "wf"},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow failed: %v", err)
	}

	body, _ := json.Marshal(StepGateRequest{StepName: "s", StepType: StepTypeLLMCall})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/workflows/"+wf.WorkflowID+"/steps/step-1/gate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "12345")
	// No X-User-Email set.
	req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "step-1"})

	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if evaluator.lastCtx == nil {
		t.Fatal("evaluator was not called")
	}
	if evaluator.lastCtx.Email != "" {
		t.Errorf("StepGateContext.Email = %q, want empty (no X-User-Email supplied)", evaluator.lastCtx.Email)
	}
}

// TestStepGate_AuditEntry_CarriesOrgID pins a fix found while building the
// #3281 fail-closed audit-row assertion: the step_gate WorkflowAuditEntry
// (service.go, the s.logAudit call right after the step is recorded) left
// OrgID unset - unlike the step_approved/step_rejected audit entries, which
// already populate it from workflow.OrgID - so every step_gate row's
// audit_logs.org_id landed NULL, including the fail-closed
// segment-resolution-failure deny this issue adds. An org-scoped audit query
// (the natural way to look up "what happened for org X") would silently
// match zero step_gate rows regardless of how many were actually written.
func TestStepGate_AuditEntry_CarriesOrgID(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "ok"})
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	capture := &captureAuditLogger{}
	svc.SetAuditLogger(capture)

	if _, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	var gateEntry *WorkflowAuditEntry
	for _, e := range capture.entries {
		if e.Operation == "step_gate" {
			gateEntry = e
		}
	}
	if gateEntry == nil {
		t.Fatal("no step_gate audit entry was recorded")
	}
	if gateEntry.OrgID != "org-1" {
		t.Errorf("step_gate audit entry OrgID = %q, want org-1 (was previously left empty - audit_logs.org_id landed NULL for every step_gate row)", gateEntry.OrgID)
	}
}

// TestResumeFromCheckpoint_CarriesResumeRequestEmail pins the fix for the
// enforcement bypass this test previously pinned as CORRECT behaviour.
//
// A checkpoint resume re-enters the SAME Service.StepGate evaluation the gate
// route runs, with retry_policy=reevaluate -- a deliberate cache bypass to get
// a FRESH verdict. Dropping the caller identity on the way in put that fresh
// verdict on the org-only path, so a step the gate route DENIES for this very
// caller was allowed through the resume route. Measured live on the pre-fix
// build: /gate -> block ["E2E 3281 WCP Segment Block"], resume -> allow.
//
// The earlier deferral argued a migration was needed for a Checkpoint email
// column. That premise was wrong twice over: a resume is a live HTTP request
// carrying its own trust-gated header (no migration involved), and replaying
// the checkpoint's PERSISTED original email would be its own escalation --
// user B's resume evaluated under user A's segments. The identity threaded
// here is the resume request's own.
func TestResumeFromCheckpoint_CarriesResumeRequestEmail(t *testing.T) {
	evaluator := &contextCapturingEvaluator{decision: GateDecisionAllow}
	svc, _ := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	_, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
		Email:    "alice@example.com",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}
	if evaluator.lastCtx.Email != "alice@example.com" {
		t.Fatalf("precondition failed: original gate call did not carry Email, got %q", evaluator.lastCtx.Email)
	}

	// The resume request carries a DIFFERENT verified identity from the one
	// that created the checkpoint. Asserting on bob (not alice) is what makes
	// this discriminating: it fails both against the pre-fix drop-the-identity
	// behaviour AND against a "replay the checkpoint's stored actor" fix,
	// which would resolve bob's resume under alice's segment memberships.
	evaluator.lastCtx = nil
	if _, err := svc.ResumeFromLastCheckpoint(ctx, workflowID, "tenant-1", "org-1", "bob@example.com"); err != nil {
		t.Fatalf("ResumeFromLastCheckpoint failed: %v", err)
	}
	if evaluator.lastCtx == nil {
		t.Fatal("evaluator was not called during resume")
	}
	if evaluator.lastCtx.Email != "bob@example.com" {
		t.Errorf("resume evaluated with Email=%q, want bob@example.com (the RESUME request's own trust-gated identity). "+
			"Empty means the identity was dropped and every segment-scoped policy silently stopped applying on this route; "+
			"alice@example.com means the checkpoint's stored actor was replayed, which evaluates one user's resume under another's segments",
			evaluator.lastCtx.Email)
	}
}

// TestResumeFromCheckpointByID_CarriesResumeRequestEmail is the same
// invariant on the OTHER resume route. Both ResumeFromLastCheckpoint
// (Evaluation+, /checkpoints/resume) and ResumeFromCheckpoint (Enterprise,
// /checkpoints/{checkpoint_id}/resume) funnel into
// resumeFromCheckpointInternal, and both are registered on live routers, so
// pinning only one leaves the other free to regress.
func TestResumeFromCheckpointByID_CarriesResumeRequestEmail(t *testing.T) {
	evaluator := &contextCapturingEvaluator{decision: GateDecisionAllow}
	svc, repo := setupTestService(evaluator)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	if _, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
		Email:    "alice@example.com",
	}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	cp, err := repo.GetLastResumableCheckpoint(ctx, workflowID)
	if err != nil || cp == nil {
		t.Fatalf("precondition failed: no resumable checkpoint (err=%v, cp=%v)", err, cp)
	}

	evaluator.lastCtx = nil
	if _, err := svc.ResumeFromCheckpoint(ctx, workflowID, cp.ID, "tenant-1", "org-1", "bob@example.com"); err != nil {
		t.Fatalf("ResumeFromCheckpoint failed: %v", err)
	}
	if evaluator.lastCtx == nil {
		t.Fatal("evaluator was not called during resume-by-id")
	}
	if evaluator.lastCtx.Email != "bob@example.com" {
		t.Errorf("resume-by-id evaluated with Email=%q, want bob@example.com (see TestResumeFromCheckpoint_CarriesResumeRequestEmail)", evaluator.lastCtx.Email)
	}
}

// TestResumeHandlers_ThreadXUserEmailIntoStepGateContext is the HTTP-level
// half of the resume fix: both checkpoint-resume routes must read the same
// trust-gated X-User-Email the gate route reads, because both re-enter the
// same Service.StepGate evaluation with retry_policy=reevaluate.
//
// Before the fix these handlers never touched the header, so a request that
// the gate route denied for this exact caller was allowed through here. The
// subtests are table-driven over the two routes so a future route added to
// resumeFromCheckpointInternal is an obvious place to extend rather than a
// silent third gap.
func TestResumeHandlers_ThreadXUserEmailIntoStepGateContext(t *testing.T) {
	cases := []struct {
		name string
		// invoke drives the handler under test for a workflow + checkpoint id.
		invoke func(h *Handler, wfID string, cpID int64, req *http.Request) *httptest.ResponseRecorder
	}{
		{
			name: "ResumeFromLastCheckpoint (Evaluation+, /checkpoints/resume)",
			invoke: func(h *Handler, wfID string, _ int64, req *http.Request) *httptest.ResponseRecorder {
				req = mux.SetURLVars(req, map[string]string{"id": wfID})
				rr := httptest.NewRecorder()
				h.ResumeFromLastCheckpoint(rr, req)
				return rr
			},
		},
		{
			name: "ResumeFromCheckpoint (Enterprise, /checkpoints/{checkpoint_id}/resume)",
			invoke: func(h *Handler, wfID string, cpID int64, req *http.Request) *httptest.ResponseRecorder {
				req = mux.SetURLVars(req, map[string]string{
					"id":            wfID,
					"checkpoint_id": strconv.FormatInt(cpID, 10),
				})
				rr := httptest.NewRecorder()
				h.ResumeFromCheckpoint(rr, req)
				return rr
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := &contextCapturingEvaluator{decision: GateDecisionAllow}
			handler, svc := setupTestHandlerWithEvaluator(evaluator)
			ctx := context.Background()
			wf, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "wf"},
				"tenant-1", "org-1", "user-1", "client-1")
			if err != nil {
				t.Fatalf("CreateWorkflow failed: %v", err)
			}

			// Establish a resumable checkpoint under a DIFFERENT identity from
			// the one that will drive the resume, so replaying the stored
			// actor is distinguishable from honouring the live header.
			if _, err := svc.StepGate(ctx, wf.WorkflowID, "step-1", &StepGateRequest{
				StepType: StepTypeToolCall,
				Email:    "alice@example.com",
			}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
				t.Fatalf("StepGate failed: %v", err)
			}
			cp, err := svc.repo.GetLastResumableCheckpoint(ctx, wf.WorkflowID)
			if err != nil || cp == nil {
				t.Fatalf("precondition failed: no resumable checkpoint (err=%v, cp=%v)", err, cp)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+wf.WorkflowID+"/checkpoints/resume", nil)
			req.Header.Set("X-Tenant-ID", "tenant-1")
			req.Header.Set("X-Org-ID", "org-1")
			req.Header.Set("X-User-ID", "12345") // numeric attribution id, must NOT be read as an email
			req.Header.Set("X-User-Email", "bob@example.com")

			evaluator.lastCtx = nil
			rr := tc.invoke(handler, wf.WorkflowID, cp.ID, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
			}
			if evaluator.lastCtx == nil {
				t.Fatal("evaluator was not called during resume")
			}
			if evaluator.lastCtx.Email != "bob@example.com" {
				t.Errorf("resume StepGateContext.Email = %q, want bob@example.com. "+
					"Empty means the handler dropped the trust-gated header and every segment-scoped policy stopped applying on this route; "+
					"alice@example.com means the checkpoint's stored actor was replayed instead of the live caller",
					evaluator.lastCtx.Email)
			}
		})
	}
}

// TestResumeHandlers_NoHeaderMeansEmptyEmail pins that the resume routes do
// NOT fall back to the attribution-only X-User-ID (or to the checkpoint's
// stored actor) when no verified identity is present. Empty is the correct,
// safe input to segment resolution: org-only, non-segment-scoped policies
// still enforce. A fallback here would feed a non-email identifier into
// resolveUserSegments.
func TestResumeHandlers_NoHeaderMeansEmptyEmail(t *testing.T) {
	evaluator := &contextCapturingEvaluator{decision: GateDecisionAllow}
	handler, svc := setupTestHandlerWithEvaluator(evaluator)
	ctx := context.Background()
	wf, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "wf"},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow failed: %v", err)
	}
	if _, err := svc.StepGate(ctx, wf.WorkflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
		Email:    "alice@example.com",
	}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+wf.WorkflowID+"/checkpoints/resume", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "12345") // present, and must NOT become the email
	req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID})

	evaluator.lastCtx = nil
	rr := httptest.NewRecorder()
	handler.ResumeFromLastCheckpoint(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if evaluator.lastCtx == nil {
		t.Fatal("evaluator was not called during resume")
	}
	if evaluator.lastCtx.Email != "" {
		t.Errorf("resume StepGateContext.Email = %q, want empty (no X-User-Email present)", evaluator.lastCtx.Email)
	}
}

// TestStepGate_AuditEntry_CarriesUserEmailAndPolicyIDs pins the two audit
// gaps that made a segment verdict unattributable.
//
// UserEmail: the step_gate verdict became identity-DEPENDENT once segment
// resolution keys on the caller email, but the audit row left user_email
// NULL while its step_approved/step_rejected siblings populated it -- an
// operator could not tell which caller a segment verdict applied to.
// Measured on a live pre-fix stack: every workflow_step_gate row, including
// the segment block, had an empty user_email.
//
// policy_ids: the adapter names its fail-closed refusal
// (PolicyIDs == ["segment_resolution_failed"]) precisely so the audit row can
// key off an identifier rather than string-matching prose, but the row only
// ever recorded len(PoliciesMatched). Measured live pre-fix, the row carried
// "policies_matched": 0 and no identifier at all, and the suite's
// ILIKE '%segment_resolution_failed%' assertion passed ONLY because `_` is a
// LIKE wildcard matching the spaces in the human-readable reason.
func TestStepGate_AuditEntry_CarriesUserEmailAndPolicyIDs(t *testing.T) {
	evaluator := &namedRefusalEvaluator{policyIDs: []string{"segment_resolution_failed"}}
	svc, _ := setupTestService(evaluator)
	capture := &captureAuditLogger{}
	svc.SetAuditLogger(capture)
	workflowID := createTestWorkflow(t, svc)

	if _, err := svc.StepGate(context.Background(), workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
		Email:    "alice@example.com",
	}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}

	var gateEntry *WorkflowAuditEntry
	for _, e := range capture.entries {
		if e.Operation == "step_gate" {
			gateEntry = e
		}
	}
	if gateEntry == nil {
		t.Fatal("no step_gate audit entry was recorded")
	}

	if gateEntry.UserEmail != "alice@example.com" {
		t.Errorf("step_gate audit entry UserEmail = %q, want alice@example.com. Empty means an operator cannot tell WHICH caller an identity-dependent segment verdict applied to", gateEntry.UserEmail)
	}

	ids, ok := gateEntry.Metadata["policy_ids"].([]string)
	if !ok {
		t.Fatalf("step_gate audit metadata has no []string policy_ids (got %T: %v). Without it a named refusal never reaches the row and the only thing left to assert on is the human-readable reason", gateEntry.Metadata["policy_ids"], gateEntry.Metadata["policy_ids"])
	}
	if len(ids) != 1 || ids[0] != "segment_resolution_failed" {
		t.Errorf("step_gate audit metadata policy_ids = %v, want [segment_resolution_failed]", ids)
	}
}

// TestStepGate_AuditEntry_OmitsEmptyPolicyIDs keeps the addition above from
// growing a null key on every uneventful allow.
func TestStepGate_AuditEntry_OmitsEmptyPolicyIDs(t *testing.T) {
	svc, _ := setupTestService(&namedRefusalEvaluator{policyIDs: nil, allow: true})
	capture := &captureAuditLogger{}
	svc.SetAuditLogger(capture)
	workflowID := createTestWorkflow(t, svc)

	if _, err := svc.StepGate(context.Background(), workflowID, "step-1", &StepGateRequest{
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("StepGate failed: %v", err)
	}
	for _, e := range capture.entries {
		if e.Operation != "step_gate" {
			continue
		}
		if _, present := e.Metadata["policy_ids"]; present {
			t.Errorf("step_gate audit metadata carries policy_ids on a no-policy allow: %v", e.Metadata["policy_ids"])
		}
	}
}

// namedRefusalEvaluator returns a verdict with a caller-chosen PolicyIDs set
// (including an EMPTY one), which fixedEvaluator cannot express -- it always
// returns ["test-policy"], so it could not distinguish "policy_ids omitted
// when empty" from "policy_ids never written".
type namedRefusalEvaluator struct {
	policyIDs []string
	allow     bool
}

func (e *namedRefusalEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	decision := GateDecisionBlock
	if e.allow {
		decision = GateDecisionAllow
	}
	return &StepGateEvaluation{
		Decision:          decision,
		Reason:            "segment resolution unavailable - request denied (fail-closed, ADR-060 #2989 P3b)",
		PolicyIDs:         e.policyIDs,
		PoliciesEvaluated: []PolicyMatch{},
		PoliciesMatched:   []PolicyMatch{},
	}
}
