// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

// #4249 row 5701284807: a step that runs ungated leaves a record, once.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func stepRunService(t *testing.T) (*Service, *MockRepository, *captureAuditLogger, string) {
	t.Helper()
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	audit := &captureAuditLogger{}
	svc.SetAuditLogger(audit)
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "plan-step"}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("create workflow: %v", err)
	}
	return svc, repo, audit, wf.WorkflowID
}

func firstStepRecord(workflowID string) StepRunRecord {
	return StepRunRecord{
		WorkflowID: workflowID, StepID: "step_0_fetch", StepName: "fetch", StepType: StepTypeConnectorCall,
		Reason:   StepRunReasonStepModeFirstStep,
		TenantID: "tenant-1", OrgID: "org-1", UserID: "resumer@example.com", ClientID: "client-1",
	}
}

// The record is an ALLOW with no approval and a reason that names it as a
// recorded ungated run, never an approved one, with its audit row.
func TestAStepRunRecordIsAnAllowNamingItselfWithItsAuditRow(t *testing.T) {
	svc, repo, audit, wf := stepRunService(t)
	if err := svc.RecordStepRun(context.Background(), firstStepRecord(wf)); err != nil {
		t.Fatalf("RecordStepRun: %v", err)
	}
	row, _ := repo.GetStepDecision(context.Background(), wf, "step_0_fetch")
	if row == nil || row.Decision != GateDecisionAllow || row.ApprovalStatus != nil || row.DecisionReason != StepRunReasonStepModeFirstStep {
		t.Fatalf("row = %+v, want an allow with no approval, reason %s", row, StepRunReasonStepModeFirstStep)
	}
	var found *WorkflowAuditEntry
	for _, e := range audit.entries {
		if e.StepID == "step_0_fetch" && e.Reason == StepRunReasonStepModeFirstStep {
			found = e
		}
	}
	if found == nil || found.UserID != "resumer@example.com" || found.Decision != string(GateDecisionAllow) || found.Metadata["gated"] != false {
		t.Errorf("audit = %+v, want an allow row for the resuming credential, marked not gated", found)
	}
}

// THE RECORD IS WRITTEN ONCE: a second write, a doubled resume, is refused, so
// the step cannot be run a second time through it.
func TestAStepRunRecordIsRefusedAsASecondWrite(t *testing.T) {
	svc, _, _, wf := stepRunService(t)
	if err := svc.RecordStepRun(context.Background(), firstStepRecord(wf)); err != nil {
		t.Fatalf("first RecordStepRun: %v", err)
	}
	err := svc.RecordStepRun(context.Background(), firstStepRecord(wf))
	if !errors.Is(err, ErrStepAlreadyRecorded) {
		t.Fatalf("second RecordStepRun = %v, want ErrStepAlreadyRecorded", err)
	}
}

// A pending approval on ANOTHER step does not stop the record (StepGate would
// refuse there): the record adds no approval, so one pending approval per
// workflow still holds.
func TestAStepRunRecordIsWrittenBesideAnotherStepsPendingApproval(t *testing.T) {
	svc, repo, _, wf := stepRunService(t)
	require := GateDecisionRequireApproval
	if _, err := svc.StepGate(context.Background(), wf, "step_1_report", &StepGateRequest{StepName: "report", StepType: StepTypeLLMCall, GateOverride: &require},
		"tenant-1", "org-1", "another", "client-2"); err != nil {
		t.Fatalf("hold step 1: %v", err)
	}
	if err := svc.RecordStepRun(context.Background(), firstStepRecord(wf)); err != nil {
		t.Fatalf("RecordStepRun beside a pending step: %v", err)
	}
	if row, _ := repo.GetStepDecision(context.Background(), wf, "step_1_report"); row == nil || row.ApprovalStatus == nil || *row.ApprovalStatus != ApprovalStatusPending {
		t.Errorf("step_1_report = %+v, want its pending approval untouched", row)
	}
}

func TestAStepRunRecordRefusesAnUndeclaredReasonAndAnotherTenant(t *testing.T) {
	svc, _, _, wf := stepRunService(t)
	bad := firstStepRecord(wf)
	bad.Reason = "approved"
	if err := svc.RecordStepRun(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "not a declared step-run reason") {
		t.Errorf("an undeclared reason = %v, want refused", err)
	}
	other := firstStepRecord(wf)
	other.OrgID = "org-2"
	if err := svc.RecordStepRun(context.Background(), other); !errors.Is(err, ErrWorkflowNotFound) {
		t.Errorf("another organization = %v, want ErrWorkflowNotFound", err)
	}
}
