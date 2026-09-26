// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
)

// WORKFLOW AUDIT ROWS CARRY THE ORGANIZATION ON EVERY PATH THAT WRITES THEM (#4312).
//
// workflow_control's census and cells pin the service's eight sites. These
// cells pin what they cannot see from inside that package: that the MAP planes
// reach the same service method with the org they were given, that the WCP
// adapter and LogWorkflowOperation carry the value to the queued row, and that
// a row still arriving with an empty org is counted and written, never dropped.

// wcpAuditCapture implements workflow_control.WorkflowAuditLogger, recording
// every entry the service hands the audit seam.
type wcpAuditCapture struct {
	entries []workflow_control.WorkflowAuditEntry
}

func (c *wcpAuditCapture) LogWorkflowOperation(_ context.Context, entry *workflow_control.WorkflowAuditEntry) {
	c.entries = append(c.entries, *entry)
}

// TestMAPModes_WorkflowCreatedAuditCarriesTheOrg drives the MAP-sourced path
// (map_wcp_execution.go's CreateWorkflow calls, confirm and step mode). The
// plan's own OrgID is a DIFFERENT string from the org parameter on purpose: the
// entry must carry the org the executor was called with, not the plan's.
func TestMAPModes_WorkflowCreatedAuditCarriesTheOrg(t *testing.T) {
	for _, mode := range []struct {
		name string
		run  func(e *MAPWCPExecutor, plan *planning.Plan, wf *Workflow) (*MAPWCPExecutionResult, error)
	}{
		{"confirm", func(e *MAPWCPExecutor, plan *planning.Plan, wf *Workflow) (*MAPWCPExecutionResult, error) {
			return e.ExecuteWithConfirm(context.Background(), plan, wf, "tenant-4312", "org-4312", "user-1", "client-1")
		}},
		{"step", func(e *MAPWCPExecutor, plan *planning.Plan, wf *Workflow) (*MAPWCPExecutionResult, error) {
			return e.ExecuteWithStep(context.Background(), plan, wf, "tenant-4312", "org-4312", "user-1", "client-1")
		}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			assertMAPCreatedCarriesTheOrg(t, mode.run)
		})
	}
}

func assertMAPCreatedCarriesTheOrg(t *testing.T, run func(e *MAPWCPExecutor, plan *planning.Plan, wf *Workflow) (*MAPWCPExecutionResult, error)) {
	t.Helper()
	svc := workflow_control.NewService(workflow_control.NewMockRepository(), nil, nil)
	capture := &wcpAuditCapture{}
	svc.SetAuditLogger(capture)
	executor := NewMAPWCPExecutor(svc, nil)

	plan := &planning.Plan{OrgID: "org_from_the_plan", TenantID: "tenant_from_the_plan", PlanID: "plan-4312", Domain: "test", Query: "q"}
	workflow := &Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{{Name: "step1", Type: "llm-call"}}}}

	result, err := run(executor, plan, workflow)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	var created []workflow_control.WorkflowAuditEntry
	for _, e := range capture.entries {
		if e.WorkflowID == result.WorkflowID && e.Operation == "created" {
			created = append(created, e)
		}
	}
	if len(created) != 1 {
		t.Fatalf("want one created audit entry for %s, got %d of %d", result.WorkflowID, len(created), len(capture.entries))
	}
	if created[0].OrgID != "org-4312" {
		t.Errorf("MAP-sourced workflow_created audit entry OrgID = %q, want the executor's bound org %q (#4312)", created[0].OrgID, "org-4312")
	}
}

// queuedAuditLogger is an AuditLogger with a queue and no database, so the
// entry LogWorkflowOperation enqueues can be read back.
func queuedAuditLogger() *AuditLogger {
	return &AuditLogger{auditQueue: make(chan *AuditEntry, 16), shutdownChan: make(chan struct{})}
}

func drainOne(t *testing.T, l *AuditLogger) *AuditEntry {
	t.Helper()
	select {
	case e := <-l.auditQueue:
		return e
	default:
		t.Fatal("no audit entry was enqueued")
		return nil
	}
}

// TestWCPAdapter_WorkflowCreatedRowCarriesTheOrg is the seam end to end short
// of the database: the service, the adapter, LogWorkflowOperation, and the
// AuditEntry the BatchWriter binds.
func TestWCPAdapter_WorkflowCreatedRowCarriesTheOrg(t *testing.T) {
	logger := queuedAuditLogger()
	svc := workflow_control.NewService(workflow_control.NewMockRepository(), nil, nil)
	svc.SetAuditLogger(NewWCPAuditAdapter(logger))

	wf, err := svc.CreateWorkflow(context.Background(), &workflow_control.CreateWorkflowRequest{WorkflowName: "adapter-4312"},
		"tenant-4312", "org-4312", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	row := drainOne(t, logger)
	if row.RequestType != "workflow_created" || row.RequestID != wf.WorkflowID {
		t.Fatalf("unexpected row: request_type=%q request_id=%q", row.RequestType, row.RequestID)
	}
	if row.OrgID != "org-4312" {
		t.Errorf("workflow_created row org_id = %q, want %q (#4312)", row.OrgID, "org-4312")
	}
}

// TestLogWorkflowOperation_EmptyOrgIsCountedAndStillWritten pins the guard:
// COUNT, NEVER REFUSE. A row with an empty (or blank) org increments the
// counter under its operation and is still enqueued; a row with an org does
// not count; an operation outside the vocabulary counts under "other".
//
// The counter is process-global, so a counting case asserts AT LEAST its own
// increment: an empty-org row another test's goroutine writes in the window
// can only add to it.
func TestLogWorkflowOperation_EmptyOrgIsCountedAndStillWritten(t *testing.T) {
	counter := func(label string) float64 {
		return testutil.ToFloat64(workflowAuditEmptyOrgTotal.WithLabelValues(label))
	}

	for _, tc := range []struct {
		name, operation, org, label string
		wantDelta                   float64
	}{
		{"empty org", "created", "", "created", 1},
		{"blank org", "completed", "  \t", "completed", 1},
		// The zero case reads a process-global label, so it is exposed to any
		// empty-org "aborted" row another goroutine writes in the window. Today
		// none can: nothing in this package logs "aborted" directly (the HITL
		// engine logs step_gate only), and the service's aborted site now sets
		// workflow.OrgID after workflowBelongsTo, which refuses an empty owner.
		// A new direct caller of that operation must pick another label here.
		{"org present", "aborted", "org-4312", "aborted", 0},
		{"operation outside the vocabulary", "resumed_by_something_new", "", workflowAuditOperationOther, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := queuedAuditLogger()
			before := counter(tc.label)

			logger.LogWorkflowOperation(context.Background(), &WorkflowAuditEntry{
				WorkflowID: "wf-4312", WorkflowName: "w", Operation: tc.operation, TenantID: "tenant-4312", OrgID: tc.org,
			})

			if got := counter(tc.label) - before; got < tc.wantDelta || (tc.wantDelta == 0 && got != 0) {
				t.Errorf("axonflow_orchestrator_workflow_audit_empty_org_total{operation=%q} moved by %v, want %v", tc.label, got, tc.wantDelta)
			}
			row := drainOne(t, logger)
			if row.OrgID != tc.org {
				t.Errorf("row org_id = %q, want it written as given (%q): the guard counts, it never rewrites or drops", row.OrgID, tc.org)
			}
		})
	}
}
