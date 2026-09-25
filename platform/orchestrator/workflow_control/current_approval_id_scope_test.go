// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"testing"
)

// scopeRecordingMirror records the scope CurrentHoldID is asked for.
type scopeRecordingMirror struct {
	recordingMirrorResolver
	lookups []string
}

func (m *scopeRecordingMirror) CurrentHoldID(_ context.Context, orgID, tenantID, workflowID, stepID string) (string, bool, error) {
	m.lookups = append(m.lookups, orgID+"|"+tenantID+"|"+workflowID+"|"+stepID)
	return "hold-id", true, nil
}

// TestCurrentApprovalIDIsScopedByTheWorkflowRow: the approval_id lookup reads
// the queue under the WORKFLOW row's organization and tenant, as the mirror's
// resolve does - never the caller's header values, which authorize after
// trimming but would scope the queue read to no row (#4249 row 5700138809, R3
// round 1). A caller that does not own the workflow gets no id and no lookup.
func TestCurrentApprovalIDIsScopedByTheWorkflowRow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	mirror := &scopeRecordingMirror{}
	svc.SetHITLMirrorResolver(mirror)
	ctx := context.Background()

	wf, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "scope"}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	if got := svc.CurrentApprovalID(ctx, wf.WorkflowID, "step-1", " tenant-1 ", " org-1 "); got != "hold-id" {
		t.Fatalf("padded header scope: approval id = %q, want hold-id (the scope authorizes after trimming)", got)
	}
	want := "org-1|tenant-1|" + wf.WorkflowID + "|step-1"
	if len(mirror.lookups) != 1 || mirror.lookups[0] != want {
		t.Errorf("lookups = %q, want exactly [%q]: the workflow row's scope, not the header's", mirror.lookups, want)
	}

	mirror.lookups = nil
	if got := svc.CurrentApprovalID(ctx, wf.WorkflowID, "step-1", "tenant-1", "org-2"); got != "" {
		t.Errorf("another organization: approval id = %q, want empty", got)
	}
	if len(mirror.lookups) != 0 {
		t.Errorf("another organization reached the queue lookup: %q", mirror.lookups)
	}
}
