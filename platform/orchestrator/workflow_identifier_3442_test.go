// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/execution"
)

// #3442 - one workflow, one identifier.
//
// Three id spaces used to share the `wf_` prefix while naming different
// things. These tests pin the resolution:
//
//	wf_<uuid>              control-plane workflow (workflow_control.NewWorkflowID)
//	  ...and its unified execution projection, which now carries the SAME
//	  string rather than minting a second one.
//	wfe_<unix>_<8>         in-process declarative workflow-engine run - a
//	                       different subsystem, so a different prefix.

// TestWCPExecutionProjectionCarriesTheWorkflowID is the convergence pin: the
// execution_history row for a WCP workflow is addressed by the workflow's own
// id, so the Approvals queue and the Executions page name one run with one
// string.
func TestWCPExecutionProjectionCarriesTheWorkflowID(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	const workflowID = "wf_9f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f"
	totalSteps := 2
	now := time.Now()
	workflow := &workflow_control.Workflow{
		WorkflowID:       workflowID,
		WorkflowName:     "3442 convergence",
		Source:           workflow_control.WorkflowSourceLangGraph,
		Status:           workflow_control.WorkflowStatusInProgress,
		CurrentStepIndex: 0,
		TotalSteps:       &totalSteps,
		TenantID:         "tenant-3442",
		OrgID:            "org-3442",
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
		Steps:            []workflow_control.WorkflowStep{},
	}

	status, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution: %v", err)
	}

	if status.ExecutionID != workflowID {
		t.Fatalf("execution id = %q, want the workflow's own id %q - two `wf_` strings for one run is the #3442 defect",
			status.ExecutionID, workflowID)
	}

	// The metadata key is unchanged and remains the lookup every WCP read path
	// uses (findExecutionByWorkflowID). Rows written before this change resolve
	// through it too, which is what keeps them addressable.
	if got := status.Metadata["workflow_id"]; got != workflowID {
		t.Fatalf("metadata[workflow_id] = %v, want %q", got, workflowID)
	}

	// And the projection must be reachable by BOTH routes: directly by primary
	// key (the new shape) and by the metadata key (what old rows depend on).
	if _, err := repo.Get(ctx, workflowID); err != nil {
		t.Fatalf("execution not retrievable by the workflow id: %v", err)
	}
	found, err := repo.GetByMetadata(ctx, "workflow_id", workflowID)
	if err != nil {
		t.Fatalf("execution not retrievable by metadata workflow_id: %v", err)
	}
	if found.ExecutionID != workflowID {
		t.Fatalf("metadata lookup returned execution id %q, want %q", found.ExecutionID, workflowID)
	}
}

// TestWCPExecutionProjectionFallsBackWhenWorkflowIDEmpty pins the defensive
// half. An empty ExecutionID would become the PRIMARY KEY of
// execution_history: the first such row is unaddressable and the second is a
// unique violation. StartExecution mints one instead.
func TestWCPExecutionProjectionFallsBackWhenWorkflowIDEmpty(t *testing.T) {
	tracker := NewWCPExecutionTracker(NewMockMAPRepository(), nil)

	status, err := tracker.StartWorkflowExecution(context.Background(), &workflow_control.Workflow{
		WorkflowName: "3442 empty id",
		TenantID:     "tenant-3442",
		OrgID:        "org-3442",
		Steps:        []workflow_control.WorkflowStep{},
	})
	if err != nil {
		t.Fatalf("StartWorkflowExecution: %v", err)
	}
	if status.ExecutionID == "" {
		t.Fatal("execution id is empty - it would be written as the execution_history PRIMARY KEY")
	}
	if !regexp.MustCompile(`^wf_[0-9a-f]{24}$`).MatchString(status.ExecutionID) {
		t.Fatalf("execution id = %q, want a minted wf_<24 hex>", status.ExecutionID)
	}
}

// TestEngineExecutionIDFormat pins the third generator and, above all, that it
// no longer masquerades as a control-plane workflow id.
func TestEngineExecutionIDFormat(t *testing.T) {
	shape := regexp.MustCompile(`^wfe_[0-9]{10,}_[a-z0-9]{8}$`)

	seen := make(map[string]struct{}, 512)
	for i := 0; i < 512; i++ {
		id := newEngineExecutionID()
		if !strings.HasPrefix(id, EngineExecutionIDPrefix) {
			t.Fatalf("newEngineExecutionID() = %q, want prefix %q", id, EngineExecutionIDPrefix)
		}
		if !shape.MatchString(id) {
			t.Fatalf("newEngineExecutionID() = %q, want wfe_<unix>_<8 alnum>", id)
		}
		// The whole point of the rename: an engine id must not be mistakable
		// for a governed workflow. `wfe_` does start with `wf`, so assert on
		// the prefix INCLUDING its separator, which is what
		// resolveExecution's strings.HasPrefix(id, "wf_") actually tests.
		if strings.HasPrefix(id, workflow_control.WorkflowIDPrefix) {
			t.Fatalf("newEngineExecutionID() = %q still carries the control-plane prefix %q (#3442)",
				id, workflow_control.WorkflowIDPrefix)
		}
		seen[id] = struct{}{}
	}
	if len(seen) != 512 {
		t.Fatalf("newEngineExecutionID() produced %d distinct ids in 512 draws", len(seen))
	}
}

// TestResolveExecutionDoesNotClaimEngineIDs pins the consequence at the
// consumer. resolveExecution treats any `wf_`-prefixed string as a candidate
// WCP workflow id; before #3442 an engine execution id was one, sending the
// handler to look up a workflow that cannot exist. This asserts the prefix
// gate itself, at the same literal the handler uses.
func TestResolveExecutionDoesNotClaimEngineIDs(t *testing.T) {
	engineID := newEngineExecutionID()
	if strings.HasPrefix(engineID, "wf_") {
		t.Fatalf("engine id %q would be routed to the WCP workflow strategy in resolveExecution", engineID)
	}
	// Positive control: the guard above must be able to fail. A control-plane
	// id MUST match the same predicate, or the assertion is measuring nothing.
	if !strings.HasPrefix(workflow_control.NewWorkflowID(), "wf_") {
		t.Fatal("a control-plane workflow id no longer matches resolveExecution's wf_ strategy; the guard above is vacuous")
	}
}

// wfLiteral matches a Go string literal that IS, or begins with, the
// control-plane workflow prefix.
var wfLiteral = regexp.MustCompile(`"wf(_[^"]*)?"`)

// TestWFPrefixNamespaceIsClosed is the ratchet. Every production string
// literal under platform/ and ee/platform/ that mints or matches a `wf_`
// identifier must be on this list with a reason. A new one is not necessarily
// wrong - but #3442 happened because three subsystems each grew one
// independently, and nothing anywhere connected them.
func TestWFPrefixNamespaceIsClosed(t *testing.T) {
	allowed := map[string]string{
		"platform/orchestrator/workflow_control/ids.go":             "the ONE control-plane minter (WorkflowIDPrefix / NewWorkflowID)",
		"platform/orchestrator/workflow_control/mock_repository.go": "test double; mints wf_mock_<n> deterministically, never persisted",
		"platform/orchestrator/unified_execution_handler.go":        "resolveExecution's prefix STRATEGY test, not a mint",
		"platform/shared/execution/tracker.go":                      "generateExecutionID's WCP prefix, reached only if a WCP caller supplies no workflow id",
	}

	// Self-test the scanner against decoys before trusting a clean result.
	for _, decoy := range []string{`x := "wf_"`, `fmt.Sprintf("wf_%s", id)`, `if p == "wf" {`} {
		if !wfLiteral.MatchString(decoy) {
			t.Fatalf("scanner self-test: decoy %q was NOT detected; this guard cannot fail", decoy)
		}
	}
	for _, clean := range []string{`x := "wfe_"`, `name := "workflow"`, `s := "wcp_"`} {
		if wfLiteral.MatchString(clean) {
			t.Fatalf("scanner self-test: %q was flagged; the guard would fail on correct code", clean)
		}
	}

	root, err := repoRootFor3442()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	scanned := 0
	sawEE := false
	hits := map[string][]string{}
	for _, sub := range []string{filepath.Join("platform"), filepath.Join("ee", "platform")} {
		dir := filepath.Join(root, sub)
		if st, statErr := os.Stat(dir); statErr != nil || !st.IsDir() {
			continue // ee/platform is absent on a community-mirror checkout
		}
		if sub == filepath.Join("ee", "platform") {
			sawEE = true
		}
		walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if info.Name() == "node_modules" || info.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, readErr := os.ReadFile(path) //nolint:gosec // walking our own tree
			if readErr != nil {
				return readErr
			}
			scanned++
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			for i, line := range strings.Split(string(src), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue // a comment naming the prefix is not a use of it
				}
				if wfLiteral.MatchString(line) {
					hits[rel] = append(hits[rel], strings.TrimSpace(line)+"  (line "+strconv.Itoa(i+1)+")")
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", dir, walkErr)
		}
	}

	// Anti-vacuity: a walk that read nothing reports a closed namespace.
	//
	// The floor is edition-dependent. `ee/platform` is stripped from the public
	// community mirror, so the same healthy walk reads far fewer files there -
	// 406 at v10.0.0 against roughly 700 on an enterprise checkout. A single
	// enterprise-calibrated floor therefore FAILS on the mirror for a tree that
	// is entirely correct, which is what happened on the v10.0.0 sync PR. Pick
	// the floor from what was actually walked, not from the enterprise number.
	floor := 300
	if sawEE {
		floor = 500
	}
	if scanned < floor {
		t.Fatalf("scanned only %d non-test .go files (floor %d, ee/platform present: %v); the walker is not reaching the tree",
			scanned, floor, sawEE)
	}
	if len(hits) == 0 {
		t.Fatal("found ZERO wf_ literals; the control-plane minter itself carries one, so the scanner is broken")
	}

	for file, lines := range hits {
		if _, ok := allowed[file]; !ok {
			t.Errorf("%s introduces a `wf_` identifier literal with no entry in this guard:\n    %s\n"+
				"    If it is a new kind of thing, give it its own prefix (see EngineExecutionIDPrefix).\n"+
				"    If it is the governed workflow id, route it through workflow_control.NewWorkflowID.\n"+
				"    Either way, add it here with a reason (#3442).",
				file, strings.Join(lines, "\n    "))
		}
	}
	for file := range allowed {
		if _, ok := hits[file]; !ok {
			t.Errorf("allowlist entry %q no longer contains a `wf_` literal - remove the stale entry so the list keeps meaning something", file)
		}
	}
}

// repoRootFor3442 ascends until it finds the directory holding platform/.
// Anchored on platform/ alone: ee/platform/ is excluded from the community
// sync filter and is legitimately absent on a mirror checkout.
func repoRootFor3442() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if st, statErr := os.Stat(filepath.Join(dir, "platform")); statErr == nil && st.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// TestConvergedIDStillReconcilesStepApprovals is the #3442 round-1 regression
// guard, against a defect the convergence itself would have introduced.
//
// The cached step snapshot in execution_history is written at /gate time with
// approval_status=pending. `GetWorkflowStatus` merges the live workflow_steps
// state over it on every read - but `resolveExecution` only reached
// GetWorkflowStatus through its WORKFLOW-id strategy. Its FIRST strategy is a
// direct primary-key lookup that returns immediately, and that is the one the
// portal Executions page hits, because the page passes the execution id.
//
// Making the execution row carry the workflow's id sends every caller down
// strategy 1, which would have retired the merge outright. The merge now lives
// on strategy 1, so this asserts on the converged id - the shape a caller
// actually has after #3442.
func TestConvergedIDStillReconcilesStepApprovals(t *testing.T) {
	ctx := context.Background()

	const stepID = "step-3442-reconcile"
	wfRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(wfRepo, nil, nil)

	wf, err := wcpSvc.CreateWorkflow(ctx, &workflow_control.CreateWorkflowRequest{
		WorkflowName: "3442 reconcile",
	}, "tenant-3442", "org-3442", "user-3442", "client-3442")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	// The LIVE control-plane state: the step has been approved.
	if err := wfRepo.AddStep(ctx, &workflow_control.WorkflowStep{
		WorkflowID: wf.WorkflowID,
		StepID:     stepID,
		StepName:   "reconcile me",
		StepType:   workflow_control.StepTypeToolCall,
		Decision:   workflow_control.GateDecisionRequireApproval,
	}); err != nil {
		t.Fatalf("AddStep: %v", err)
	}
	if err := wfRepo.UpdateStepApproval(ctx, wf.WorkflowID, stepID,
		workflow_control.ApprovalStatusApproved, "approver@example.com", "looks fine"); err != nil {
		t.Fatalf("UpdateStepApproval: %v", err)
	}

	// The STALE cached projection: the snapshot written at gate time.
	execRepo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(execRepo, wcpSvc)
	pending := execution.ApprovalStatusPending
	if err := execRepo.Create(ctx, &execution.ExecutionStatus{
		ExecutionID:   wf.WorkflowID, // the #3442 convergence
		ExecutionType: execution.ExecutionTypeWCP,
		Name:          "3442 reconcile",
		Status:        execution.StatusRunning,
		TenantID:      "tenant-3442",
		OrgID:         "org-3442",
		Metadata:      map[string]interface{}{"workflow_id": wf.WorkflowID},
		Steps: []execution.StepStatus{{
			StepID:         stepID,
			StepName:       "reconcile me",
			Status:         execution.StepStatusApproval,
			ApprovalStatus: &pending,
		}},
	}); err != nil {
		t.Fatalf("seed execution: %v", err)
	}

	// The fixture must be able to tell the bug from the fix: the cached row
	// really does disagree with the live one before the merge runs.
	raw, err := execRepo.Get(ctx, wf.WorkflowID)
	if err != nil {
		t.Fatalf("seeded execution not readable: %v", err)
	}
	if raw.Steps[0].ApprovalStatus == nil || *raw.Steps[0].ApprovalStatus != execution.ApprovalStatusPending {
		t.Fatalf("cached snapshot is not stale (%v); this test could not detect a lost merge", raw.Steps[0].ApprovalStatus)
	}

	handler := NewUnifiedExecutionHandler(execRepo, nil, tracker, nil, nil)
	resolved, err := handler.resolveExecution(ctx, wf.WorkflowID)
	if err != nil {
		t.Fatalf("resolveExecution(%q): %v", wf.WorkflowID, err)
	}
	if len(resolved.Steps) != 1 {
		t.Fatalf("resolved %d steps, want 1", len(resolved.Steps))
	}
	got := resolved.Steps[0].ApprovalStatus
	if got == nil || *got != execution.ApprovalStatusApproved {
		t.Fatalf("step approval_status = %v after resolveExecution, want approved - "+
			"the direct-id strategy is not reconciling against live workflow_steps (#3442)", got)
	}
	if resolved.Steps[0].ApprovedBy != "approver@example.com" {
		t.Errorf("approved_by = %q, want the live approver", resolved.Steps[0].ApprovedBy)
	}
}
