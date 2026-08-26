// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3408 sibling - the WCP plane's HITL write path, on BOTH editions.
//
// NO BUILD TAG, matching hitl_wcp_adapter.go. Before this change the two
// editions had two copies of the write path and two copies of these tests, and
// the copies had diverged: the enterprise one asserted an ON CONFLICT dedup
// that the community one did not have, so the missing dedup on the Evaluation
// tier was invisible to CI. One implementation, one test file.

package orchestrator

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"axonflow/platform/agent/hitl/queue"
	"axonflow/platform/agent/license"
	"axonflow/platform/orchestrator/workflow_control"
)

// entitledTier is the tier override every test here installs.
//
// SetTierProviderForTest rather than AXONFLOW_LICENSE_KEY is deliberate: the
// shared test licence key in hitl_wcp_community_test.go expired on 2026-05-30,
// so a test that gates on it silently takes the DISABLED branch today and
// passes for the wrong reason.
//
// Enterprise, not Evaluation: the 2026-08-26 operator decision made HITL
// Enterprise-only. These tests exercise the WRITE PATH, which that decision
// does not change; the refusal of the newly-unentitled tiers is pinned
// separately.
func entitledTier(context.Context) license.Tier { return license.TierEnterprise }

func newTestAdapter(t *testing.T, db *sql.DB, maxPending int) *wcpHITLAdapter {
	t.Helper()
	enq := queue.NewEnqueuer(db, queue.Config{
		Plane:               wcpHITLRequestType,
		MaxPendingApprovals: maxPending,
		DefaultExpiry:       24 * time.Hour,
	})
	enq.SetTierProviderForTest(entitledTier)
	return newWCPHITLAdapter(enq)
}

func stepGateRequest() *HITLApprovalRequest {
	return &HITLApprovalRequest{
		OrgID:         "test-org",
		TenantID:      "test-tenant",
		ClientID:      "test-client",
		UserID:        "test-user",
		ExecutionID:   "wf-123",
		StepName:      "high-risk-step",
		StepType:      "llm_call",
		PolicyID:      "policy-123",
		PolicyName:    "test-policy",
		TriggerReason: "High-risk op",
		Severity:      "high",
		RequestContext: map[string]interface{}{
			"workflow_id": "wf-123",
			"step_id":     "step-a",
		},
	}
}

// expectScope stubs BEGIN + the org GUC, and the per-tenant advisory lock
// only when a finite cap is configured.
//
// The lock is CONDITIONAL on `maxPending > 0` (R3 round 1: taking it on the
// unlimited tiers serialised every step gate behind one cluster-wide lock to
// protect a limit that is disabled). sqlmock's expectations are ordered, so
// this flag is not decoration - it is what makes
// TestUnlimitedCapIssuesNoCount able to observe that the lock is skipped.
func expectScope(mock sqlmock.Sqlmock, org string, withCapLock bool) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(org).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if withCapLock {
		mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
			WillReturnResult(sqlmock.NewResult(0, 0))
	}
}

func insertRows(id uuid.UUID, inserted bool) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows([]string{"id", "request_id", "status", "created_at", "updated_at", "expires_at", "inserted"}).
		AddRow(int64(1), id, "pending", now, now, now.Add(24*time.Hour), inserted)
}

// TestCreateApprovalDerivesTheIDTheAPIProjects is the regression pin for the
// Evaluation-tier half of #3408's sibling.
//
// The eval adapter used to mint uuid.New(), while approve/reject responses
// project workflow_control.DeriveHITLApprovalID(workflow_id, step_id). The two
// never matched, so on Evaluation the `approval_id` a client was handed
// resolved to no row at all. Both editions now write under the derived id, and
// this asserts the EXACT value rather than "some uuid".
func TestCreateApprovalDerivesTheIDTheAPIProjects(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	want := uuid.MustParse(workflow_control.DeriveHITLApprovalID("wf-123", "step-a"))

	expectScope(mock, "test-org", true)
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WithArgs(
			want,             // request_id - the DERIVED value, not any uuid
			"test-org",       // org_id
			"test-tenant",    // tenant_id
			"test-client",    // client_id
			"test-user",      // user_id
			"high-risk-step", // original_query (step name, by convention)
			"wcp_step_gate",  // request_type
			sqlmock.AnyArg(), // request_context JSON
			"policy-123",     // triggered_policy_id
			"test-policy",    // triggered_policy_name
			"High-risk op",   // trigger_reason
			"high",           // severity
			sqlmock.AnyArg(), // eu_ai_act_article (NULL)
			sqlmock.AnyArg(), // compliance_framework (NULL)
			sqlmock.AnyArg(), // risk_classification (NULL)
			"pending",        // status
			sqlmock.AnyArg(), // expires_at
			sqlmock.AnyArg(), // notify_url (NULL)
		).
		WillReturnRows(insertRows(want, true))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(int64(1), time.Now()))
	mock.ExpectCommit()

	resp, err := newTestAdapter(t, db, 25).CreateApproval(context.Background(), stepGateRequest())
	if err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}
	if resp.ApprovalID != want {
		t.Errorf("approval id = %s, want the derived %s", resp.ApprovalID, want)
	}
	if resp.Enqueue != string(queue.OutcomeCreated) {
		t.Errorf("enqueue outcome = %q, want %q", resp.Enqueue, queue.OutcomeCreated)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestCreateApprovalWritesTheArticle14HistoryRow pins the third defect: NEITHER
// edition wrote a hitl_approval_history entry, so the EU AI Act Article 14
// trail recorded a `created` action for approvals raised through the agent and
// nothing at all for approvals raised by a workflow gate.
//
// The mutant that kills this is deleting the insertHistory call in
// queue.Enqueue - which compiles.
func TestCreateApprovalWritesTheArticle14HistoryRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	id := uuid.MustParse(workflow_control.DeriveHITLApprovalID("wf-123", "step-a"))
	expectScope(mock, "test-org", true)
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").WillReturnRows(insertRows(id, true))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WithArgs(
			id, "test-org", "test-tenant", "created",
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), // previous_status (NULL on create)
			"pending",        // new_status
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(int64(1), time.Now()))
	mock.ExpectCommit()

	if _, err := newTestAdapter(t, db, 25).CreateApproval(context.Background(), stepGateRequest()); err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestReusedRowIsNotChargedAgainstTheCap pins the ordering decision in
// queue.Enqueue: the cap is measured only when the INSERT actually created a
// row.
//
// Count-then-insert - the obvious alternative, and what hitl.Service still
// does - would refuse a re-gate of an ALREADY-QUEUED step once the tenant sat
// at the limit, so a workflow could no longer re-poll its own pending gate.
// Here the conflict arm returns inserted=false and no COUNT is issued at all;
// sqlmock's ordered expectations are what make that assertable (an
// unexpected COUNT would fail the call).
func TestReusedRowIsNotChargedAgainstTheCap(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	id := uuid.MustParse(workflow_control.DeriveHITLApprovalID("wf-123", "step-a"))
	expectScope(mock, "test-org", true)
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").WillReturnRows(insertRows(id, false))
	// No COUNT and no history INSERT: both are conditional on Inserted.
	mock.ExpectCommit()

	// maxPending = 1 while the tenant is (notionally) far past it. A
	// count-then-insert implementation would refuse here.
	resp, err := newTestAdapter(t, db, 1).CreateApproval(context.Background(), stepGateRequest())
	if err != nil {
		t.Fatalf("re-gate of an existing approval was refused: %v", err)
	}
	if resp.Enqueue != string(queue.OutcomeReused) {
		t.Errorf("enqueue outcome = %q, want %q", resp.Enqueue, queue.OutcomeReused)
	}
	if resp.ApprovalID != id {
		t.Errorf("re-gate returned %s, want the existing %s", resp.ApprovalID, id)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestCapRefusesAndRollsBack pins that the sixth pending row for a cap of five
// is refused AND leaves nothing behind.
//
// The speculative insert has already run when the cap is measured, so the
// refusal MUST roll back - otherwise the cap would reject the caller while
// still growing the queue it was protecting, which is worse than no cap.
func TestCapRefusesAndRollsBack(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	id := uuid.MustParse(workflow_control.DeriveHITLApprovalID("wf-123", "step-a"))
	expectScope(mock, "test-org", true)
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").WillReturnRows(insertRows(id, true))
	// Six pending INCLUDING the speculative row, against a limit of five.
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(6))
	mock.ExpectRollback()

	_, err = newTestAdapter(t, db, 5).CreateApproval(context.Background(), stepGateRequest())
	if err == nil {
		t.Fatal("CreateApproval over the cap returned no error")
	}
	if !errors.Is(err, queue.ErrPendingCapReached) {
		t.Fatalf("error = %v, want it to wrap ErrPendingCapReached", err)
	}
	// The refusal must carry the numbers, not just a sentinel: an operator
	// reading it needs to know which tenant and which limit.
	if !strings.Contains(err.Error(), "test-tenant") || !strings.Contains(err.Error(), "limit 5") {
		t.Errorf("refusal does not name the tenant and the limit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestCapAdmitsExactlyAtTheLimit is the other direction of the boundary, and
// it is the assertion that would catch an off-by-one turning the cap of five
// into a cap of four.
//
// [[feedback_an_assertion_that_cannot_pass_is_the_same_defect_as_one_that_cannot_fail]]
func TestCapAdmitsExactlyAtTheLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	id := uuid.MustParse(workflow_control.DeriveHITLApprovalID("wf-123", "step-a"))
	expectScope(mock, "test-org", true)
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").WillReturnRows(insertRows(id, true))
	// FIVE pending including the row just written, against a limit of five:
	// this is the fifth approval and it is admitted.
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(int64(1), time.Now()))
	mock.ExpectCommit()

	if _, err := newTestAdapter(t, db, 5).CreateApproval(context.Background(), stepGateRequest()); err != nil {
		t.Fatalf("the fifth pending approval was refused against a cap of five: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestUnlimitedCapIssuesNoCount pins that the Enterprise sentinel (-1) skips
// the cap read entirely rather than comparing against a negative number.
func TestUnlimitedCapIssuesNoCount(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	id := uuid.MustParse(workflow_control.DeriveHITLApprovalID("wf-123", "step-a"))
	// NO advisory lock and NO count: with the cap disabled there is nothing to
	// serialise and nothing to measure. sqlmock's ordered expectations turn
	// either one appearing into a failure.
	expectScope(mock, "test-org", false)
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").WillReturnRows(insertRows(id, true))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(int64(1), time.Now()))
	mock.ExpectCommit()

	if _, err := newTestAdapter(t, db, license.EnterpriseLimits.MaxPendingApprovals).
		CreateApproval(context.Background(), stepGateRequest()); err != nil {
		t.Fatalf("CreateApproval under the unlimited sentinel: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestTierGateRefusesBeforeTouchingTheDatabase pins #1998's acceptance
// criterion 3 on this plane: a Community-tier process must be refused, and it
// must be refused BEFORE any statement runs.
//
// The enterprise adapter used to consult no licence at all, so an enterprise
// image with no AXONFLOW_LICENSE_KEY wrote rows on a tier whose
// HITLApprovalEnabled is false. sqlmock with ZERO expectations is what makes
// "before touching the database" assertable - any statement at all fails the
// call.
func TestTierGateRefusesBeforeTouchingTheDatabase(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	enq := queue.NewEnqueuer(db, queue.Config{Plane: wcpHITLRequestType, MaxPendingApprovals: 5})
	enq.SetTierProviderForTest(func(context.Context) license.Tier { return license.TierCommunity })

	_, err = newWCPHITLAdapter(enq).CreateApproval(context.Background(), stepGateRequest())
	if !errors.Is(err, queue.ErrTierDisabled) {
		t.Fatalf("error = %v, want ErrTierDisabled", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the tier gate ran statements against the database: %v", err)
	}
}

// --- the disclosure half: a refusal must reach the caller ------------------

type stubCreator struct {
	resp *HITLApprovalResponse
	err  error
}

func (s *stubCreator) CreateApproval(context.Context, *HITLApprovalRequest) (*HITLApprovalResponse, error) {
	return s.resp, s.err
}

func requireApprovalResult() *PolicyEvaluationResult {
	return &PolicyEvaluationResult{
		Allowed:         false,
		RequiredActions: []string{"require_approval"},
		AppliedPolicies: []string{"wsp-approval-policy"},
		Severity:        "high",
	}
}

func gateContext() *workflow_control.StepGateContext {
	return &workflow_control.StepGateContext{
		WorkflowID: "wf-123",
		StepID:     "step-a",
		StepName:   "high-risk-step",
		OrgID:      "test-org",
		TenantID:   "test-tenant",
		ClientID:   "test-client",
	}
}

type allowAllEngine struct{ result *PolicyEvaluationResult }

func (e *allowAllEngine) EvaluateDynamicPolicies(context.Context, OrchestratorRequest) *PolicyEvaluationResult {
	return e.result
}
func (e *allowAllEngine) ListActivePolicies() []DynamicPolicy { return nil }
func (e *allowAllEngine) IsHealthy() bool                     { return true }

// TestEnqueueRefusalIsDisclosedNotSwallowed is the core of scope item D.
//
// Pre-fix, wcp_policy_adapter.go did `log.Printf(...); return uuid.Nil` - so a
// cap refusal produced a response byte-identical to a healthy hold minus the
// approval_id, and nothing on the wire, on the audit row or on any dashboard
// distinguished "held, go and approve it" from "held, there is nothing to
// approve and there never will be". That is the failure mode #3509 documented
// on the FinCrime seam, one file over.
//
// The step is still HELD in every arm. Admitting it because the review queue
// is full would turn a capacity limit into a governance bypass.
func TestEnqueueRefusalIsDisclosedNotSwallowed(t *testing.T) {
	cases := []struct {
		name         string
		err          error
		wantOutcome  string
		wantInReason string
	}{
		{
			name:         "cap reached",
			err:          &queue.CapError{TenantID: "test-tenant", Pending: 5, Limit: 5},
			wantOutcome:  string(queue.OutcomeCapReached),
			wantInReason: "pending-approval limit",
		},
		{
			name:         "tier disabled",
			err:          queue.ErrTierDisabled,
			wantOutcome:  string(queue.OutcomeTierDisabled),
			wantInReason: "licence tier",
		},
		{
			name:         "database failure",
			err:          errors.New("connection refused"),
			wantOutcome:  string(queue.OutcomeError),
			wantInReason: "could not be queued",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := NewWCPPolicyAdapter(&allowAllEngine{result: requireApprovalResult()})
			adapter.SetHITLApproval(&stubCreator{err: tc.err})

			ev := adapter.EvaluateStepGate(context.Background(), gateContext())

			if ev.Decision != workflow_control.GateDecisionRequireApproval {
				t.Fatalf("decision = %q, want require_approval - the caller must stay HELD", ev.Decision)
			}
			if ev.ApprovalID != "" {
				t.Errorf("approval_id = %q, want empty: no queue entry exists", ev.ApprovalID)
			}
			if ev.ApprovalEnqueue != tc.wantOutcome {
				t.Errorf("approval_enqueue = %q, want %q", ev.ApprovalEnqueue, tc.wantOutcome)
			}
			if !strings.Contains(ev.Reason, tc.wantInReason) {
				t.Errorf("reason %q does not contain %q", ev.Reason, tc.wantInReason)
			}
		})
	}
}

// TestSuccessfulEnqueueIsAlsoClassified is the positive control for the test
// above. Without it, an implementation that hard-coded ApprovalEnqueue to the
// failure value would satisfy every case there.
func TestSuccessfulEnqueueIsAlsoClassified(t *testing.T) {
	id := uuid.New()
	adapter := NewWCPPolicyAdapter(&allowAllEngine{result: requireApprovalResult()})
	adapter.SetHITLApproval(&stubCreator{resp: &HITLApprovalResponse{
		ApprovalID: id, Status: "pending", Enqueue: string(queue.OutcomeCreated),
	}})

	ev := adapter.EvaluateStepGate(context.Background(), gateContext())

	if ev.ApprovalID != id.String() {
		t.Errorf("approval_id = %q, want %s", ev.ApprovalID, id)
	}
	if ev.ApprovalEnqueue != string(queue.OutcomeCreated) {
		t.Errorf("approval_enqueue = %q, want created", ev.ApprovalEnqueue)
	}
	if ev.Reason == "" || strings.Contains(ev.Reason, "held") {
		t.Errorf("reason %q reads as a refusal on the success path", ev.Reason)
	}
}

// TestAllowDecisionCarriesNoEnqueueClassification keeps the field honest: it
// must be EMPTY when no enqueue was attempted, so `approval_enqueue` present
// always means "a HITL write was tried". A field that is always populated
// cannot be filtered on.
func TestAllowDecisionCarriesNoEnqueueClassification(t *testing.T) {
	adapter := NewWCPPolicyAdapter(&allowAllEngine{result: &PolicyEvaluationResult{Allowed: true}})
	adapter.SetHITLApproval(&stubCreator{err: errors.New("must not be called")})

	ev := adapter.EvaluateStepGate(context.Background(), gateContext())

	if ev.Decision != workflow_control.GateDecisionAllow {
		t.Fatalf("decision = %q, want allow", ev.Decision)
	}
	if ev.ApprovalEnqueue != "" {
		t.Errorf("approval_enqueue = %q on an allow, want empty", ev.ApprovalEnqueue)
	}
}

// TestEnqueueRefusalKeepsThePolicyReason pins the half of the disclosure that
// had no coverage at all: the POLICY's own reason must survive alongside the
// enqueue explanation.
//
// R3 round 2 reverted the append to a plain assignment and every suite stayed
// green - the only test touching Reason asserted `strings.Contains(reason,
// <enqueue half>)`, which an overwrite satisfies just as well. Losing the
// policy half means the audit row for a capped request no longer records WHY
// the step was gated, on exactly the requests an operator most needs to
// reconstruct.
func TestEnqueueRefusalKeepsThePolicyReason(t *testing.T) {
	adapter := NewWCPPolicyAdapter(&allowAllEngine{result: requireApprovalResult()})
	adapter.SetHITLApproval(&stubCreator{err: &queue.CapError{TenantID: "test-tenant", Pending: 5, Limit: 5}})

	ev := adapter.EvaluateStepGate(context.Background(), gateContext())

	// The policy half - what convertToStepGateEvaluation set before the
	// enqueue ran. Asserted by its literal, because that literal is what an
	// operator reading the audit row sees.
	if !strings.Contains(ev.Reason, "Step requires human approval") {
		t.Errorf("the policy's own reason was lost: %q", ev.Reason)
	}
	// The enqueue half.
	if !strings.Contains(ev.Reason, "pending-approval limit") {
		t.Errorf("the enqueue refusal is not in the reason: %q", ev.Reason)
	}
	// And joined, not concatenated into an unreadable run-on.
	if !strings.Contains(ev.Reason, "; ") {
		t.Errorf("the two halves are not separated: %q", ev.Reason)
	}
	// Never a LEADING separator - the invariant the empty guard protects.
	if strings.HasPrefix(strings.TrimSpace(ev.Reason), ";") {
		t.Errorf("reason starts with the separator: %q", ev.Reason)
	}
}
