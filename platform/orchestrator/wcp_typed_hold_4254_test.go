// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4254: a challenge holds a workflow step with the engine's TYPED approval
// requirement, and the approval queue row carries it whole: every clause with
// its own quorum and pool, whether duties must be separated, the decision that
// held the step, and an expiry the row never outlives. An approval that timed
// out before it could be queued withholds the step instead, because timeout is
// deny.

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"axonflow/platform/agent/hitl/queue"
	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// typedApproval is a requirement of two clauses with disjoint pools, the shape
// a flattening would destroy.
func typedApproval(expiresAt time.Time) *contract.ApprovalRequirement {
	return &contract.ApprovalRequirement{
		AllOf: []contract.ApprovalClause{
			{Quorum: 2, Eligible: []contract.ID{
				contract.MustParseID(contract.KindGroup, "Group::mars:finance"),
				contract.MustParseID(contract.KindGroup, "Group::mars:risk"),
			}},
			{Quorum: 1, Eligible: []contract.ID{
				contract.MustParseID(contract.KindGroup, "Group::mars:compliance"),
			}},
		},
		SeparationOfDuties: true,
		ExpiresAt:          expiresAt,
	}
}

// typedHoldVerdict is the engine's challenge carrying a decision id and an
// approval requirement.
func typedHoldVerdict(decisionID string, approval *contract.ApprovalRequirement) anchoredenforcer.Verdict {
	v := heldStepVerdict()
	v.Decision.DecisionID = decisionID
	v.Decision.Approval = approval
	return v
}

// holdStep runs one step through the adapter over a typed challenge and
// returns the gate's answer and the approval creator that saw the enqueue.
func holdStep(t *testing.T, approval *contract.ApprovalRequirement) (*workflow_control.StepGateEvaluation, *mockHITLApprovalCreator) {
	t.Helper()
	withStepGateEngine(t, typedHoldVerdict("dec-4254-hold", approval))
	creator := &mockHITLApprovalCreator{resp: &HITLApprovalResponse{
		ApprovalID: uuid.New(),
		Status:     "pending",
		Enqueue:    string(queue.OutcomeCreated),
	}}
	adapter := NewWCPPolicyAdapter()
	adapter.SetHITLApproval(creator)
	return adapter.EvaluateStepGate(wcpSubjectContext(), seamStepContext()), creator
}

// Every clause lands as its own element with its own quorum and pool. Merging
// the pools would let one finance approver and one compliance approver satisfy
// a requirement that asks for two from finance or risk AND one from compliance.
func TestAHeldStepQueuesEveryApprovalClauseAsItsOwnElement(t *testing.T) {
	expiresAt := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	ev, creator := holdStep(t, typedApproval(expiresAt))

	if ev.Decision != workflow_control.GateDecisionRequireApproval {
		t.Fatalf("decision = %q (%s), want require_approval", ev.Decision, ev.Reason)
	}
	if creator.callCount != 1 || creator.lastReq == nil {
		t.Fatalf("the approval was queued %d times, want once", creator.callCount)
	}
	rc := creator.lastReq.RequestContext
	want := []map[string]interface{}{
		{"quorum": 2, "eligible": []string{"Group::mars:finance", "Group::mars:risk"}},
		{"quorum": 1, "eligible": []string{"Group::mars:compliance"}},
	}
	if !reflect.DeepEqual(rc["approval_clauses"], want) {
		t.Errorf("approval_clauses = %#v\nwant every clause with its own quorum and pool: %#v", rc["approval_clauses"], want)
	}
	if rc["separation_of_duties"] != true {
		t.Errorf("separation_of_duties = %#v, want true", rc["separation_of_duties"])
	}
	if rc["plane"] != "wcp" {
		t.Errorf("plane = %#v, want wcp", rc["plane"])
	}
	if rc["decision_id"] != "dec-4254-hold" {
		t.Errorf("decision_id = %#v, want the decision that held the step", rc["decision_id"])
	}
	if rc["expires_at"] != expiresAt.UTC().Format(time.RFC3339) {
		t.Errorf("expires_at = %#v, want %s", rc["expires_at"], expiresAt.UTC().Format(time.RFC3339))
	}
	if id, has := rc["correlation_id"]; has {
		t.Errorf("correlation_id = %#v on the workflow step gate, which has none", id)
	}
	if !creator.lastReq.ExpiresAt.Equal(expiresAt) {
		t.Errorf("the request's expiry = %s, want the approval's %s", creator.lastReq.ExpiresAt, expiresAt)
	}
	if rc["workflow_id"] != "wf-seam" || rc["step_id"] != "step-1" {
		t.Errorf("the row lost the step it holds: workflow_id=%#v step_id=%#v", rc["workflow_id"], rc["step_id"])
	}
}

// With no declared expiry the queue's default applies, and the row says so by
// carrying no expires_at, never a zero time.
func TestAHeldStepWithNoDeclaredExpiryKeepsTheQueueDefault(t *testing.T) {
	approval := &contract.ApprovalRequirement{AllOf: []contract.ApprovalClause{
		{Quorum: 1, Eligible: []contract.ID{contract.MustParseID(contract.KindGroup, "Group::mars:ops")}},
	}}
	ev, creator := holdStep(t, approval)

	if ev.Decision != workflow_control.GateDecisionRequireApproval {
		t.Fatalf("decision = %q (%s), want require_approval", ev.Decision, ev.Reason)
	}
	if creator.callCount != 1 || creator.lastReq == nil {
		t.Fatalf("the approval was queued %d times, want once", creator.callCount)
	}
	rc := creator.lastReq.RequestContext
	if v, has := rc["expires_at"]; has {
		t.Errorf("expires_at = %#v with no declared expiry; want it absent", v)
	}
	if !creator.lastReq.ExpiresAt.IsZero() {
		t.Errorf("the request's expiry = %s with none declared; want zero, the queue default", creator.lastReq.ExpiresAt)
	}
	want := []map[string]interface{}{{"quorum": 1, "eligible": []string{"Group::mars:ops"}}}
	if !reflect.DeepEqual(rc["approval_clauses"], want) {
		t.Errorf("approval_clauses = %#v, want a one-element list, not a flattened clause: %#v", rc["approval_clauses"], want)
	}
	if rc["separation_of_duties"] != false {
		t.Errorf("separation_of_duties = %#v, want false, recorded rather than omitted", rc["separation_of_duties"])
	}
}

// An approval whose expiry has already passed when the step would be queued has
// timed out, and timeout is deny: the step is withheld, named, and nothing is
// queued. The reason names the decision and the expiry and nothing of the
// requirement: no pool, no group, no policy.
func TestAnApprovalThatExpiredBeforeItCouldBeQueuedWithholdsTheStep(t *testing.T) {
	expiresAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	ev, creator := holdStep(t, typedApproval(expiresAt))

	if ev.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision = %q (%s), want block: a timed-out approval is a deny", ev.Decision, ev.Reason)
	}
	if creator.callCount != 0 {
		t.Errorf("the approval was queued %d times, want never: it had already timed out", creator.callCount)
	}
	if ev.ApprovalEnqueue != "" {
		t.Errorf("approval_enqueue = %q, want empty: no enqueue was attempted", ev.ApprovalEnqueue)
	}
	if !reflect.DeepEqual(ev.PolicyIDs, []string{"approval_expired"}) {
		t.Errorf("policy ids = %v, want [approval_expired]", ev.PolicyIDs)
	}
	wantReason := "approval_expired: decision dec-4254-hold requires an approval that expired at " +
		expiresAt.UTC().Format(time.RFC3339) + ", and a timed-out approval is a deny"
	if ev.Reason != wantReason {
		t.Errorf("reason = %q\nwant %q", ev.Reason, wantReason)
	}
	for _, leak := range []string{"mars", "finance", "risk", "compliance", "group", "quorum", "wsp-approval-policy"} {
		if strings.Contains(strings.ToLower(ev.Reason), leak) {
			t.Errorf("reason %q names %q: the withhold must carry only the decision id and the expiry", ev.Reason, leak)
		}
	}
}

// The boundary is the engine's: an approval is grantable only strictly before
// its expiry, so one expiring at the instant of the decision has timed out.
func TestAnApprovalExpiringAtTheInstantOfTheDecisionHasTimedOut(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		expiresAt time.Time
		want      workflow_control.GateDecision
	}{
		{"at the instant", now, workflow_control.GateDecisionBlock},
		{"a nanosecond before", now.Add(-time.Nanosecond), workflow_control.GateDecisionBlock},
		{"a nanosecond after", now.Add(time.Nanosecond), workflow_control.GateDecisionRequireApproval},
		{"none declared", time.Time{}, workflow_control.GateDecisionRequireApproval},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, result := stepGateFromDecision(typedHoldVerdict("dec-instant", typedApproval(c.expiresAt)), 0, now)
			if ev.Decision != c.want {
				t.Fatalf("decision = %q (%s), want %q", ev.Decision, ev.Reason, c.want)
			}
			if held := result.hold != nil; held != (c.want == workflow_control.GateDecisionRequireApproval) {
				t.Errorf("hold carried = %v on a %q decision; only a hold carries one", held, ev.Decision)
			}
		})
	}
}

// The hold rides beside the result to the enqueue and is never marshalled with
// it: the field is unexported, and this pins that no rename exports it.
func TestTheHoldIsNeverMarshalledWithTheResult(t *testing.T) {
	_, result := stepGateFromDecision(typedHoldVerdict("dec-wire-4254", typedApproval(time.Now().Add(time.Hour))), 0, time.Now())
	if result.hold == nil {
		t.Fatal("PREMISE: the challenge carried no hold, so its absence from the JSON proves nothing")
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, has := members["hold"]; has {
		t.Errorf("the result's JSON has a hold member: %s", body)
	}
	for _, leak := range []string{"dec-wire-4254", "approval_clauses", "Group::", "separation_of_duties"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("the result's JSON carries %q from the hold: %s", leak, body)
		}
	}
}

func TestApprovalExpiresInNeverOutlivesTheApproval(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	if d, err := approvalExpiresIn(time.Time{}, now); d != 0 || err != nil {
		t.Errorf("no declared expiry = (%s, %v), want (0, nil): the queue default", d, err)
	}
	if d, err := approvalExpiresIn(now.Add(90*time.Minute), now); d != 90*time.Minute || err != nil {
		t.Errorf("an expiry 90m away = (%s, %v), want (1h30m0s, nil)", d, err)
	}
	for _, lapsed := range []time.Time{now, now.Add(-time.Second)} {
		if d, err := approvalExpiresIn(lapsed, now); !errors.Is(err, errApprovalExpiredBeforeQueue) || d != 0 {
			t.Errorf("an expiry at %s (now %s) = (%s, %v), want refused, never clamped or defaulted", lapsed, now, d, err)
		}
	}
}

// expiresNear matches the queue row's expires_at within a minute of want, which
// separates a declared expiry from the 24h default by hours.
type expiresNear struct{ want time.Time }

func (e expiresNear) Match(v driver.Value) bool {
	got, ok := v.(time.Time)
	if !ok {
		return false
	}
	d := got.Sub(e.want)
	if d < 0 {
		d = -d
	}
	return d < time.Minute
}

// The queue row expires when the approval does, and at the queue's default when
// none was declared.
func TestTheQueueRowExpiresWhenTheApprovalDoes(t *testing.T) {
	cases := []struct {
		name      string
		expiresAt time.Time
		wantRow   time.Time
	}{
		{"declared", time.Now().Add(3 * time.Hour), time.Now().Add(3 * time.Hour)},
		{"none declared", time.Time{}, time.Now().Add(24 * time.Hour)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock: %v", err)
			}
			defer db.Close()

			id := uuid.MustParse(workflow_control.DeriveHITLApprovalID("wf-123", "step-a"))
			expectScope(mock, "test-org", true)
			mock.ExpectQuery("INSERT INTO hitl_approval_queue").
				WithArgs(
					id, "test-org", "test-tenant", "test-client", "test-user",
					"high-risk-step", "wcp_step_gate", sqlmock.AnyArg(),
					"policy-123", "test-policy", "High-risk op", "high",
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					"pending",
					expiresNear{want: c.wantRow}, // expires_at
					sqlmock.AnyArg(),
				).
				WillReturnRows(insertRows(id, true))
			mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
			mock.ExpectQuery("INSERT INTO hitl_approval_history").
				WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(int64(1), time.Now()))
			mock.ExpectCommit()

			req := stepGateRequest()
			req.ExpiresAt = c.expiresAt
			if _, err := newTestAdapter(t, db, 25).CreateApproval(context.Background(), req); err != nil {
				t.Fatalf("CreateApproval: %v (an expires_at away from %s does not match)", err, c.wantRow.Format(time.RFC3339))
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet sqlmock expectations: %v", err)
			}
		})
	}
}

// An approval that lapsed between the step gate's decision and the enqueue is
// refused before any statement is sent: no row outlives it.
func TestTheQueueRefusesAnApprovalThatLapsedBeforeTheEnqueue(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	req := stepGateRequest()
	req.ExpiresAt = time.Now().Add(-time.Second)
	resp, err := newTestAdapter(t, db, 25).CreateApproval(context.Background(), req)

	if !errors.Is(err, errApprovalExpiredBeforeQueue) {
		t.Fatalf("CreateApproval error = %v, want errApprovalExpiredBeforeQueue", err)
	}
	if resp != nil {
		t.Errorf("response = %+v for a refused approval, want nil", resp)
	}
	// No expectations were set, so any statement sent would have failed the
	// call with a different error above.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}
