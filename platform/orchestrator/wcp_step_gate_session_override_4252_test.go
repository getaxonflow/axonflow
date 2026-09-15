// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/workflow_control"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestTheStepGateReadsNoSessionOverride is #4252's proof at the adapter: a
// step the engine denies stays denied while the caller holds an active
// session-override row that the deleted ADR-044 read would have honoured.
//
// TWO detectors, because the first one alone was not enough. The mock is
// seeded with exactly the reads that path made (the org scope, then the
// override row for this policy, user, tenant and no tool), and those
// expectations must stay UNCONSUMED, so a read that happened and was ignored
// cannot pass. But sqlmock matches in order, so a restored read that does NOT
// reproduce the whole transaction shape (begin, set_config, query, commit)
// simply errors and leaves the expectations unconsumed - a mutation that
// re-inserted the flip against the bare handle SURVIVED this test for exactly
// that reason. So the second detector is the query matcher below: ANY
// statement naming policy_overrides fails the test, in or out of a
// transaction, in any order, whatever its columns.
func TestTheStepGateReadsNoSessionOverride(t *testing.T) {
	// refuseOverrideReads is the detector a mutation run proved this test needed:
	// it sees every statement the code under test sends, before sqlmock's ordered
	// expectations get a say.
	var overrideReads []string
	refuseOverrideReads := sqlmock.QueryMatcherFunc(func(expectedSQL, actualSQL string) error {
		if strings.Contains(actualSQL, "policy_overrides") {
			// Deduped: sqlmock consults the matcher once per candidate expectation
			// and again to confirm the match, so a single statement arrives twice.
			stmt := strings.Join(strings.Fields(actualSQL), " ")
			if !slices.Contains(overrideReads, stmt) {
				overrideReads = append(overrideReads, stmt)
			}
		}
		return sqlmock.QueryMatcherRegexp.Match(expectedSQL, actualSQL)
	})
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(refuseOverrideReads))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	// UNORDERED, and that is load bearing: in sqlmock's ordered mode a statement
	// arriving while the next unfulfilled expectation is ExpectBegin is refused
	// before the query matcher is consulted, so the matcher never sees it - which
	// is why the first version of this detector did not kill the mutation either.
	mock.MatchExpectationsInOrder(false)

	prev := usageDB
	usageDB = db
	t.Cleanup(func() {
		usageDB = prev
		_ = db.Close()
	})

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-4252").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT id, policy_id, policy_type`).
		WithArgs("pol-overridable", "holder@corp.example", "tenant-4252", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at"}).
			AddRow("ovr-4252", "pol-overridable", "dynamic", "", "seeded legacy override", nil))
	mock.ExpectCommit()

	// #4254: the step gate's deny is the anchored engine's, and it is a double
	// here. This test's subject is that no session override is READ, not how
	// the deny was decided, so both detectors below are unchanged.
	withStepGateEngine(t, stepGateVerdict(contract.StateDeny, contract.ReasonExplicitConstraint,
		contract.Determining{MatchedConstraints: []string{"pol-overridable"}}))
	adapter := NewWCPPolicyAdapter()

	eval := adapter.EvaluateStepGate(wcpSubjectContext(), &workflow_control.StepGateContext{
		WorkflowID: "wf-4252",
		StepID:     "step-1",
		StepName:   "seeded",
		StepType:   "llm_call",
		TenantID:   "tenant-4252",
		OrgID:      "org-4252",
		Email:      "holder@corp.example",
		UserID:     "holder@corp.example",
	})

	if eval.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision = %q, want block: the seeded session override must not flip the deny (#4252)", eval.Decision)
	}
	if eval.Reason != "Step blocked by policy" {
		t.Errorf("reason = %q, want the policy's own block reason and never an override's", eval.Reason)
	}
	if err := mock.ExpectationsWereMet(); err == nil {
		t.Error("the seeded override reads were consumed: the step gate read policy_overrides")
	}
	if len(overrideReads) != 0 {
		t.Errorf("the step gate sent %d statement(s) naming policy_overrides, and it must send none: %v",
			len(overrideReads), overrideReads)
	}
}
