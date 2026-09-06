// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Real-Postgres proof for #3718: A HUMAN APPROVAL APPEARS IN THE DECISIONS FEED.
//
// WHY THIS ASSERTS THE OUTCOME AND NOT THE COLUMNS.
//
// The obvious test - "the HITL writer binds decision_id, plane and
// correlation_id" - passes while the row still fails the feed's filter for a
// different reason, and there are several: policy_decision could be a value
// migration 123's CHECK rejects, the timestamp could fall outside the window,
// the tenant could not match, the row could be dropped on read as an
// override_lifecycle marker. A column-presence assertion lands on a cheaper
// signal that the behaviour usually produces, and #3718 is precisely a case
// where "usually" was never.
//
// So: seed through the PRODUCTION statement (audit.HITLAuditInsertSQL, which is
// the statement ee/platform/agent/hitl/repository.go executes), then ask the
// PRODUCTION query (queryDecisionList, the function
// GET /api/v1/decisions calls) whether the row came back.
//
// THE NEGATIVE CONTROL IS THE POINT. TestHITLApprovalBeforeTheFixIsInvisible
// seeds the SAME row the pre-#3718 writer produced - fifteen columns, no
// decision_id, no plane, no correlation_id, and no `decision_id` key in
// policy_details - and asserts it is ABSENT. Without it, the positive assertion
// could be passing because the feed returns everything.
//
// Skips cleanly when Docker is unavailable (CI unit lane).

import (
	"encoding/json"
	"testing"
	"time"

	"axonflow/platform/shared/audit"
	"axonflow/platform/testutil"
)

const hitlFeedTenant = "acme"

// hitlDetailsAfterFix mirrors what ee/platform/agent/hitl.BuildHITLAuditDetails
// produces for an approval raised by a policy step-up.
//
// It is built from the same shared constants the writer uses rather than from
// retyped strings, so a rename of a key cannot leave this fixture describing a
// shape nothing writes - the "rebuilt object is a lookalike" trap. The keys the
// writer adds that this test does not assert on (workflow_id, step_id, action,
// comment, reviewer_*) are omitted deliberately: this test is about IDENTITY,
// and policy_attribution_contract_test.go in the ee module is about the rest.
func hitlDetailsAfterFix(t *testing.T, action, requestID, originatingDecisionID, correlationID string) []byte {
	t.Helper()
	m := map[string]interface{}{
		"request_id":                           requestID,
		"action":                               action,
		"decision_id":                          audit.HITLDecisionID(action, requestID),
		"plane":                                audit.PlaneHITL,
		audit.HITLDetailKeyOriginatingDecision: audit.HITLAttributionNoOriginatingDecision,
	}
	if originatingDecisionID != "" {
		m[audit.HITLDetailKeyOriginatingDecision] = originatingDecisionID
	}
	if correlationID != "" {
		m["correlation_id"] = correlationID
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal details: %v", err)
	}
	return b
}

// seedHITLApproval writes one human-oversight audit row THROUGH THE PRODUCTION
// STATEMENT AND ITS PRODUCTION BIND BUILDER.
//
// audit.HITLAuditArgs is what the ee writer calls, and it is where plane,
// decision_id and the NULL response_time_ms are decided - so a regression in
// any of those three reaches this test rather than being re-implemented past it.
func seedHITLApproval(t *testing.T, action, requestID, originatingDecisionID, correlationID string, ts time.Time) string {
	t.Helper()
	row := audit.HITLAuditRow{
		ID:                "hitl_" + action + "_" + requestID,
		RequestID:         requestID,
		Timestamp:         ts,
		ReviewerEmail:     "reviewer@acme.com",
		ReviewerRole:      "compliance_officer",
		ClientID:          "client-acme",
		TenantID:          hitlFeedTenant,
		OrgID:             "org-acme",
		RequestType:       "workflow_step_gate",
		Query:             "HITL " + action + " for workflow=wf-1 step=step-1",
		QueryHash:         "hash-" + requestID,
		PolicyDecision:    audit.DecisionAllowed,
		PolicyDetails:     hitlDetailsAfterFix(t, action, requestID, originatingDecisionID, correlationID),
		Action:            action,
		ApprovalRequestID: requestID,
		CorrelationID:     correlationID,
	}
	if action == "rejected" {
		row.PolicyDecision = audit.DecisionBlocked
	}
	if _, err := usageDB.Exec(audit.HITLAuditInsertSQL, audit.HITLAuditArgs(row)...); err != nil {
		t.Fatalf("seed HITL approval %s: %v", requestID, err)
	}
	return audit.HITLDecisionID(action, requestID)
}

// seedHITLApprovalPreFix writes the row the pre-#3718 writer produced: the
// SAME fifteen columns it bound, and nothing else.
//
// Deliberately NOT built by mutating audit.HITLAuditArgs - a fixture derived
// from the fixed writer would inherit whatever the fixed writer does and could
// not express the defect. This is the literal column list from
// ee/platform/agent/hitl/repository.go as it stood on origin/main at ed1c444a4.
func seedHITLApprovalPreFix(t *testing.T, requestID string, ts time.Time) {
	t.Helper()
	details, err := json.Marshal(map[string]interface{}{
		"workflow_id": "wf-1",
		"step_id":     "step-1",
		"request_id":  requestID,
		"action":      "approved",
		"comment":     "",
		"policy_name": "High-Value Wire Transfer Oversight",
		"policy_id":   "wire_oversight",
		"reviewer_id": "u-1",
	})
	if err != nil {
		t.Fatalf("marshal pre-fix details: %v", err)
	}
	_, err = usageDB.Exec(`
		INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, policy_details, response_time_ms
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		"hitl_approved_"+requestID, requestID, ts, 0, "reviewer@acme.com", "compliance_officer",
		"client-acme", hitlFeedTenant, "org-acme", "workflow_step_gate",
		"HITL approved for workflow=wf-1 step=step-1", "hash-"+requestID,
		audit.DecisionAllowed, details, nil)
	if err != nil {
		t.Fatalf("seed pre-fix HITL approval: %v", err)
	}
}

func feedDecisionIDs(t *testing.T, since time.Time) map[string]bool {
	t.Helper()
	// decisionVals is an EMPTY SLICE, not nil, because that is what the handler
	// passes (decisions_list_handler.go: `decisionVals := []string{}`) and
	// because nil is not the same query: pq.Array(nil) binds SQL NULL, and
	// `cardinality(NULL) = 0` evaluates to NULL rather than TRUE, so the
	// no-filter short-circuit stops short-circuiting and the feed returns
	// nothing. Measured - the first run of this test reported every row absent
	// for that reason and not for the one it was written to detect.
	items, err := queryDecisionList(hitlFeedTenant, "", since, []string{}, "", "", 100)
	if err != nil {
		t.Fatalf("queryDecisionList: %v", err)
	}
	out := map[string]bool{}
	for _, it := range items {
		out[it.DecisionID] = true
	}
	return out
}

// TestHITLApprovalAppearsInTheDecisionsFeed_RealPostgres is the DoD assertion
// for #3718, stated as an outcome.
func TestHITLApprovalAppearsInTheDecisionsFeed_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, auditLogsTestDDL)

	prev := usageDB
	usageDB = pg.DB
	t.Cleanup(func() { usageDB = prev })

	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	since := base.Add(-time.Hour)

	// 1. An approval raised by a policy step-up: it has an originating decision
	//    and a propagated trace.
	approvedID := seedHITLApproval(t, "approved", "11111111-1111-1111-1111-111111111111",
		"dec-origin-1", "4bf92f3577b34da6a3ce929d0e0e4736", base)

	// 2. A REJECTION, because "blocked" is the verdict a reviewer most needs to
	//    find and it travels a different policy_decision value.
	rejectedID := seedHITLApproval(t, "rejected", "22222222-2222-2222-2222-222222222222",
		"dec-origin-2", "", base.Add(time.Minute))

	// 3. An approval with NO originating decision - a WCP step gate, or one
	//    raised before the enqueue path recorded a decision id. #3718 requires
	//    this one to appear too: it is the case where a fallback that keyed the
	//    row on the ORIGINATING id would have written NULL and vanished.
	orphanID := seedHITLApproval(t, "approved", "33333333-3333-3333-3333-333333333333",
		"", "", base.Add(2*time.Minute))

	got := feedDecisionIDs(t, since)

	for _, want := range []struct{ id, why string }{
		{approvedID, "an approval with an originating decision"},
		{rejectedID, "a REJECTION"},
		{orphanID, "an approval with NO originating decision"},
	} {
		if !got[want.id] {
			t.Errorf("%s is ABSENT from the decisions feed (decision_id %q). This is #3718: the "+
				"human oversight decision the platform records most consequentially cannot be found "+
				"where every other decision is. Feed returned: %v", want.why, want.id, keysOf(got))
		}
	}
}

// TestHITLApprovalBeforeTheFixIsInvisible_RealPostgres is the negative control.
//
// It seeds the row the pre-#3718 writer produced and asserts the feed does NOT
// return it. Without this, the positive test above could be green because the
// feed returns every audit row it is given - which would make it a test of
// nothing, on a query whose whole subject is a filter.
func TestHITLApprovalBeforeTheFixIsInvisible_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, auditLogsTestDDL)

	prev := usageDB
	usageDB = pg.DB
	t.Cleanup(func() { usageDB = prev })

	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	since := base.Add(-time.Hour)

	seedHITLApprovalPreFix(t, "44444444-4444-4444-4444-444444444444", base)
	// ...and one row that DOES qualify, so a feed that returned nothing at all
	// (a broken tenant scope, a wrong window) cannot satisfy this assertion by
	// being empty.
	fixedID := seedHITLApproval(t, "approved", "55555555-5555-5555-5555-555555555555",
		"dec-origin-5", "", base.Add(time.Minute))

	got := feedDecisionIDs(t, since)

	if !got[fixedID] {
		t.Fatalf("the control row is missing, so the absence asserted below proves nothing: "+
			"the feed returned %v", keysOf(got))
	}
	if got["hitl_approved_44444444-4444-4444-4444-444444444444"] {
		t.Fatal("the PRE-FIX HITL row appeared in the decisions feed. It carries no decision_id " +
			"column and no policy_details.decision_id, so it must fail the feed's predicate - if it " +
			"does not, the predicate has stopped filtering and the positive test above is vacuous.")
	}
	if len(got) != 1 {
		t.Errorf("expected exactly the one qualifying row, got %d: %v", len(got), keysOf(got))
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestHITLPlaneIsExcludedFromTheLatencyTile pins the pair
// platform/shared/audit's PlaneHITL doc claims.
//
// Stamping a plane on a row is not free: LatencyEnforcementPredicate admits any
// row with a non-null, non-'llm' plane, so a HITL row could have started voting
// itself into the operator's enforcement-latency average - a human decision
// measured in minutes averaged against machine enforcement measured in
// milliseconds. It does not, because the writer binds a NULL response_time_ms,
// and that is asserted here against a REAL Postgres rather than reasoned about.
func TestHITLPlaneIsExcludedFromTheLatencyTile_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, auditLogsTestDDL)

	prev := usageDB
	usageDB = pg.DB
	t.Cleanup(func() { usageDB = prev })

	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	seedHITLApproval(t, "approved", "66666666-6666-6666-6666-666666666666", "dec-6", "", base)

	var n int
	if err := pg.DB.QueryRow(
		`SELECT count(*) FROM audit_logs WHERE ` + audit.LatencyEnforcementPredicate,
	).Scan(&n); err != nil {
		t.Fatalf("count latency samples: %v", err)
	}
	if n != 0 {
		t.Errorf("the HITL row counts as %d enforcement-latency sample(s). It must count as none: "+
			"an approve/reject is an asynchronous human decision with no enforcement duration, and "+
			"admitting one would move the operator's Avg Latency tile by minutes.", n)
	}

	// ...and the same predicate MUST admit an ordinary enforcement row, or the
	// zero above is the predicate matching nothing rather than excluding this
	// row. [[feedback_an_absence_assertion_needs_a_proof_the_run_happened]]
	if _, err := pg.DB.Exec(`
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision,
			policy_details, response_time_ms, plane)
		VALUES ('enf-1','req-enf-1',$1,1,'dev@acme.com','agent','client-acme',$2,'org-acme',
			'tool_call','q','h','allowed','{}',7,'decision')`, base, hitlFeedTenant); err != nil {
		t.Fatalf("seed enforcement row: %v", err)
	}
	if err := pg.DB.QueryRow(
		`SELECT count(*) FROM audit_logs WHERE ` + audit.LatencyEnforcementPredicate,
	).Scan(&n); err != nil {
		t.Fatalf("recount latency samples: %v", err)
	}
	if n != 1 {
		t.Errorf("the enforcement predicate admitted %d rows, want 1; it is matching nothing, so "+
			"the exclusion asserted above is vacuous", n)
	}
}
