// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-PostgreSQL coverage for the HITL enqueue chokepoint (#3408 sibling).
//
// EVERY assertion in this file needs a real database, and none of them could
// have been written with sqlmock:
//
//   - `(xmax = 0) AS inserted` is a PostgreSQL system-column behaviour. sqlmock
//     returns whatever row you hand it, so a sqlmock test of the ON CONFLICT
//     arm asserts the fixture, not the engine. The pre-existing enterprise
//     adapter's one-second created_at heuristic was believed correct for
//     seven months on exactly that basis.
//   - The cap boundary at exactly five needs five rows that really exist and a
//     COUNT that really counts them.
//   - The rollback needs a transaction that really rolls back.
//   - The RLS posture needs a non-owner role. hitl_approval_queue is
//     ENABLE ROW LEVEL SECURITY without FORCE (mig core/025:199), so the table
//     OWNER bypasses every policy - an RLS assertion made on the owner
//     connection passes no matter what the policy says. These run as
//     axonflow_app_role and assert current_user first.
//
// Gating: TEST_PG_INTEGRATION=1 + docker. No build tag, matching the package.

package queue

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/license"
	"axonflow/platform/agent/rls"
)

const (
	testOrg    = "wshitl-org"
	testTenant = "wshitl-tenant"
)

// entitledTier is what the MECHANISM tests inject.
//
// It was TierEvaluation until the 2026-08-26 operator decision made HITL
// Enterprise-only. Every test in this file that exercises the write path then
// started failing at the tier gate - correctly, and loudly, which is how the
// change was found rather than shipped. The write path is not what changed, so
// these tests inject an entitled tier; Evaluation's REFUSAL has its own tests
// (TestEvaluationIsRefusedAtTheChokepoint and friends) rather than being
// folded into these.
//
// The CAP the tests below exercise is passed to NewEnqueuer explicitly, not
// read from this tier's table - which is why the boundary tests still work on
// a tier whose real cap is -1. See TestNoShippedTierCanReachTheCap for the
// guard that keeps that honest.
func entitledTier(context.Context) license.Tier { return license.TierEnterprise }

// setup returns an app-role pool (NOBYPASSRLS) and asserts the posture, so a
// later RLS claim cannot be made from the owner connection by accident.
func setup(t *testing.T) *sql.DB {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../../../migrations/core")

	appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app-role DSN: %v", err)
	}
	t.Cleanup(func() { _ = appRoleDB.Close() })
	approletest.AssertCurrentUser(t, appRoleDB, "axonflow_app_role")
	return appRoleDB
}

func newEnq(db *sql.DB, maxPending int) *Enqueuer {
	e := NewEnqueuer(db, Config{Plane: RequestTypeWCPStepGate, MaxPendingApprovals: maxPending, DefaultExpiry: time.Hour})
	e.SetTierProviderForTest(entitledTier)
	return e
}

func input(requestID uuid.UUID, step string) Input {
	return Input{
		RequestID:           requestID,
		OrgID:               testOrg,
		TenantID:            testTenant,
		ClientID:            "wshitl-client",
		UserID:              "reviewer@example.com",
		OriginalQuery:       step,
		RequestType:         RequestTypeWCPStepGate,
		RequestContext:      map[string]interface{}{"workflow_id": "wf-1", "step_id": step},
		TriggeredPolicyID:   "pol-1",
		TriggeredPolicyName: "wshitl policy",
		TriggerReason:       "Step requires human approval per policy",
		Severity:            "high",
	}
}

func countRows(t *testing.T, db *sql.DB, q string, args ...interface{}) int {
	t.Helper()
	var n int
	// Reads go through the same org scope writes do - a bare read under
	// axonflow_app_role matches zero rows through mig 025's RLS (#3048), which
	// would make every count here a confident, wrong zero.
	err := scopedRead(context.Background(), db, testOrg, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), q, args...).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count query %q: %v", q, err)
	}
	return n
}

// TestEnqueueDistinguishesInsertFromConflict is the assertion the
// InsertIdempotentSQL doc comment points at. `(xmax = 0) AS inserted` is
// canonical but undocumented folklore, and the whole cap accounting rests on
// it: if it reported `true` on the conflict arm, every re-gate of a pending
// step would be charged against MaxPendingApprovals and a workflow at the
// limit could never re-poll its own gate.
func TestEnqueueDistinguishesInsertFromConflict(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	id := uuid.New()

	row, outcome, err := enq.Enqueue(context.Background(), input(id, "step-a"))
	if err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if !row.Inserted || outcome != OutcomeCreated {
		t.Fatalf("first enqueue: inserted=%v outcome=%q, want true/created", row.Inserted, outcome)
	}

	row2, outcome2, err := enq.Enqueue(context.Background(), input(id, "step-a"))
	if err != nil {
		t.Fatalf("second enqueue: %v", err)
	}
	if row2.Inserted || outcome2 != OutcomeReused {
		t.Fatalf("second enqueue: inserted=%v outcome=%q, want false/reused", row2.Inserted, outcome2)
	}
	if row2.RequestID != row.RequestID || row2.ID != row.ID {
		t.Errorf("conflict arm returned a different row: %v/%d vs %v/%d",
			row2.RequestID, row2.ID, row.RequestID, row.ID)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue WHERE request_id = $1`, id); n != 1 {
		t.Errorf("row count = %d, want exactly 1", n)
	}
	// Exactly ONE `created` history entry: the reuse must not append a second.
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_history WHERE request_id = $1 AND action = 'created'`, id); n != 1 {
		t.Errorf("created-history rows = %d, want exactly 1", n)
	}
}

// TestConcurrentFirstTimeEnqueuesProduceOneRow is the DoD's "concurrent-call
// test shows one row, not two".
//
// This is the property the pre-existing enterprise adapter had and the
// community/Evaluation one did NOT: the eval adapter minted uuid.New() per
// call, so N concurrent gates produced N pending rows for one step.
func TestConcurrentFirstTimeEnqueuesProduceOneRow(t *testing.T) {
	db := setup(t)
	db.SetMaxOpenConns(8)
	enq := newEnq(db, 0)
	id := uuid.New()

	const racers = 6
	var wg sync.WaitGroup
	results := make([]Outcome, racers)
	errs := make([]error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, outcome, err := enq.Enqueue(context.Background(), input(id, "step-race"))
			results[i], errs[i] = outcome, err
		}(i)
	}
	wg.Wait()

	created := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racer %d failed: %v", i, err)
		}
		if results[i] == OutcomeCreated {
			created++
		}
	}
	if created != 1 {
		t.Errorf("%d racers reported 'created', want exactly 1", created)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue WHERE request_id = $1`, id); n != 1 {
		t.Errorf("row count after %d concurrent enqueues = %d, want 1", racers, n)
	}
}

// TestCapBoundaryAtExactlyFive is the DoD's "cap boundary tested at exactly 5
// pending", in BOTH directions.
//
// [[feedback_an_assertion_that_cannot_pass_is_the_same_defect_as_one_that_cannot_fail]]
// - the fifth must be ADMITTED and the sixth must be REFUSED. A test that
// asserted only the refusal would pass just as happily against an off-by-one
// that capped the tenant at four.
func TestCapBoundaryAtExactlyFive(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 5)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		_, outcome, err := enq.Enqueue(ctx, input(uuid.New(), fmt.Sprintf("step-%d", i)))
		if err != nil {
			t.Fatalf("approval %d of 5 was refused under a cap of 5: %v", i, err)
		}
		if outcome != OutcomeCreated {
			t.Fatalf("approval %d outcome = %q, want created", i, outcome)
		}
	}
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`, testTenant); n != 5 {
		t.Fatalf("pending rows after five admits = %d, want 5", n)
	}

	_, outcome, err := enq.Enqueue(ctx, input(uuid.New(), "step-6"))
	if !errors.Is(err, ErrPendingCapReached) {
		t.Fatalf("sixth enqueue error = %v, want ErrPendingCapReached", err)
	}
	if outcome != OutcomeCapReached {
		t.Errorf("sixth outcome = %q, want cap_reached", outcome)
	}
	// The refusal must carry the real numbers, not a bare sentinel.
	if !strings.Contains(err.Error(), testTenant) || !strings.Contains(err.Error(), "limit 5") {
		t.Errorf("refusal does not name the tenant and limit: %v", err)
	}

	// AND IT MUST LEAVE NOTHING BEHIND. The insert is speculative - it has
	// already run when the cap is measured - so a missing rollback would
	// refuse the caller while still growing the queue the cap protects.
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE tenant_id = $1`, testTenant); n != 5 {
		t.Errorf("rows after a capped attempt = %d, want 5 - the speculative INSERT was not rolled back", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_history`); n != 5 {
		t.Errorf("history rows after a capped attempt = %d, want 5", n)
	}
}

// TestReGateAtTheCapIsStillAdmitted is the case that made "count after insert"
// the right ordering rather than a clever one.
//
// A tenant AT OR OVER the cap must still be able to re-gate a step that is
// ALREADY in the queue - otherwise a workflow at the limit can never re-poll
// its own pending approval and the cap silently becomes a deadlock.
// Count-then-insert, which is what hitl.Service still does, fails this.
//
// THE FIXTURE PUTS THE TENANT *OVER* THE CAP, NOT AT IT. An earlier version
// seeded exactly five against a cap of five, and the M3 mutant (charging the
// cap on re-gates as well as new rows) SURVIVED it: with five pending and a
// limit of five, `5 > 5` is false, so the mutant admitted the re-gate too and
// the test could not tell the two apart. Six pending against a limit of five
// is the state that discriminates - and it is reachable in production the
// moment an operator lowers a tenant's tier.
func TestReGateAtTheCapIsStillAdmitted(t *testing.T) {
	db := setup(t)
	ctx := context.Background()

	// Seed SIX pending rows with the cap disabled, so the fixture itself is
	// not shaped by the code under test.
	seeder := newEnq(db, 0)
	first := uuid.New()
	if _, _, err := seeder.Enqueue(ctx, input(first, "step-1")); err != nil {
		t.Fatalf("seed enqueue 1: %v", err)
	}
	for i := 2; i <= 6; i++ {
		if _, _, err := seeder.Enqueue(ctx, input(uuid.New(), fmt.Sprintf("step-%d", i))); err != nil {
			t.Fatalf("seed enqueue %d: %v", i, err)
		}
	}
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`, testTenant); n != 6 {
		t.Fatalf("fixture: %d pending, want 6 (the tenant must be OVER the cap)", n)
	}

	capped := newEnq(db, 5)

	// A re-gate of an EXISTING step is admitted even six-over-five...
	_, outcome, err := capped.Enqueue(ctx, input(first, "step-1"))
	if err != nil {
		t.Fatalf("re-gate of an already-queued step over the cap was refused: %v", err)
	}
	if outcome != OutcomeReused {
		t.Errorf("re-gate outcome = %q, want reused", outcome)
	}

	// ...while a NEW step is still refused. Without this half the test would
	// pass against an implementation that simply never enforced the cap.
	if _, outcome, err := capped.Enqueue(ctx, input(uuid.New(), "step-new")); !errors.Is(err, ErrPendingCapReached) {
		t.Errorf("a NEW approval over the cap was admitted (outcome %q, err %v)", outcome, err)
	}
}

// TestConcurrentEnqueuesRespectTheCapExactly is what the per-(org,tenant)
// advisory lock buys, and it is the property the duplicate-row test could not
// see.
//
// ON CONFLICT alone already guarantees one row per request_id, so removing the
// lock does not create duplicates - the first mutation pass proved that by
// leaving TestConcurrentFirstTimeEnqueuesProduceOneRow green with the lock
// gone. What the lock protects is the CAP: without it, each racer's COUNT runs
// in its own snapshot and misses the others' uncommitted rows, so N concurrent
// first-time enqueues can all pass a cap of one.
func TestConcurrentEnqueuesRespectTheCapExactly(t *testing.T) {
	db := setup(t)
	db.SetMaxOpenConns(12)
	const cap0 = 3
	const racers = 10
	enq := newEnq(db, cap0)

	var wg sync.WaitGroup
	outcomes := make([]Outcome, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// DISTINCT request_ids: every racer is a first-time enqueue, so
			// each one genuinely contends for a cap slot. Sharing one id would
			// make ON CONFLICT absorb the race and measure nothing.
			_, outcomes[i], _ = enq.Enqueue(context.Background(), input(uuid.New(), fmt.Sprintf("step-%d", i)))
		}(i)
	}
	wg.Wait()

	created := 0
	for _, o := range outcomes {
		if o == OutcomeCreated {
			created++
		}
	}
	if created != cap0 {
		t.Errorf("%d of %d racers were admitted under a cap of %d, want exactly %d",
			created, racers, cap0, cap0)
	}
	n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`, testTenant)
	if n != cap0 {
		t.Errorf("%d pending rows after %d concurrent enqueues against a cap of %d, want %d - "+
			"the cap overshot", n, racers, cap0, cap0)
	}
}

// TestTierGateRefusesUnderCommunity pins #1998's acceptance criterion on this
// plane: a Community-tier process writes NO row. The enterprise WCP adapter
// consulted no licence at all before this change.
func TestTierGateRefusesUnderCommunity(t *testing.T) {
	db := setup(t)
	enq := NewEnqueuer(db, Config{Plane: RequestTypeWCPStepGate, MaxPendingApprovals: 5})
	enq.SetTierProviderForTest(func(context.Context) license.Tier { return license.TierCommunity })

	_, outcome, err := enq.Enqueue(context.Background(), input(uuid.New(), "step-x"))
	if !errors.Is(err, ErrTierDisabled) {
		t.Fatalf("error = %v, want ErrTierDisabled", err)
	}
	if outcome != OutcomeTierDisabled {
		t.Errorf("outcome = %q, want tier_disabled", outcome)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue`); n != 0 {
		t.Errorf("%d rows written on a Community-tier process, want 0", n)
	}
}

// TestEnqueuePassesRLSUnderAppRole is the DoD's "RLS org guard preserved;
// ON CONFLICT branch passes under app_role".
//
// The ON CONFLICT arm is effectively an UPDATE, so it is gated by mig 025's
// UPDATE USING predicate as well as the INSERT WITH CHECK - the pre-existing
// enterprise adapter's comment says exactly this and it is the reason the wrap
// exists. This asserts the CONFLICT arm specifically, under a NOBYPASSRLS
// role, which is the combination that could regress silently.
func TestEnqueuePassesRLSUnderAppRole(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	id := uuid.New()
	ctx := context.Background()

	if _, _, err := enq.Enqueue(ctx, input(id, "step-rls")); err != nil {
		t.Fatalf("insert arm under app_role: %v", err)
	}
	// Second call takes the DO UPDATE arm.
	if _, outcome, err := enq.Enqueue(ctx, input(id, "step-rls")); err != nil {
		t.Fatalf("ON CONFLICT arm under app_role: %v", err)
	} else if outcome != OutcomeReused {
		t.Fatalf("outcome = %q, want reused - the conflict arm did not run", outcome)
	}

	// An enqueue for a DIFFERENT org must not be able to write under this
	// org's scope: the WITH CHECK predicate compares the row's org_id to the
	// GUC, and WithOrgScope pins the GUC to Input.OrgID, so the two always
	// agree. What this proves is that the wrap is REAL - remove it and the
	// insert fails under app_role rather than succeeding unscoped.
	var scoped string
	if err := scopedRead(ctx, db, testOrg, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT current_setting('app.current_org_id', true)`).Scan(&scoped)
	}); err != nil {
		t.Fatalf("read back the GUC: %v", err)
	}
	if scoped != testOrg {
		t.Errorf("app.current_org_id = %q inside the scope, want %q", scoped, testOrg)
	}
}

// TestResolveMirrorResolvesAndRecordsHistory is #3408's core assertion, at the
// data layer: the mirror row leaves `pending`, records the reviewer, and gains
// a history entry.
func TestResolveMirrorResolvesAndRecordsHistory(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	id := uuid.New()

	if _, _, err := enq.Enqueue(ctx, input(id, "step-mirror")); err != nil {
		t.Fatalf("seed enqueue: %v", err)
	}
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE request_id = $1 AND status = 'pending'`, id); n != 1 {
		t.Fatalf("precondition: mirror is not pending")
	}

	err := ResolveMirror(ctx, db, StatusParams{
		OrgID:         testOrg,
		RequestID:     id,
		Status:        "approved",
		ReviewerID:    "ops@example.com",
		ReviewerEmail: "ops@example.com",
		ReviewerRole:  "workflow_approver",
		Comment:       "approved on the workflow plane",
	}, testTenant)
	if err != nil {
		t.Fatalf("ResolveMirror: %v", err)
	}

	// The badge predicate itself - not a proxy for it.
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE org_id = $1 AND status = 'pending'`, testOrg); n != 0 {
		t.Errorf("pending rows after resolution = %d, want 0 - the phantom survived", n)
	}
	var status, reviewer string
	var reviewedAt sql.NullTime
	if err := scopedRead(ctx, db, testOrg, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT status, COALESCE(reviewer_email,''), reviewed_at FROM hitl_approval_queue WHERE request_id = $1`, id).
			Scan(&status, &reviewer, &reviewedAt)
	}); err != nil {
		t.Fatalf("read resolved row: %v", err)
	}
	if status != "approved" || reviewer != "ops@example.com" || !reviewedAt.Valid {
		t.Errorf("resolved row = status %q reviewer %q reviewed_at valid=%v; want approved/ops@example.com/true",
			status, reviewer, reviewedAt.Valid)
	}
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_history WHERE request_id = $1 AND action = 'approved'`, id); n != 1 {
		t.Errorf("approved-history rows = %d, want 1", n)
	}
}

// TestResolveMirrorIsIdempotentAndSafeWhenAbsent pins the two benign cases the
// resolver must NOT turn into operator-visible failures: an already-terminal
// mirror (a second approve attempt) and no mirror at all (a deployment whose
// adapter was never wired).
//
// Getting this wrong in the other direction is a real hazard: if a missing
// mirror failed loudly, every community deployment's approve path would log an
// error on every approval.
func TestResolveMirrorIsIdempotentAndSafeWhenAbsent(t *testing.T) {
	db := setup(t)
	ctx := context.Background()

	if err := ResolveMirror(ctx, db, StatusParams{
		OrgID: testOrg, RequestID: uuid.New(), Status: "approved",
	}, testTenant); !errors.Is(err, ErrNotPending) {
		t.Errorf("resolving an ABSENT mirror = %v, want ErrNotPending", err)
	}

	enq := newEnq(db, 0)
	id := uuid.New()
	if _, _, err := enq.Enqueue(ctx, input(id, "step-twice")); err != nil {
		t.Fatalf("seed enqueue: %v", err)
	}
	p := StatusParams{OrgID: testOrg, RequestID: id, Status: "approved", ReviewerID: "ops@example.com"}
	if err := ResolveMirror(ctx, db, p, testTenant); err != nil {
		t.Fatalf("first resolution: %v", err)
	}
	if err := ResolveMirror(ctx, db, p, testTenant); !errors.Is(err, ErrNotPending) {
		t.Errorf("second resolution = %v, want ErrNotPending", err)
	}
	// And it must not have appended a second history entry.
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_history WHERE request_id = $1 AND action = 'approved'`, id); n != 1 {
		t.Errorf("approved-history rows after two resolutions = %d, want 1", n)
	}
}

// scopedRead runs fn inside a transaction with app.current_org_id pinned.
//
// Every read in this file goes through it, deliberately. hitl_approval_queue
// is ENABLE RLS with a policy keyed on org_id (mig core/025:199), and these
// tests run as axonflow_app_role (NOBYPASSRLS) - so a BARE `SELECT count(*)`
// here returns 0 for every query, and every assertion of the form "want 0"
// would pass while measuring nothing. That is #3048's bug reproduced inside
// its own regression test.
func scopedRead(ctx context.Context, db *sql.DB, org string, fn func(*sql.Tx) error) error {
	return rls.WithOrgScope(ctx, db, org, fn)
}

// TestResolveMirrorRefusesToWriteANullReviewer is the regression pin for the
// R3 finding that a plan-resume approve left the mirror pending FOR EVER.
//
// migrations/core/025:77 declares
//
//	CHECK (status NOT IN ('approved','rejected') OR reviewer_id IS NOT NULL)
//
// and an empty reviewer binds SQL NULL. `run.go`'s plan-resume handler passed
// `r.Header.Get("X-User-ID")` with no `"system"` fallback - the only approve
// path without one - and the identity headers are stripped unless
// AXONFLOW_TRUST_IDENTITY_HEADERS is on, which is the default. So on that
// route the resolution failed with a 23514, was logged and counted, and the
// row stayed `pending`: #3408 unfixed, on the one path the other tests did not
// reach.
//
// This asserts the CONSTRAINT is real (an empty reviewer is genuinely refused
// by the database) and that the caller-side substitution is what keeps the
// resolution working. Without the first half the test would pass on a schema
// where the column is nullable, proving nothing.
func TestResolveMirrorRefusesToWriteANullReviewer(t *testing.T) {
	db := setup(t)
	ctx := context.Background()
	enq := newEnq(db, 0)

	// Half 1: the constraint is real. An empty reviewer must FAIL.
	bare := uuid.New()
	if _, _, err := enq.Enqueue(ctx, input(bare, "step-null-reviewer")); err != nil {
		t.Fatalf("seed enqueue: %v", err)
	}
	err := ResolveMirror(ctx, db, StatusParams{
		OrgID: testOrg, RequestID: bare, Status: "approved", ReviewerID: "",
	}, testTenant)
	if err == nil {
		t.Fatalf("resolving with an EMPTY reviewer succeeded; " +
			"either the mig core/025:77 CHECK is gone or the column became nullable, " +
			"and the caller-side substitution this pins is no longer load-bearing")
	}
	if !strings.Contains(err.Error(), "hitl_reviewed_requires_reviewer") {
		t.Errorf("empty-reviewer failure was %v; wanted the "+
			"hitl_reviewed_requires_reviewer CHECK, so this test is failing for its own reason", err)
	}
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE request_id = $1 AND status = 'pending'`, bare); n != 1 {
		t.Errorf("the refused resolution did not leave the row pending (found %d)", n)
	}

	// Half 2: the substitution the orchestrator's resolver applies works.
	named := uuid.New()
	if _, _, err := enq.Enqueue(ctx, input(named, "step-system-reviewer")); err != nil {
		t.Fatalf("seed enqueue: %v", err)
	}
	if err := ResolveMirror(ctx, db, StatusParams{
		OrgID: testOrg, RequestID: named, Status: "approved",
		ReviewerID: "system", ReviewerEmail: "system", ReviewerRole: "workflow_approver",
	}, testTenant); err != nil {
		t.Fatalf("resolving with the \"system\" substitution failed: %v", err)
	}
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE request_id = $1 AND status = 'approved'`, named); n != 1 {
		t.Errorf("the substituted resolution did not land (found %d approved rows)", n)
	}
}

// TestNilTierProviderFailsClosed pins R3 round 1's fail-direction fix.
//
// The gate was `if e.currentTier != nil && !IsEvaluationOrHigher(...)`, so a
// nil tier source meant "admit everything" - the fail-OPEN direction on a gate
// whose entire purpose is a refusal. NewEnqueuer always sets a provider, so
// production was never exposed; but a nil one is a WIRING defect, and a wiring
// defect must not silently disable a governance gate.
//
// The handle points at a host that does not exist, and database/sql connects
// LAZILY - so reaching any statement would fail with a dial error instead.
// Getting ErrTierDisabled is therefore also proof the refusal lands before the
// chokepoint touches the database. A nil handle would NOT prove it: the nil-db
// guard runs first and would mask the tier gate entirely.
func TestNilTierProviderFailsClosed(t *testing.T) {
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/nodb?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("open a lazy handle: %v", err)
	}
	defer func() { _ = db.Close() }()

	enq := NewEnqueuer(db, Config{Plane: RequestTypeWCPStepGate, MaxPendingApprovals: 5})
	enq.SetTierProviderForTest(nil)

	_, outcome, err := enq.Enqueue(context.Background(), input(uuid.New(), "step-nil-tier"))
	if !errors.Is(err, ErrTierDisabled) {
		t.Fatalf("error = %v, want it to wrap ErrTierDisabled", err)
	}
	if outcome != OutcomeTierDisabled {
		t.Errorf("outcome = %q, want tier_disabled", outcome)
	}
	// The refusal must say it is a WIRING problem, not a licence problem -
	// otherwise an operator goes hunting for a licence that is fine.
	if !strings.Contains(err.Error(), "wiring defect") {
		t.Errorf("refusal does not identify itself as a wiring defect: %v", err)
	}
}

// TestNoShippedTierCanReachTheCap is the guard that keeps the cap machinery
// honest now that no configuration reaches it.
//
// Since the 2026-08-26 operator decision HITL is Enterprise-only, and every
// entitled tier maps onto EnterpriseLimits with MaxPendingApprovals -1
// (unlimited). Every tier that declares a FINITE cap has HITLApprovalEnabled
// false, so the tier gate refuses first. The cap tests below therefore
// exercise a MECHANISM, not a reachable configuration - which is exactly the
// state that rots into "an assertion no configuration can make fail".
//
// This test is what stops that. It fails the moment a tier is both entitled
// AND finitely capped, which is the only circumstance under which the
// boundary tests become live again and need re-reading.
//
// It runs against the COMPILED tier table, so each build tag checks its own.
func TestNoShippedTierCanReachTheCap(t *testing.T) {
	// ALL EIGHT tiers, not the five an earlier version listed. R3 round 1:
	// Free, Pro and Premium exist in BOTH build tables, each declaring
	// MaxPendingApprovals 5, and Pro already carries MaxHITLApprovalsPerWeek
	// 20 - so "a SaaS-plugin tier gains HITL" is a plausible product move and
	// was exactly the case the guard could not see.
	tiers := []license.Tier{
		license.TierCommunity, license.TierEvaluation, license.TierProfessional,
		license.TierEnterprise, license.TierEnterprisePlus,
		license.TierFree, license.TierPro, license.TierPremium,
	}
	checked := 0
	for _, tr := range tiers {
		lim := license.GetTierLimits(tr)
		checked++
		if !lim.HITLApprovalEnabled {
			continue // gate refuses first; the cap is unreachable by construction
		}
		if lim.MaxPendingApprovals > 0 {
			t.Errorf("tier %q is HITL-entitled AND finitely capped (MaxPendingApprovals=%d).\n"+
				"The cap is reachable again, so the boundary tests in this file "+
				"(TestCapBoundaryAtExactlyFive, TestReGateAtTheCapIsStillAdmitted, "+
				"TestConcurrentEnqueuesRespectTheCapExactly) now describe live behaviour "+
				"and their numbers must be re-derived from this tier rather than injected.",
				tr, lim.MaxPendingApprovals)
		}
	}
	// Positive control. The floor is the length of the list above, so this
	// only catches an empty loop - it is deliberately NOT a claim that the
	// list is complete, which no test can make about a hand-written list.
	// What makes the list trustworthy is that it names every Tier constant
	// the package declares; TestTierListCoversEveryDeclaredTier is the guard
	// that keeps it that way.
	if checked != len(tiers) || checked == 0 {
		t.Fatalf("checked %d of %d tiers - the loop did not run to completion", checked, len(tiers))
	}
	// And the entitlement itself must be non-empty, or the whole feature is off
	// and this guard passes for the wrong reason.
	entitled := 0
	for _, tr := range tiers {
		if license.GetTierLimits(tr).HITLApprovalEnabled {
			entitled++
		}
	}
	if entitled == 0 {
		t.Fatal("NO tier is HITL-entitled - either the tables were emptied or this guard " +
			"is reading the wrong ones; either way it is passing vacuously")
	}
}

// TestHITLEntitlementMatchesTheOperatorDecision is the tier-by-tier pin for
// the 2026-08-26 decision: HITL is Enterprise-only.
//
// Asserted per tier and in BOTH directions - the entitled ones must be
// admitted and the refused ones must be refused. A one-directional list would
// pass against a predicate that refuses everything, which is the failure mode
// a tightening change is most likely to produce.
//
// The `want` map is written out BY HAND from the operator decision rather than
// derived from the tables under test - which is what stops it being circular.
// A version that looped over GetTierLimits and compared it to
// IsHITLApprovalEntitled would pass for any table at all, because the
// predicate reads that same table.
func TestHITLEntitlementMatchesTheOperatorDecision(t *testing.T) {
	// Written out by hand from the operator decision, NOT derived from the
	// tables under test.
	want := map[license.Tier]bool{
		license.TierCommunity:      false,
		license.TierEvaluation:     false, // WAS true until 2026-08-26
		license.TierProfessional:   true,
		license.TierEnterprise:     true,
		license.TierEnterprisePlus: true,
		// The SaaS-plugin tiers. They were missing from an earlier version of
		// this map, so a product change entitling one of them would have gone
		// unasserted - and Pro already carries MaxHITLApprovalsPerWeek 20,
		// which makes that a plausible move rather than a hypothetical.
		license.TierFree:    false,
		license.TierPro:     false,
		license.TierPremium: false,
	}
	if len(want) != 8 {
		t.Fatalf("the entitlement map covers %d tiers, want 8 - see TestTierListCoversEveryDeclaredTier", len(want))
	}
	for tr, expected := range want {
		if got := license.IsHITLApprovalEntitled(tr); got != expected {
			t.Errorf("IsHITLApprovalEntitled(%q) = %v, want %v", tr, got, expected)
		}
	}
}

// TestEvaluationIsRefusedAtTheChokepoint drives the refusal through the real
// enqueue path rather than through the predicate, and asserts nothing was
// written.
//
// Evaluation is the tier this decision REMOVES, so it gets its own test: a
// deployment that had workflow approvals yesterday must be refused today, at
// the chokepoint, with the tier it actually resolved named in the error.
func TestEvaluationIsRefusedAtTheChokepoint(t *testing.T) {
	db := setup(t)
	enq := NewEnqueuer(db, Config{Plane: RequestTypeWCPStepGate, MaxPendingApprovals: 25})
	enq.SetTierProviderForTest(func(context.Context) license.Tier { return license.TierEvaluation })

	_, outcome, err := enq.Enqueue(context.Background(), input(uuid.New(), "step-eval"))
	if !errors.Is(err, ErrTierDisabled) {
		t.Fatalf("error = %v, want ErrTierDisabled", err)
	}
	if outcome != OutcomeTierDisabled {
		t.Errorf("outcome = %q, want tier_disabled", outcome)
	}
	// The refusal must name the tier the process really resolved - otherwise
	// an operator on a valid Evaluation licence goes hunting a licence-loading
	// bug that does not exist.
	if !strings.Contains(err.Error(), "Evaluation") {
		t.Errorf("refusal does not name the resolved tier: %v", err)
	}
	// And it must NOT advertise Evaluation as a way to get the feature.
	if strings.Contains(err.Error(), "require") && strings.Contains(err.Error(), "Evaluation or higher") {
		t.Errorf("refusal still offers Evaluation as an entitled tier: %v", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue`); n != 0 {
		t.Errorf("%d rows written on an Evaluation-tier process, want 0", n)
	}
}

// TestEntitledTiersStillEnqueue is the other direction, on the real path.
// Without it, a predicate that refuses every tier would satisfy every refusal
// test in this file.
func TestEntitledTiersStillEnqueue(t *testing.T) {
	for _, tr := range []license.Tier{license.TierProfessional, license.TierEnterprise, license.TierEnterprisePlus} {
		t.Run(string(tr), func(t *testing.T) {
			db := setup(t)
			enq := NewEnqueuer(db, Config{Plane: RequestTypeWCPStepGate,
				MaxPendingApprovals: license.GetTierLimits(tr).MaxPendingApprovals})
			enq.SetTierProviderForTest(func(context.Context) license.Tier { return tr })

			row, outcome, err := enq.Enqueue(context.Background(), input(uuid.New(), "step-"+string(tr)))
			if err != nil {
				t.Fatalf("tier %q was refused: %v", tr, err)
			}
			if outcome != OutcomeCreated || !row.Inserted {
				t.Fatalf("tier %q: outcome=%q inserted=%v, want created/true", tr, outcome, row.Inserted)
			}
			if n := countRows(t, db,
				`SELECT count(*) FROM hitl_approval_queue WHERE request_id = $1`, row.RequestID); n != 1 {
				t.Errorf("tier %q wrote %d rows, want 1", tr, n)
			}
		})
	}
}

// setupWithOwner is setup() plus the owner DSN, for the one test that must
// install a failing trigger. Same per-test container, so the trigger cannot
// leak into another test.
func setupWithOwner(t *testing.T) (*sql.DB, *sql.DB) {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../../../migrations/core")

	appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app-role DSN: %v", err)
	}
	t.Cleanup(func() { _ = appRoleDB.Close() })
	approletest.AssertCurrentUser(t, appRoleDB, "axonflow_app_role")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	t.Cleanup(func() { _ = ownerDB.Close() })
	return appRoleDB, ownerDB
}

// inputForTenant is input() for an arbitrary tenant under the SAME org, so a
// cross-tenant assertion is not silently also a cross-ORG one (which RLS would
// block on its own and which would therefore prove nothing about the cap).
func inputForTenant(requestID uuid.UUID, tenant, step string) Input {
	in := input(requestID, step)
	in.TenantID = tenant
	return in
}

// TestCapIsScopedToOneTenant kills mutant M11.
//
// The cap is measured with CountPendingSQL (writer.go:217), whose predicate is
// `WHERE tenant_id = $1 AND status = 'pending'`. Every existing cap test uses a
// single tenant, so dropping `tenant_id = $1` - counting every pending row in
// the ORG against one tenant's limit - changed no assertion and the mutant
// survived.
//
// That is not a cosmetic scoping error. MaxPendingApprovals is a PER-TENANT
// limit; org-wide counting means one busy tenant silently exhausts the approval
// capacity of every other tenant sharing the org, and the refusal blames the
// wrong tenant. On a SaaS stack that is a cross-tenant denial of service.
//
// The fixture puts tenant A exactly AT the cap and then asks tenant B for its
// FIRST approval. Correct: admitted (B has 0 pending). Mutant: refused (it
// counts A's 5). Both directions verified.
func TestCapIsScopedToOneTenant(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 5)
	ctx := context.Background()

	const tenantA = testTenant
	const tenantB = "wshitl-tenant-b"

	// Fill tenant A to exactly the cap.
	for i := 1; i <= 5; i++ {
		_, outcome, err := enq.Enqueue(ctx, inputForTenant(uuid.New(), tenantA, fmt.Sprintf("a-step-%d", i)))
		if err != nil {
			t.Fatalf("tenant A approval %d of 5 was refused under a cap of 5: %v", i, err)
		}
		if outcome != OutcomeCreated {
			t.Fatalf("tenant A approval %d outcome = %q, want created", i, outcome)
		}
	}

	// Anti-vacuity: A really is at the cap, and B really is empty. Without
	// both, an "admitted" result below would prove nothing.
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`, tenantA); n != 5 {
		t.Fatalf("fixture: tenant A has %d pending rows, want exactly 5 (the cap)", n)
	}
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`, tenantB); n != 0 {
		t.Fatalf("fixture: tenant B has %d pending rows, want 0", n)
	}
	// And A is over the cap only in the org-wide sense the mutant would use.
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE status = 'pending'`); n != 5 {
		t.Fatalf("fixture: the org has %d pending rows, want 5 - the mutant and the correct code would not differ otherwise", n)
	}

	// Tenant B's FIRST approval must be admitted.
	_, outcome, err := enq.Enqueue(ctx, inputForTenant(uuid.New(), tenantB, "b-step-1"))
	if err != nil {
		t.Fatalf("tenant B's FIRST approval was refused while tenant A sat at the cap: %v\n"+
			"the pending cap is counting across the whole org instead of per tenant - one tenant can exhaust every other tenant's approval capacity", err)
	}
	if outcome != OutcomeCreated {
		t.Errorf("tenant B first-approval outcome = %q, want created", outcome)
	}
	if n := countRows(t, db,
		`SELECT count(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`, tenantB); n != 1 {
		t.Errorf("tenant B pending rows = %d, want 1", n)
	}

	// The other direction: B's own cap is still enforced, so this test cannot
	// pass by the cap being disabled outright.
	for i := 2; i <= 5; i++ {
		if _, _, err := enq.Enqueue(ctx, inputForTenant(uuid.New(), tenantB, fmt.Sprintf("b-step-%d", i))); err != nil {
			t.Fatalf("tenant B approval %d of 5 was refused: %v", i, err)
		}
	}
	_, outcome, err = enq.Enqueue(ctx, inputForTenant(uuid.New(), tenantB, "b-step-6"))
	if !errors.Is(err, ErrPendingCapReached) {
		t.Fatalf("tenant B's SIXTH approval error = %v, want ErrPendingCapReached - the cap is not enforced per tenant either", err)
	}
	if outcome != OutcomeCapReached {
		t.Errorf("tenant B sixth outcome = %q, want cap_reached", outcome)
	}
	if !strings.Contains(err.Error(), tenantB) {
		t.Errorf("the refusal names the wrong tenant: %v (want %q)", err, tenantB)
	}
}

// TestHistoryFailureRollsBackTheQueueRow kills mutant M12.
//
// enqueuer.go:321-336 returns the history-insert error rather than logging it,
// which rolls the whole transaction back. The comment states the reason - "a
// queue entry with no `created` record is an approval whose provenance cannot
// be reconstructed", the EU AI Act Article 14 trail - but nothing tested it, so
// swallowing that error (which is what hitl.Service does) left every assertion
// green while shipping queue rows with no history.
//
// THE INJECTED FAILURE IS A BEFORE-INSERT TRIGGER THAT RETURNS NULL, NOT ONE
// THAT RAISES. This distinction is the whole test, and the first version got it
// wrong: a RAISE EXCEPTION poisons the Postgres transaction, so the COMMIT
// fails and nothing persists NO MATTER WHAT THE GO CODE DOES. That version
// passed against the mutant - it was measuring Postgres's transaction
// semantics, not this function's error handling, and could not have failed.
//
// A BEFORE INSERT trigger returning NULL silently skips the row instead. The
// `INSERT ... RETURNING` then yields zero rows, Scan returns sql.ErrNoRows -
// a Go-level error - and the transaction stays perfectly healthy. Now the two
// behaviours diverge: returning the error rolls back, while swallowing it
// commits a queue row with no history, which is exactly the hazard.
//
// The trigger is installed as the table owner on this test's own throwaway
// container.
func TestHistoryFailureRollsBackTheQueueRow(t *testing.T) {
	db, owner := setupWithOwner(t)
	enq := newEnq(db, 0) // cap disabled: this test is about the history arm only
	ctx := context.Background()

	// Anti-vacuity 1: without the trigger the enqueue succeeds and writes BOTH
	// rows. If it did not, the assertions after the trigger would be measuring
	// a path that never worked.
	if _, outcome, err := enq.Enqueue(ctx, input(uuid.New(), "pre-trigger")); err != nil || outcome != OutcomeCreated {
		t.Fatalf("baseline enqueue outcome = %q, err = %v; want created/nil", outcome, err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue`); n != 1 {
		t.Fatalf("baseline queue rows = %d, want 1", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_history`); n != 1 {
		t.Fatalf("baseline history rows = %d, want 1", n)
	}

	if _, err := owner.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION wshitl_skip_history() RETURNS trigger AS $$
		BEGIN
			RETURN NULL;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER wshitl_fail_history_trg
			BEFORE INSERT ON hitl_approval_history
			FOR EACH ROW EXECUTE FUNCTION wshitl_skip_history();
	`); err != nil {
		t.Fatalf("install skipping trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = owner.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS wshitl_fail_history_trg ON hitl_approval_history`)
	})

	// Anti-vacuity 2: the trigger really does fire, and it suppresses the row
	// WITHOUT raising. Both halves matter - if it raised, the assertion below
	// could not distinguish the two behaviours.
	if _, err := owner.ExecContext(ctx,
		`INSERT INTO hitl_approval_history (request_id, org_id, tenant_id, action, new_status)
		 VALUES ($1,$2,$3,'created','pending')`, uuid.New(), testOrg, testTenant); err != nil {
		t.Fatalf("fixture: the injected trigger RAISED (%v); it must suppress silently, or this test measures Postgres transaction abort rather than the code under test", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_history`); n != 1 {
		t.Fatalf("fixture: history rows = %d after an insert the trigger should have suppressed, want 1 - the trigger is not firing and this test would pass vacuously", n)
	}

	// THE ASSERTION. The queue insert succeeds, the history insert raises, and
	// the whole transaction must roll back.
	_, outcome, err := enq.Enqueue(ctx, input(uuid.New(), "during-trigger"))
	if err == nil {
		t.Fatalf("enqueue SUCCEEDED with the history insert failing (outcome %q) - the history error was swallowed and a queue row shipped with no Article 14 provenance", outcome)
	}
	if outcome != OutcomeError {
		t.Errorf("outcome = %q, want %q", outcome, OutcomeError)
	}

	// Still exactly the baseline row. A swallowed history error leaves 2.
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue`); n != 1 {
		t.Errorf("queue rows after the failed enqueue = %d, want 1 - the queue INSERT was not rolled back when its history INSERT failed", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_history`); n != 1 {
		t.Errorf("history rows after the failed enqueue = %d, want 1", n)
	}

	// And the other direction: once the trigger is gone the same call works, so
	// the failure above is attributable to the trigger and not to the fixture.
	if _, err := owner.ExecContext(ctx, `DROP TRIGGER wshitl_fail_history_trg ON hitl_approval_history`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if _, outcome, err := enq.Enqueue(ctx, input(uuid.New(), "post-trigger")); err != nil || outcome != OutcomeCreated {
		t.Fatalf("post-trigger enqueue outcome = %q, err = %v; want created/nil", outcome, err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue`); n != 2 {
		t.Errorf("queue rows after the trigger was dropped = %d, want 2", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_history`); n != 2 {
		t.Errorf("history rows after the trigger was dropped = %d, want 2", n)
	}
}

// TestTierListCoversEveryDeclaredTier stops the hand-written tier lists in
// this file going stale.
//
// R3 round 1: TestNoShippedTierCanReachTheCap and
// TestHITLEntitlementMatchesTheOperatorDecision both iterate hand-written
// lists, and both were missing Free, Pro and Premium - so a tier could become
// entitled, or entitled-and-capped, with neither guard noticing. A test cannot
// prove a hand list is complete by iterating it; it has to compare the list
// against the DECLARATIONS.
//
// Source census rather than reflection, for the same reason as the
// approval_enqueue enum guard: Go has no enum to enumerate at runtime.
func TestTierListCoversEveryDeclaredTier(t *testing.T) {
	declared := map[string]bool{}
	for _, f := range []string{"../../license/tier.go", "../../license/tier_support.go"} {
		blob, err := os.ReadFile(f)
		if err != nil {
			continue // one of the two is excluded by the current build tag
		}
		for _, m := range regexp.MustCompile(`(?m)^\s*(Tier\w+)\s+Tier\s*=\s*"`).FindAllStringSubmatch(string(blob), -1) {
			declared[m[1]] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("no `TierX Tier = \"...\"` declarations found - the census is reading the wrong files " +
			"and would otherwise pass against any list at all")
	}

	covered := map[string]bool{
		"TierCommunity": true, "TierEvaluation": true, "TierProfessional": true,
		"TierEnterprise": true, "TierEnterprisePlus": true,
		"TierFree": true, "TierPro": true, "TierPremium": true,
	}
	for name := range declared {
		if !covered[name] {
			t.Errorf("license declares %s but the tier lists in this file do not cover it - "+
				"TestNoShippedTierCanReachTheCap and "+
				"TestHITLEntitlementMatchesTheOperatorDecision are blind to it", name)
		}
	}
}
