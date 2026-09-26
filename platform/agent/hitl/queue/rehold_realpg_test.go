// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-PostgreSQL coverage for a workflow step held AGAIN after its earlier
// hold was decided (#4249 row 5700138809).
//
// Before: the re-hold derived the same request id as the first hold, landed on
// the ON CONFLICT arm against the DECIDED row and came back `reused` - the row
// still `approved`, its reviewer and its first expiry kept, and nothing pending
// for anyone to review. After: a re-hold writes a NEW row under the next hold
// id, and the decided row stays exactly as it was, because the regulator packs
// read that row as the record of the decision.
//
// Gating: TEST_PG_INTEGRATION=1 + docker, as enqueuer_realpg_test.go.

package queue

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// testHoldNamespace and testIDForHold reproduce the workflow plane's hold
// naming (workflow_control.DeriveHITLApprovalIDForHold), which this package
// does not import. TestTestHoldNamingMatchesTheWorkflowPlane pins it to values
// computed with python3 uuid.uuid5 - the same vectors the workflow_control
// test pins - so a drift on either side is a red test, not a silent disagreement.
var testHoldNamespace = uuid.MustParse("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

func testIDForHold(wf, step string) func(int) uuid.UUID {
	return func(n int) uuid.UUID {
		if n < 1 {
			return uuid.Nil
		}
		name := wf + ":" + step
		if n > 1 {
			name += "#" + strconv.Itoa(n)
		}
		return uuid.NewSHA1(testHoldNamespace, []byte(name))
	}
}

func TestTestHoldNamingMatchesTheWorkflowPlane(t *testing.T) {
	f := testIDForHold("wf-4249", "step-a")
	for n, want := range map[int]string{
		1: "a08f5f47-f38c-52b6-ae0a-11aafb53bedf",
		2: "189eab2c-ad75-5b6e-b889-bd62adb01bf8",
		3: "f50ac3da-6baf-5759-901a-dfcc3e8ef4ab",
	} {
		if got := f(n).String(); got != want {
			t.Errorf("hold %d = %s, want %s", n, got, want)
		}
	}
}

// holdInput is input() for a step hold: no RequestID, a StepHold, and the
// request_context pair the enqueue validates (and the unnamed-row check reads).
func holdInput(wf, step string) Input {
	in := input(uuid.Nil, step)
	in.RequestContext = map[string]interface{}{"workflow_id": wf, "step_id": step}
	in.StepHold = &StepHold{WorkflowID: wf, StepID: step, IDForHold: testIDForHold(wf, step)}
	return in
}

// rowJSON is the whole queue row as PostgreSQL renders it, minus the columns
// named in except. Comparing the rendering is what "byte-unchanged" means.
func rowJSON(t *testing.T, db *sql.DB, id uuid.UUID, except ...string) string {
	t.Helper()
	var s string
	q := `SELECT (to_jsonb(q) - $2::text[])::text FROM hitl_approval_queue q WHERE request_id = $1`
	if err := scopedRead(context.Background(), db, testOrg, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), q, id, "{"+strings.Join(except, ",")+"}").Scan(&s)
	}); err != nil {
		t.Fatalf("read row %s: %v", id, err)
	}
	return s
}

// decide moves a pending hold to status through the real transition for it.
func decide(t *testing.T, db *sql.DB, id uuid.UUID, status string) {
	t.Helper()
	ctx := context.Background()
	var err error
	switch status {
	case "approved", "rejected":
		err = ResolveMirror(ctx, db, StatusParams{
			OrgID: testOrg, RequestID: id, Status: status,
			ReviewerID: "ops@example.com", ReviewerEmail: "ops@example.com",
			ReviewerRole: "workflow_approver", Comment: "decided on the workflow plane",
		}, testTenant)
	case "overridden":
		err = Override(ctx, db, OverrideParams{OrgID: testOrg, RequestID: id,
			Justification: "break-glass for the re-hold test", AuthorizedBy: "ops@example.com"})
	case "expired":
		err = scopedRead(ctx, db, testOrg, func(tx *sql.Tx) error {
			var rowID int64
			if e := tx.QueryRowContext(ctx, `SELECT id FROM hitl_approval_queue WHERE request_id = $1`, id).Scan(&rowID); e != nil {
				return e
			}
			return ExpireByIDs(ctx, tx, []int64{rowID})
		})
	default:
		t.Fatalf("decide: unknown status %q", status)
	}
	if err != nil {
		t.Fatalf("decide %s as %s: %v", id, status, err)
	}
}

func stepRows(t *testing.T, db *sql.DB, wf, step string) int {
	t.Helper()
	return countRows(t, db, `SELECT count(*) FROM hitl_approval_queue
		WHERE request_context->>'workflow_id' = $1 AND request_context->>'step_id' = $2`, wf, step)
}

// TestRetryOfAPendingHoldIsReusedAndUnchanged is the behaviour that must NOT
// change: a retried gate of a still-pending step returns that row, `reused`,
// with every column unchanged except updated_at (the BEFORE UPDATE trigger
// moves it on the conflict arm's self-assignment, as it always has).
func TestRetryOfAPendingHoldIsReusedAndUnchanged(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-retry", "step-a"
	hold1 := testIDForHold(wf, step)(1)

	first, outcome, err := enq.Enqueue(ctx, holdInput(wf, step))
	if err != nil || outcome != OutcomeCreated || first.RequestID != hold1 {
		t.Fatalf("first hold: row=%+v outcome=%q err=%v; want created under %s", first, outcome, err, hold1)
	}
	before := rowJSON(t, db, hold1, "updated_at")

	second, outcome, err := enq.Enqueue(ctx, holdInput(wf, step))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if outcome != OutcomeReused || second.Inserted || second.RequestID != hold1 || second.ID != first.ID {
		t.Errorf("retry: outcome=%q inserted=%v id=%s/%d; want reused, the same row %s/%d",
			outcome, second.Inserted, second.RequestID, second.ID, hold1, first.ID)
	}
	if after := rowJSON(t, db, hold1, "updated_at"); after != before {
		t.Errorf("the retried row changed beyond updated_at:\nbefore %s\nafter  %s", before, after)
	}
	if n := stepRows(t, db, wf, step); n != 1 {
		t.Errorf("rows for the step = %d, want 1", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue
		WHERE request_context->>'step_id' = $1 AND status = 'pending'`, step); n != 1 {
		t.Errorf("pending rows for the step = %d, want 1 (a retry opened a second live hold)", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_history WHERE request_id = $1`, hold1); n != 1 {
		t.Errorf("history rows = %d, want the one `created`", n)
	}
}

// TestReHoldOfADecidedHoldWritesANewRow covers each decided status the queue
// has. For each: a NEW pending row under hold 2's id, its own expiry by value,
// no reviewer; the decided row byte-unchanged; one `created` history row
// naming the previous status; outcome `created`.
func TestReHoldOfADecidedHoldWritesANewRow(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()

	for _, status := range []string{"approved", "rejected", "expired", "overridden"} {
		t.Run(status, func(t *testing.T) {
			wf, step := "wf-rehold-"+status, "step-a"
			ids := testIDForHold(wf, step)

			if _, _, err := enq.Enqueue(ctx, holdInput(wf, step)); err != nil {
				t.Fatalf("first hold: %v", err)
			}
			decide(t, db, ids(1), status)
			decidedBefore := rowJSON(t, db, ids(1))
			historyBefore := countRows(t, db, `SELECT count(*) FROM hitl_approval_history WHERE request_id = $1`, ids(1))

			in := holdInput(wf, step)
			in.ExpiresIn = 3 * time.Hour
			var dbNow time.Time
			if err := scopedRead(ctx, db, testOrg, func(tx *sql.Tx) error {
				return tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow)
			}); err != nil {
				t.Fatalf("read the database clock: %v", err)
			}
			row, outcome, err := enq.Enqueue(ctx, in)
			if err != nil {
				t.Fatalf("re-hold: %v", err)
			}

			if outcome != OutcomeCreated || !row.Inserted {
				t.Errorf("outcome = %q inserted = %v, want created/true", outcome, row.Inserted)
			}
			if row.RequestID != ids(2) {
				t.Errorf("request id = %s, want hold 2's %s", row.RequestID, ids(2))
			}
			if row.Status != "pending" {
				t.Errorf("new row status = %q, want pending", row.Status)
			}
			if d := row.ExpiresAt.Sub(dbNow.Add(3 * time.Hour)); d < -time.Minute || d > time.Minute {
				t.Errorf("new row expires_at = %s, want about %s (its own TTL)", row.ExpiresAt, dbNow.Add(3*time.Hour))
			}

			var reviewer, reviewerEmail, reviewerRole, reviewComment sql.NullString
			var reviewedAt sql.NullTime
			if err := scopedRead(ctx, db, testOrg, func(tx *sql.Tx) error {
				return tx.QueryRowContext(ctx, `SELECT reviewer_id, reviewer_email, reviewer_role, review_comment, reviewed_at
					FROM hitl_approval_queue WHERE request_id = $1`, ids(2)).
					Scan(&reviewer, &reviewerEmail, &reviewerRole, &reviewComment, &reviewedAt)
			}); err != nil {
				t.Fatalf("read the new row: %v", err)
			}
			if reviewer.Valid || reviewerEmail.Valid || reviewerRole.Valid || reviewComment.Valid || reviewedAt.Valid {
				t.Errorf("new row carries a review: id=%v email=%v role=%v comment=%v at=%v",
					reviewer, reviewerEmail, reviewerRole, reviewComment, reviewedAt)
			}

			if after := rowJSON(t, db, ids(1)); after != decidedBefore {
				t.Errorf("the decided row changed:\nbefore %s\nafter  %s", decidedBefore, after)
			}
			if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_history WHERE request_id = $1`, ids(1)); n != historyBefore {
				t.Errorf("history rows of the decided hold = %d, want %d unchanged", n, historyBefore)
			}
			if n := stepRows(t, db, wf, step); n != 2 {
				t.Errorf("rows for the step = %d, want 2", n)
			}

			var action, prev, next, comment string
			var historyRows int
			if err := scopedRead(ctx, db, testOrg, func(tx *sql.Tx) error {
				if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM hitl_approval_history WHERE request_id = $1`, ids(2)).Scan(&historyRows); e != nil {
					return e
				}
				return tx.QueryRowContext(ctx, `SELECT action, COALESCE(previous_status,''), COALESCE(new_status,''), COALESCE(comment,'')
					FROM hitl_approval_history WHERE request_id = $1`, ids(2)).Scan(&action, &prev, &next, &comment)
			}); err != nil {
				t.Fatalf("read the new hold's history: %v", err)
			}
			if historyRows != 1 {
				t.Errorf("history rows of the new hold = %d, want 1", historyRows)
			}
			if action != "created" || prev != status || next != "pending" {
				t.Errorf("history = action %q previous %q new %q, want created/%s/pending", action, prev, next, status)
			}
			if !strings.Contains(comment, "re-hold") || !strings.Contains(comment, status) {
				t.Errorf("history comment = %q, want it to name a re-hold and the previous status %q", comment, status)
			}
		})
	}
}

// TestFirstHoldHistoryIsUnchanged: a first hold's history row carries no
// previous status and no comment, as before this change.
func TestFirstHoldHistoryIsUnchanged(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-first", "step-a"
	if _, _, err := enq.Enqueue(ctx, holdInput(wf, step)); err != nil {
		t.Fatalf("first hold: %v", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_history WHERE request_id = $1
		AND action = 'created' AND previous_status IS NULL AND comment IS NULL AND new_status = 'pending'`,
		testIDForHold(wf, step)(1)); n != 1 {
		t.Errorf("first hold's created history with no previous status and no comment = %d, want 1", n)
	}
}

// TestReHoldIsChargedAgainstTheCap: a new-row re-hold IS a creation. With the
// tenant at its cap, it is refused - where a retry of a pending hold at the
// cap is admitted (TestReGateAtTheCapIsStillAdmitted).
func TestReHoldIsChargedAgainstTheCap(t *testing.T) {
	db := setup(t)
	ctx := context.Background()
	ids := testIDForHold("wf-cap", "step-a")

	open := newEnq(db, 0)
	if _, _, err := open.Enqueue(ctx, holdInput("wf-cap", "step-a")); err != nil {
		t.Fatalf("first hold: %v", err)
	}
	decide(t, db, ids(1), "approved")
	if _, _, err := open.Enqueue(ctx, holdInput("wf-cap", "step-b")); err != nil {
		t.Fatalf("occupying hold: %v", err)
	}

	atCap := newEnq(db, 1)
	_, outcome, err := atCap.Enqueue(ctx, holdInput("wf-cap", "step-a"))
	if outcome != OutcomeCapReached || !errors.Is(err, ErrPendingCapReached) {
		t.Errorf("re-hold at the cap: outcome=%q err=%v, want cap_reached", outcome, err)
	}
	if n := stepRows(t, db, "wf-cap", "step-a"); n != 1 {
		t.Errorf("rows for the step after a refused re-hold = %d, want 1", n)
	}

	underCap := newEnq(db, 2)
	if _, outcome, err := underCap.Enqueue(ctx, holdInput("wf-cap", "step-a")); err != nil || outcome != OutcomeCreated {
		t.Errorf("re-hold under the cap: outcome=%q err=%v, want created", outcome, err)
	}
	if n := countRows(t, db, CountPendingSQL, testTenant); n != 2 {
		t.Errorf("pending count = %d, want 2 (step-b and the re-hold)", n)
	}
}

// TestConflictWithADecidedRowIsAnError is the fail-closed guard on every
// caller: an insert that meets a row no longer pending is never `reused`.
func TestConflictWithADecidedRowIsAnError(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()

	t.Run("caller-supplied id", func(t *testing.T) {
		id := uuid.New()
		if _, _, err := enq.Enqueue(ctx, input(id, "step-plain")); err != nil {
			t.Fatalf("seed: %v", err)
		}
		decide(t, db, id, "approved")
		before := rowJSON(t, db, id)
		row, outcome, err := enq.Enqueue(ctx, input(id, "step-plain"))
		if outcome != OutcomeError || !errors.Is(err, ErrResolvedConflict) || row != nil {
			t.Errorf("outcome=%q err=%v row=%v, want error/ErrResolvedConflict/nil", outcome, err, row)
		}
		if after := rowJSON(t, db, id); after != before {
			t.Errorf("the decided row changed (the refused conflict arm must roll back):\nbefore %s\nafter  %s", before, after)
		}
	})

	t.Run("a step hold whose derivation names every hold alike", func(t *testing.T) {
		const wf, step = "wf-bug", "step-a"
		good := testIDForHold(wf, step)
		if _, _, err := enq.Enqueue(ctx, holdInput(wf, step)); err != nil {
			t.Fatalf("first hold: %v", err)
		}
		decide(t, db, good(1), "approved")
		in := holdInput(wf, step)
		// The planted derivation bug: every hold is named hold 1 (today's id).
		// The walk refuses it before the insert could meet the decided row.
		in.StepHold.IDForHold = func(int) uuid.UUID { return good(1) }
		_, outcome, err := enq.Enqueue(ctx, in)
		// Refused at hold 2, on the repeated id - not after walking the same row
		// up to maxHoldsPerStep times.
		if outcome != OutcomeError || !errors.Is(err, ErrHoldSequence) || !strings.Contains(err.Error(), "same id as an earlier hold") {
			t.Errorf("outcome=%q err=%v, want error/ErrHoldSequence naming the repeated id (never reused)", outcome, err)
		}
		if n := stepRows(t, db, wf, step); n != 1 {
			t.Errorf("rows for the step = %d, want 1", n)
		}
	})
}

// TestAStepWithAnUnnamedRowIsNotHeldAgain: a step that has a row outside its
// hold ids is refused a NEW hold (ErrHoldUnnamedRow) rather than getting hold
// 1 beside it, so it can never have two live holds.
func TestAStepWithAnUnnamedRowIsNotHeldAgain(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-unnamed", "step-a"

	stray := input(uuid.New(), step)
	stray.RequestContext = map[string]interface{}{"workflow_id": wf, "step_id": step}
	if _, _, err := enq.Enqueue(ctx, stray); err != nil {
		t.Fatalf("stray row: %v", err)
	}
	_, outcome, err := enq.Enqueue(ctx, holdInput(wf, step))
	if outcome != OutcomeError || !errors.Is(err, ErrHoldUnnamedRow) || !strings.Contains(err.Error(), stray.RequestID.String()) {
		t.Errorf("outcome=%q err=%v, want error/ErrHoldUnnamedRow naming %s", outcome, err, stray.RequestID)
	}
	if n := stepRows(t, db, wf, step); n != 1 {
		t.Errorf("rows for the step = %d, want 1", n)
	}
}

// TestADecidedUnnamedRowDoesNotBlockAHold: only a PENDING stray is a live
// hold the new one could sit beside. A decided stray (a legacy row reviewed long
// ago) must not wedge the step: hold 1 is written.
func TestADecidedUnnamedRowDoesNotBlockAHold(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-decided-stray", "step-a"

	stray := input(uuid.New(), step)
	stray.RequestContext = map[string]interface{}{"workflow_id": wf, "step_id": step}
	if _, _, err := enq.Enqueue(ctx, stray); err != nil {
		t.Fatalf("stray row: %v", err)
	}
	decide(t, db, stray.RequestID, "approved")

	row, outcome, err := enq.Enqueue(ctx, holdInput(wf, step))
	if err != nil || outcome != OutcomeCreated || row.RequestID != testIDForHold(wf, step)(1) {
		t.Errorf("hold beside a decided stray: outcome=%q err=%v, want hold 1 created", outcome, err)
	}
}

// TestAPendingUnnamedRowWithNoHoldRefusesTheExpiryRead: a step whose gate was
// refused its first hold because of a pending stray is still held. Its expiry
// read must refuse rather than report "no expiry", which would let a late
// approval skip the hold's deadline. Once the stray is decided the step has no
// live row and the read reports no hold, as for any step without one.
func TestAPendingUnnamedRowWithNoHoldRefusesTheExpiryRead(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-stray-expiry", "step-a"

	stray := input(uuid.New(), step)
	stray.RequestContext = map[string]interface{}{"workflow_id": wf, "step_id": step}
	if _, _, err := enq.Enqueue(ctx, stray); err != nil {
		t.Fatalf("stray row: %v", err)
	}
	if _, _, err := enq.Enqueue(ctx, holdInput(wf, step)); !errors.Is(err, ErrHoldUnnamedRow) {
		t.Fatalf("precondition: hold 1 refused by the stray, got %v", err)
	}
	if _, _, found, err := CurrentHoldExpiry(ctx, db, testOrg, *holdInput(wf, step).StepHold); !errors.Is(err, ErrHoldUnnamedRow) || found {
		t.Errorf("expiry read with a pending stray and no hold: found=%v err=%v, want ErrHoldUnnamedRow", found, err)
	}

	decide(t, db, stray.RequestID, "rejected")
	if _, _, found, err := CurrentHoldExpiry(ctx, db, testOrg, *holdInput(wf, step).StepHold); err != nil || found {
		t.Errorf("expiry read once the stray is decided: found=%v err=%v, want no hold and no error", found, err)
	}
}

// TestAHoldAfterAPendingHoldIsRefused: holds are consecutive with at most one
// pending, the newest. A hold written after a still-pending one (not something
// this package writes) is ErrHoldSequence on the enqueue and on the reads.
func TestAHoldAfterAPendingHoldIsRefused(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-seq", "step-a"
	ids := testIDForHold(wf, step)

	if _, _, err := enq.Enqueue(ctx, holdInput(wf, step)); err != nil {
		t.Fatalf("hold 1: %v", err)
	}
	out := input(ids(2), step)
	out.RequestContext = map[string]interface{}{"workflow_id": wf, "step_id": step}
	if _, _, err := enq.Enqueue(ctx, out); err != nil {
		t.Fatalf("out-of-sequence hold 2: %v", err)
	}
	if _, outcome, err := enq.Enqueue(ctx, holdInput(wf, step)); outcome != OutcomeError || !errors.Is(err, ErrHoldSequence) {
		t.Errorf("enqueue: outcome=%q err=%v, want error/ErrHoldSequence", outcome, err)
	}
	if _, _, err := CurrentHoldID(ctx, db, testOrg, *holdInput(wf, step).StepHold); !errors.Is(err, ErrHoldSequence) {
		t.Errorf("CurrentHoldID err=%v, want ErrHoldSequence", err)
	}
	if _, _, _, err := CurrentHoldExpiry(ctx, db, testOrg, *holdInput(wf, step).StepHold); !errors.Is(err, ErrHoldSequence) {
		t.Errorf("CurrentHoldExpiry err=%v, want ErrHoldSequence", err)
	}
}

// TestAHoldIDThatNamesAnotherStepIsRefused: step "a#2"'s hold 1 and step "a"'s
// hold 2 are the same name. Whichever is written first, the other is refused
// rather than answered with a row of another step - from both sides.
func TestAHoldIDThatNamesAnotherStepIsRefused(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf = "wf-collide"
	if testIDForHold(wf, "a")(2) != testIDForHold(wf, "a#2")(1) {
		t.Fatal("precondition: hold 2 of a and hold 1 of a#2 are not the same id; the cell proves nothing")
	}

	t.Run("a#2 first, then a is re-held", func(t *testing.T) {
		if _, _, err := enq.Enqueue(ctx, holdInput(wf, "a#2")); err != nil {
			t.Fatalf("a#2 hold 1: %v", err)
		}
		if _, _, err := enq.Enqueue(ctx, holdInput(wf, "a")); err != nil {
			t.Fatalf("a hold 1: %v", err)
		}
		decide(t, db, testIDForHold(wf, "a")(1), "approved")
		_, outcome, err := enq.Enqueue(ctx, holdInput(wf, "a"))
		if outcome != OutcomeError || !errors.Is(err, ErrHoldOwnership) {
			t.Errorf("re-hold of a: outcome=%q err=%v, want error/ErrHoldOwnership (not reused of a#2's row)", outcome, err)
		}
		// The reads refuse too: an approval of step a must not be judged by, or
		// resolve, a#2's pending row.
		if id, _, err := CurrentHoldID(ctx, db, testOrg, *holdInput(wf, "a").StepHold); !errors.Is(err, ErrHoldOwnership) {
			t.Errorf("CurrentHoldID(a) = %s err=%v, want ErrHoldOwnership", id, err)
		}
		if _, _, _, err := CurrentHoldExpiry(ctx, db, testOrg, *holdInput(wf, "a").StepHold); !errors.Is(err, ErrHoldOwnership) {
			t.Errorf("CurrentHoldExpiry(a) err=%v, want ErrHoldOwnership", err)
		}
	})

	const wf2 = "wf-collide-2"
	t.Run("a's hold 2 first, then a#2 is held", func(t *testing.T) {
		if _, _, err := enq.Enqueue(ctx, holdInput(wf2, "a")); err != nil {
			t.Fatalf("a hold 1: %v", err)
		}
		decide(t, db, testIDForHold(wf2, "a")(1), "approved")
		if _, outcome, err := enq.Enqueue(ctx, holdInput(wf2, "a")); err != nil || outcome != OutcomeCreated {
			t.Fatalf("a hold 2: outcome=%q err=%v", outcome, err)
		}
		_, outcome, err := enq.Enqueue(ctx, holdInput(wf2, "a#2"))
		if outcome != OutcomeError || !errors.Is(err, ErrHoldOwnership) {
			t.Errorf("hold 1 of a#2: outcome=%q err=%v, want error/ErrHoldOwnership (not reused of a's row)", outcome, err)
		}
	})
}

// TestConcurrentReHoldsProduceOneNewRow: with no cap the advisory lock is not
// taken, so the unique index on request_id is the whole guarantee. Every racer
// derives hold 2; one inserts, the rest land on its pending row.
func TestConcurrentReHoldsProduceOneNewRow(t *testing.T) {
	db := setup(t)
	db.SetMaxOpenConns(8)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-race", "step-a"
	ids := testIDForHold(wf, step)

	if _, _, err := enq.Enqueue(ctx, holdInput(wf, step)); err != nil {
		t.Fatalf("first hold: %v", err)
	}
	decide(t, db, ids(1), "approved")

	const racers = 6
	var wg sync.WaitGroup
	outcomes := make([]Outcome, racers)
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, outcomes[i], errs[i] = enq.Enqueue(ctx, holdInput(wf, step))
		}(i)
	}
	close(start)
	wg.Wait()

	created := 0
	for i := range outcomes {
		if errs[i] != nil {
			t.Errorf("racer %d: %v", i, errs[i])
		}
		switch outcomes[i] {
		case OutcomeCreated:
			created++
		case OutcomeReused:
		default:
			t.Errorf("racer %d outcome = %q, want created or reused", i, outcomes[i])
		}
	}
	if created != 1 {
		t.Errorf("created = %d, want exactly 1", created)
	}
	if n := stepRows(t, db, wf, step); n != 2 {
		t.Errorf("rows for the step = %d, want 2", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_history WHERE request_id = $1`, ids(2)); n != 1 {
		t.Errorf("history rows of hold 2 = %d, want 1", n)
	}
}

// TestCurrentHoldFollowsTheReHold: CurrentHoldID names hold 1 before the
// re-hold and hold 2 after; CurrentHoldExpiry reads hold 2's expiry, so an
// approval of the live hold is judged by ITS window, not the first hold's.
func TestCurrentHoldFollowsTheReHold(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-current", "step-a"
	ids := testIDForHold(wf, step)

	if _, found, err := CurrentHoldID(ctx, db, testOrg, *holdInput(wf, step).StepHold); err != nil || found {
		t.Fatalf("no row yet: found=%v err=%v, want not found", found, err)
	}
	if _, _, found, err := CurrentHoldExpiry(ctx, db, testOrg, *holdInput(wf, step).StepHold); err != nil || found {
		t.Fatalf("no row yet: expiry found=%v err=%v, want not found", found, err)
	}

	first := holdInput(wf, step)
	first.ExpiresIn = 50 * time.Millisecond
	if _, _, err := enq.Enqueue(ctx, first); err != nil {
		t.Fatalf("first hold: %v", err)
	}
	if id, found, err := CurrentHoldID(ctx, db, testOrg, *holdInput(wf, step).StepHold); err != nil || !found || id != ids(1) {
		t.Errorf("before the re-hold: id=%s found=%v err=%v, want hold 1 %s", id, found, err, ids(1))
	}
	decide(t, db, ids(1), "approved")
	time.Sleep(200 * time.Millisecond)

	second := holdInput(wf, step)
	second.ExpiresIn = time.Hour
	if _, _, err := enq.Enqueue(ctx, second); err != nil {
		t.Fatalf("re-hold: %v", err)
	}
	if id, found, err := CurrentHoldID(ctx, db, testOrg, *holdInput(wf, step).StepHold); err != nil || !found || id != ids(2) {
		t.Errorf("after the re-hold: id=%s found=%v err=%v, want hold 2 %s", id, found, err, ids(2))
	}
	expiresAt, expired, found, err := CurrentHoldExpiry(ctx, db, testOrg, *holdInput(wf, step).StepHold)
	if err != nil || !found || expired || !expiresAt.After(time.Now().Add(30*time.Minute)) {
		t.Errorf("current expiry = %s expired=%v found=%v err=%v, want hold 2's, about an hour ahead", expiresAt, expired, found, err)
	}
	if firstExp, _, _, err := ApprovalExpiry(ctx, db, testOrg, ids(1)); err != nil || firstExp.After(time.Now()) {
		t.Errorf("precondition: hold 1's expiry %s should have passed (err %v)", firstExp, err)
	}

	// Once hold 2 is decided the step has no pending hold. The id an
	// approve/reject projects is the newest, hold 2; but an approval has no
	// live hold to be judged by, so the expiry read refuses rather than
	// returning hold 2's window.
	decide(t, db, ids(2), "approved")
	if id, _, err := CurrentHoldID(ctx, db, testOrg, *holdInput(wf, step).StepHold); err != nil || id != ids(2) {
		t.Errorf("after hold 2 is decided: id=%s err=%v, want hold 2", id, err)
	}
	if _, _, found, err := CurrentHoldExpiry(ctx, db, testOrg, *holdInput(wf, step).StepHold); !errors.Is(err, ErrHoldNotPending) || !found {
		t.Errorf("expiry after hold 2 is decided: found=%v err=%v, want found with ErrHoldNotPending", found, err)
	}
}

// TestAnExpiredNewestHoldReadsAsExpired: with no pending hold and the newest
// expired by the queue, the expiry read reports it expired - the refusal
// #4254 gives a timed-out approval - rather than not pending.
func TestAnExpiredNewestHoldReadsAsExpired(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-expired", "step-a"
	if _, _, err := enq.Enqueue(ctx, holdInput(wf, step)); err != nil {
		t.Fatalf("hold 1: %v", err)
	}
	decide(t, db, testIDForHold(wf, step)(1), "expired")
	if _, expired, found, err := CurrentHoldExpiry(ctx, db, testOrg, *holdInput(wf, step).StepHold); err != nil || !found || !expired {
		t.Errorf("expired=%v found=%v err=%v, want expired, found, no error", expired, found, err)
	}
}

// TestARowThatOnlyNamesTheStepIsNotItsHold is R3 round 1's permissive finding
// at the queue: a pending row whose request_context names the step, under an
// id that is not one of the step's hold ids (a caller-created row before the
// type was reserved; a pre-v10 row), with a far later expiry, is not the
// step's current hold. The current hold, its expiry and the id to project stay
// the real hold's.
func TestARowThatOnlyNamesTheStepIsNotItsHold(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-injected", "step-a"
	hold1 := testIDForHold(wf, step)(1)

	live := holdInput(wf, step)
	live.ExpiresIn = time.Minute
	if _, _, err := enq.Enqueue(ctx, live); err != nil {
		t.Fatalf("hold 1: %v", err)
	}
	injected := input(uuid.New(), step)
	injected.RequestContext = map[string]interface{}{"workflow_id": wf, "step_id": step}
	injected.ExpiresIn = 30 * 24 * time.Hour
	if _, _, err := enq.Enqueue(ctx, injected); err != nil {
		t.Fatalf("injected row: %v", err)
	}

	if id, found, err := CurrentHoldID(ctx, db, testOrg, *holdInput(wf, step).StepHold); err != nil || !found || id != hold1 {
		t.Errorf("current hold = %s found=%v err=%v, want hold 1 %s", id, found, err, hold1)
	}
	expiresAt, _, found, err := CurrentHoldExpiry(ctx, db, testOrg, *holdInput(wf, step).StepHold)
	if err != nil || !found || expiresAt.After(time.Now().Add(2*time.Minute)) {
		t.Errorf("expiry = %s found=%v err=%v, want hold 1's (about a minute), not the injected row's (30 days)", expiresAt, found, err)
	}
	// A retry of the live hold is still a retry.
	if row, outcome, err := enq.Enqueue(ctx, holdInput(wf, step)); err != nil || outcome != OutcomeReused || row.RequestID != hold1 {
		t.Errorf("retry: outcome=%q err=%v, want reused hold 1", outcome, err)
	}
}

// TestSweeperExpiresTheReHoldAtItsOwnExpiry: the queue-side sweeper expires
// the new row when ITS expiry passes and leaves the decided row alone; and the
// pending predicates the listing and the cap use see exactly one row.
func TestSweeperExpiresTheReHoldAtItsOwnExpiry(t *testing.T) {
	db, owner := setupWithOwner(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	const wf, step = "wf-sweep", "step-a"
	ids := testIDForHold(wf, step)

	if _, _, err := enq.Enqueue(ctx, holdInput(wf, step)); err != nil {
		t.Fatalf("first hold: %v", err)
	}
	decide(t, db, ids(1), "approved")
	decided := rowJSON(t, db, ids(1))

	second := holdInput(wf, step)
	second.ExpiresIn = 100 * time.Millisecond
	if _, _, err := enq.Enqueue(ctx, second); err != nil {
		t.Fatalf("re-hold: %v", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue WHERE request_type = $1 AND status = 'pending'`, RequestTypeWCPStepGate); n != 1 {
		t.Errorf("request_type=wcp_step_gate&status=pending rows = %d, want 1", n)
	}
	if n := countRows(t, db, CountPendingSQL, testTenant); n != 1 {
		t.Errorf("CountPendingSQL = %d, want 1", n)
	}

	time.Sleep(300 * time.Millisecond)
	rows, err := ExpireDueReturning(ctx, owner, 50)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	var swept []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var tenant, query string
		var reqCtx []byte
		if err := rows.Scan(&id, &tenant, &query, &reqCtx); err != nil {
			t.Fatalf("scan swept row: %v", err)
		}
		swept = append(swept, id)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close swept rows: %v", err)
	}
	if len(swept) != 1 || swept[0] != ids(2) {
		t.Errorf("swept = %v, want only hold 2 %s", swept, ids(2))
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue WHERE request_id = $1 AND status = 'expired'`, ids(2)); n != 1 {
		t.Errorf("hold 2 not expired")
	}
	if after := rowJSON(t, db, ids(1)); after != decided {
		t.Errorf("the sweep changed the decided row:\nbefore %s\nafter  %s", decided, after)
	}
}

// TestStepHoldInputIsValidated: a step hold with a caller id, a missing field,
// or a request_context that names another step is refused before any write.
func TestStepHoldInputIsValidated(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()

	withID := holdInput("wf-v", "s")
	withID.RequestID = uuid.New()
	noFunc := holdInput("wf-v", "s")
	noFunc.StepHold.IDForHold = nil
	otherCtx := holdInput("wf-v", "s")
	otherCtx.RequestContext = map[string]interface{}{"workflow_id": "wf-v", "step_id": "other"}

	for name, in := range map[string]Input{"caller id": withID, "no id function": noFunc, "context names another step": otherCtx} {
		if _, outcome, err := enq.Enqueue(ctx, in); err == nil || outcome != OutcomeError {
			t.Errorf("%s: outcome=%q err=%v, want a refusal", name, outcome, err)
		}
	}
	if n := countRows(t, db, `SELECT count(*) FROM hitl_approval_queue`); n != 0 {
		t.Errorf("rows written by refused inputs = %d, want 0", n)
	}
}

// TestCrossOrgRequestIDCollision records what happens at the queue when a
// second organization enqueues a request id that another organization's row
// already holds. request_id is UNIQUE across the table while RLS scopes every
// read to one organization. Observed, not fixed here (#4249 row 5700138809,
// "Findings at base"): the assertion is that it is REFUSED and writes nothing.
func TestCrossOrgRequestIDCollision(t *testing.T) {
	db := setup(t)
	enq := newEnq(db, 0)
	ctx := context.Background()
	id := uuid.New()

	if _, _, err := enq.Enqueue(ctx, input(id, "step-org-a")); err != nil {
		t.Fatalf("org A: %v", err)
	}
	other := input(id, "step-org-b")
	other.OrgID = "wshitl-other-org"
	row, outcome, err := enq.Enqueue(ctx, other)
	t.Logf("cross-org collision: outcome=%q err=%v row=%+v", outcome, err, row)
	if err == nil || outcome != OutcomeError || row != nil {
		t.Errorf("cross-org collision: outcome=%q err=%v row=%+v, want a refusal", outcome, err, row)
	}
	var n int
	if err := scopedRead(ctx, db, "wshitl-other-org", func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM hitl_approval_queue`).Scan(&n)
	}); err != nil {
		t.Fatalf("count org B rows: %v", err)
	}
	if n != 0 {
		t.Errorf("org B rows = %d, want 0", n)
	}
}

// TestAStepHoldOfAnotherRequestTypeIsRefused: the unnamed-row check on the
// write takes the input's request_type and the read path takes
// RequestTypeWCPStepGate, so a step hold of any other type is refused before
// any write. No database: validate runs before the transaction opens.
func TestAStepHoldOfAnotherRequestTypeIsRefused(t *testing.T) {
	in := holdInput("wf-t", "s")
	if err := validate(&in); err != nil {
		t.Fatalf("a step hold of request_type %q: %v, want accepted", RequestTypeWCPStepGate, err)
	}
	other := holdInput("wf-t", "s")
	other.RequestType = "mcp_tool_call"
	if err := validate(&other); err == nil {
		t.Errorf("a step hold of request_type %q was accepted, want a refusal", other.RequestType)
	}
}

// A re-hold whose walk ran BEFORE a concurrent re-hold of the same step
// committed hold 2, and whose remaining reads run after it, must reuse that
// hold 2: it is the step's next hold, not a stray (#4249 row 5768527813). The
// interleaving is made on purpose, not waited for: racer A stops right after
// its walk (testHookAfterStepHoldWalk), racer B re-holds and commits, then A
// goes on. Under load this is the race TestConcurrentReHoldsProduceOneNewRow
// met 5 times in 20; on a quiet machine it never met it.
func TestAReHoldWhoseWalkPredatesAConcurrentReHoldReusesIt(t *testing.T) {
	db := setup(t)
	db.SetMaxOpenConns(8)
	enq := newEnq(db, 0) // no cap: the advisory lock that would serialise the two is not taken
	ctx := context.Background()
	const wf, step = "wf-race-seam", "step-a"
	ids := testIDForHold(wf, step)
	if _, _, err := enq.Enqueue(ctx, holdInput(wf, step)); err != nil {
		t.Fatalf("first hold: %v", err)
	}
	decide(t, db, ids(1), "approved")

	walked, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	testHookAfterStepHoldWalk = func(*StepHold) {
		first := false
		once.Do(func() { first = true })
		if first {
			close(walked)
			<-release
		}
	}
	t.Cleanup(func() { testHookAfterStepHoldWalk = nil })

	type result struct {
		row     *Row
		outcome Outcome
		err     error
	}
	aDone := make(chan result, 1)
	go func() {
		row, outcome, err := enq.Enqueue(ctx, holdInput(wf, step))
		aDone <- result{row, outcome, err}
	}()
	select {
	case <-walked:
	case <-time.After(30 * time.Second):
		t.Fatal("racer A never reached the end of its walk")
	}
	// A has walked: hold 1 is decided and there is no hold 2. B now re-holds.
	rowB, outcomeB, errB := enq.Enqueue(ctx, holdInput(wf, step))
	if errB != nil || outcomeB != OutcomeCreated || rowB == nil || rowB.RequestID != ids(2) {
		close(release)
		t.Fatalf("PREMISE: racer B outcome %q err %v; want hold 2 created", outcomeB, errB)
	}
	close(release)
	var a result
	select {
	case a = <-aDone:
	case <-time.After(30 * time.Second):
		t.Fatal("racer A never finished")
	}
	if a.err != nil {
		t.Fatalf("racer A, whose walk predates hold 2, was refused: %v; want hold 2 reused", a.err)
	}
	if a.outcome != OutcomeReused || a.row == nil || a.row.RequestID != ids(2) {
		t.Fatalf("racer A outcome %q; want hold 2 (%s) reused", a.outcome, ids(2))
	}
	if n := stepRows(t, db, wf, step); n != 2 {
		t.Fatalf("rows for the step = %d, want 2", n)
	}
}
