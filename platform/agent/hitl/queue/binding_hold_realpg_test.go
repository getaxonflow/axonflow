// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-PostgreSQL coverage for the call-binding hold and its single-use spend
// (#4370): what the request planes (mcp:request, decide) queue when a
// challenge holds a call, and what a retry naming the approval may spend.
//
// Every cell runs as axonflow_app_role (setup asserts it), under the RLS the
// production pool runs under, so "the app role can spend" is proven by the
// spend itself as well as by the privilege read.
//
// Gating: TEST_PG_INTEGRATION=1 + docker, as enqueuer_realpg_test.go.
package queue

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	callClient    = "acme-mcp-adapter"
	callRequester = "User::axonflow-minted:alice@corp.example"
	callEmail     = "alice@corp.example"
)

var callExcluded = []string{callClient, callRequester, callEmail}

// callInput is a call-binding hold's enqueue for the binding digest d.
func callInput(org, d string, expiresIn time.Duration) Input {
	return Input{
		OrgID:               org,
		TenantID:            testTenant,
		ClientID:            callClient,
		UserID:              callRequester,
		OriginalQuery:       "mcp check_policy: postgres",
		RequestType:         RequestTypePolicyStepUp,
		RequestContext:      map[string]interface{}{ContextBindingDigest: d, "plane": "mcp:request", "step_name": "run_query"},
		TriggeredPolicyID:   "require.approval_tools",
		TriggeredPolicyName: "require.approval_tools",
		TriggerReason:       "an approval is required for run_query on mcp:request",
		Severity:            "high",
		ExpiresIn:           expiresIn,
		BindingHold:         &BindingHold{BindingDigest: d},
	}
}

func newDigest() string { return "sha256:" + strings.ReplaceAll(uuid.NewString(), "-", "") }

// review decides a call hold as a reviewer would through the agent's approve
// route (UpdateStatus, the portal's own statement).
func review(t *testing.T, db *sql.DB, org string, id uuid.UUID, status, reviewerID, reviewerEmail, role string) {
	t.Helper()
	if err := UpdateStatus(context.Background(), db, StatusParams{
		OrgID: org, RequestID: id, Status: status,
		ReviewerID: reviewerID, ReviewerEmail: reviewerEmail, ReviewerRole: role, Comment: "reviewed in the portal",
	}); err != nil {
		t.Fatalf("review %s as %s: %v", id, status, err)
	}
}

func spend(t *testing.T, db *sql.DB, org string, id uuid.UUID, d string) GrantOutcome {
	t.Helper()
	o, _, err := SpendBindingGrant(context.Background(), db, GrantSpend{
		OrgID: org, RequestID: id, BindingDigest: d, Excluded: callExcluded, ActorID: callRequester, Plane: "mcp:request",
	})
	if err != nil {
		t.Fatalf("spend %s: %v", id, err)
	}
	return o
}

func enqueueCall(t *testing.T, e *Enqueuer, org, d string) (*Row, Outcome) {
	t.Helper()
	r, o, err := e.Enqueue(context.Background(), callInput(org, d, time.Hour))
	if err != nil {
		t.Fatalf("enqueue call %s: %v", d, err)
	}
	return r, o
}

func TestTheAppRoleHoldsUpdateOnTheQueue(t *testing.T) {
	db := setup(t)
	var ok bool
	if err := db.QueryRow(`SELECT has_table_privilege(current_user, 'hitl_approval_queue', 'UPDATE')`).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	var who string
	_ = db.QueryRow(`SELECT current_user`).Scan(&who)
	t.Logf("has_table_privilege(%s, hitl_approval_queue, UPDATE) = %v", who, ok)
	if !ok {
		t.Fatal("the app role cannot UPDATE hitl_approval_queue: the consume's FOR UPDATE and its UPDATE would both fail")
	}
}

func TestACallHoldIsReusedWhilePendingAndNamedByItsBinding(t *testing.T) {
	db := setup(t)
	e := newEnq(db, 0)
	d := newDigest()
	first, o1 := enqueueCall(t, e, testOrg, d)
	again, o2 := enqueueCall(t, e, testOrg, d)
	if o1 != OutcomeCreated || o2 != OutcomeReused || first.RequestID != again.RequestID {
		t.Fatalf("outcomes %s/%s ids %s/%s; want created then reused, one row", o1, o2, first.RequestID, again.RequestID)
	}
	if first.RequestID != BindingHoldID(d, 1) {
		t.Fatalf("hold 1 is %s; want BindingHoldID(d, 1) = %s", first.RequestID, BindingHoldID(d, 1))
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM hitl_approval_queue WHERE request_context->>'binding_digest' = $1`, d); n != 1 {
		t.Fatalf("%d rows for one call; want 1", n)
	}
}

func TestAnApprovedUnspentHoldIsNamedAndNotReopened(t *testing.T) {
	db := setup(t)
	e := newEnq(db, 0)
	d := newDigest()
	r, _ := enqueueCall(t, e, testOrg, d)
	review(t, db, testOrg, r.RequestID, "approved", "ops@corp.example", "ops@corp.example", "user")
	_, _, err := e.Enqueue(context.Background(), callInput(testOrg, d, time.Hour))
	var unspent *HoldApprovedUnspentError
	if !errors.As(err, &unspent) || unspent.RequestID != r.RequestID {
		t.Fatalf("enqueue beside an approved unspent hold: %v; want HoldApprovedUnspentError naming %s", err, r.RequestID)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM hitl_approval_queue WHERE request_context->>'binding_digest' = $1`, d); n != 1 {
		t.Fatalf("%d rows; a second approval was opened beside a waiting one", n)
	}
}

func TestASpentOrDecidedHoldIsFollowedByANewHold(t *testing.T) {
	for _, end := range []string{"consumed", "rejected", "expired"} {
		t.Run(end, func(t *testing.T) {
			db := setup(t)
			e := newEnq(db, 0)
			d := newDigest()
			r, _ := enqueueCall(t, e, testOrg, d)
			before := rowJSON(t, db, r.RequestID)
			switch end {
			case "consumed":
				review(t, db, testOrg, r.RequestID, "approved", "ops@corp.example", "ops@corp.example", "user")
				if o := spend(t, db, testOrg, r.RequestID, d); o != GrantSpent {
					t.Fatalf("PREMISE: spend = %s", o)
				}
			case "rejected":
				review(t, db, testOrg, r.RequestID, "rejected", "ops@corp.example", "ops@corp.example", "user")
			case "expired":
				decide(t, db, r.RequestID, "expired")
			}
			decided := rowJSON(t, db, r.RequestID)
			next, o := enqueueCall(t, e, testOrg, d)
			if o != OutcomeCreated || next.RequestID != BindingHoldID(d, 2) {
				t.Fatalf("after a %s hold: outcome %s id %s; want a NEW row, hold 2 (%s)", end, o, next.RequestID, BindingHoldID(d, 2))
			}
			if after := rowJSON(t, db, r.RequestID); after != decided || after == before {
				t.Fatalf("the %s hold's row changed when the call was held again", end)
			}
			var comment string
			if err := scopedRead(context.Background(), db, testOrg, func(tx *sql.Tx) error {
				return tx.QueryRow(`SELECT COALESCE(comment, '') FROM hitl_approval_history WHERE request_id = $1 AND action = 'created'`, next.RequestID).Scan(&comment)
			}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(comment, "ended "+end) {
				t.Fatalf("hold 2's created history says %q; want it to name how hold 1 ended (%s)", comment, end)
			}
		})
	}
}

// SINGLE USE, UNDER CONTENTION: many retries naming one approval, at once.
func TestConcurrentRetriesSpendAnApprovalExactlyOnce(t *testing.T) {
	db := setup(t)
	e := newEnq(db, 0)
	d := newDigest()
	r, _ := enqueueCall(t, e, testOrg, d)
	review(t, db, testOrg, r.RequestID, "approved", "ops@corp.example", "ops@corp.example", "user")

	const retries = 12
	var wg sync.WaitGroup
	start := make(chan struct{})
	outcomes := make(chan GrantOutcome, retries)
	errs := make(chan error, retries)
	for i := 0; i < retries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			o, _, err := SpendBindingGrant(context.Background(), db, GrantSpend{
				OrgID: testOrg, RequestID: r.RequestID, BindingDigest: d, Excluded: callExcluded, ActorID: callRequester, Plane: "mcp:request",
			})
			if err != nil {
				errs <- err
				return
			}
			outcomes <- o
		}()
	}
	close(start)
	wg.Wait()
	close(outcomes)
	close(errs)
	for err := range errs {
		t.Errorf("a concurrent spend errored: %v", err)
	}
	counts := map[GrantOutcome]int{}
	for o := range outcomes {
		counts[o]++
	}
	t.Logf("%d concurrent retries: %v", retries, counts)
	if counts[GrantSpent] != 1 || counts[GrantConsumed] != retries-1 {
		t.Fatalf("outcomes %v; want exactly one spent and %d consumed", counts, retries-1)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM hitl_approval_history WHERE request_id = $1 AND action = 'consumed'`, r.RequestID); n != 1 {
		t.Fatalf("%d consumed history rows; want 1", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM hitl_approval_queue WHERE request_id = $1 AND consumed_at IS NOT NULL AND status = 'approved'`, r.RequestID); n != 1 {
		t.Fatal("the spent approval is not marked consumed (status stays approved)")
	}
}

// Every reason an approval cannot be spent, each from a row in that state.
func TestEveryApprovalTheRetryCannotSpendIsClassified(t *testing.T) {
	db := setup(t)
	e := newEnq(db, 0)
	ctx := context.Background()

	held := func() (uuid.UUID, string) {
		d := newDigest()
		r, _ := enqueueCall(t, e, testOrg, d)
		return r.RequestID, d
	}
	approved := func(reviewerID, email, role string) (uuid.UUID, string) {
		id, d := held()
		review(t, db, testOrg, id, "approved", reviewerID, email, role)
		return id, d
	}

	type cell struct {
		id   uuid.UUID
		d    string
		want GrantOutcome
	}
	cells := map[string]cell{}

	id, d := held()
	cells["pending"] = cell{id, d, GrantPending}
	id, d = held()
	review(t, db, testOrg, id, "rejected", "ops@corp.example", "ops@corp.example", "user")
	cells["rejected"] = cell{id, d, GrantRejected}
	id, d = held()
	decide(t, db, id, "expired")
	cells["expired by the sweep"] = cell{id, d, GrantExpired}
	id, d = approved("ops@corp.example", "ops@corp.example", "user")
	cells["another call's binding"] = cell{id, newDigest(), GrantBindingMismatch}
	id, d = approved("healthcare-portal", "org-1@axonflow.local", "service")
	cells["approved by a credential"] = cell{id, d, GrantReviewerUnattributed}
	id, d = approved(callClient, "", "user")
	cells["approved as the caller's client id"] = cell{id, d, GrantReviewerExcluded}
	id, d = approved("someone-else", "Alice@Corp.Example", "user")
	cells["approved by the caller's email, other case"] = cell{id, d, GrantReviewerExcluded}
	id, d = approved(callRequester, "x@corp.example", "user")
	cells["approved as the caller's principal"] = cell{id, d, GrantReviewerExcluded}
	id, d = approved("ops@corp.example", "ops@corp.example", "user")
	if o := spend(t, db, testOrg, id, d); o != GrantSpent {
		t.Fatalf("PREMISE: first spend = %s", o)
	}
	cells["already spent"] = cell{id, d, GrantConsumed}
	cells["an unknown id"] = cell{uuid.New(), newDigest(), GrantNotFound}

	// Approved, then its own expiry passed before the retry (the database
	// clock decides).
	d = newDigest()
	r, _, err := e.Enqueue(ctx, callInput(testOrg, d, 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	review(t, db, testOrg, r.RequestID, "approved", "ops@corp.example", "ops@corp.example", "user")
	time.Sleep(2500 * time.Millisecond)
	cells["approved, then past its expiry"] = cell{r.RequestID, d, GrantExpired}

	// Another organization's approval, by its exact id and binding: RLS
	// hides it, and it reads exactly as an unknown id.
	const otherOrg = "wshitl-other-org"
	od := newDigest()
	other, _ := enqueueCall(t, e, otherOrg, od)
	review(t, db, otherOrg, other.RequestID, "approved", "ops@other.example", "ops@other.example", "user")
	cells["another organization's approval"] = cell{other.RequestID, od, GrantNotFound}

	// A workflow step's approved row, by its id: not a call hold.
	step := holdInput("wf-4370", "step-x")
	sr, _, err := e.Enqueue(ctx, step)
	if err != nil {
		t.Fatal(err)
	}
	decide(t, db, sr.RequestID, "approved")
	cells["a workflow step's approval"] = cell{sr.RequestID, newDigest(), GrantNotFound}

	for name, c := range cells {
		t.Run(name, func(t *testing.T) {
			if got := spend(t, db, testOrg, c.id, c.d); got != c.want {
				t.Fatalf("spend = %s; want %s", got, c.want)
			}
		})
	}
	// None of the refusals consumed anything but the one premise spend.
	if n := countRows(t, db, `SELECT COUNT(*) FROM hitl_approval_queue WHERE consumed_at IS NOT NULL`); n != 1 {
		t.Fatalf("%d rows consumed; only the premise spend may be", n)
	}
}

// #3509's grant rows (request_type policy_step_up, written before #4254) carry
// no binding: neither the walk nor the spend can ever match one.
func TestLegacyPolicyStepUpRowsNeverMatchABinding(t *testing.T) {
	db := setup(t)
	ctx := context.Background()
	legacy := uuid.New()
	if _, _, _, err := Insert(ctx, db, Params{
		RequestID: legacy, OrgID: testOrg, TenantID: testTenant, ClientID: callClient, UserID: callRequester,
		OriginalQuery: "legacy step-up", RequestType: RequestTypePolicyStepUp,
		RequestContext:    map[string]interface{}{"query_hash": "abc"},
		TriggeredPolicyID: "pol-legacy", TriggeredPolicyName: "legacy", TriggerReason: "legacy step-up",
		Severity: "high", Status: "pending", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	review(t, db, testOrg, legacy, "approved", "ops@corp.example", "ops@corp.example", "user")
	if got := spend(t, db, testOrg, legacy, newDigest()); got != GrantNotFound {
		t.Fatalf("a legacy grant row was classified %s; want not_found", got)
	}
	if got := spend(t, db, testOrg, legacy, ""+"sha256:"); got != GrantNotFound {
		t.Fatalf("an empty-looking binding matched a legacy row: %s", got)
	}
}

// #4375 R3 round 1 (the reviewer's plant, committed): a row a CLIENT can
// write through POST /api/v1/hitl/queue before the type was reserved -
// request_type policy_step_up, a random request id, the real call's binding
// digest copied from its own hold's context and a 7-day expiry - approved by a
// person, is NOT spent for the real call: its id is not a hold id the binding
// derives. Also with a hold number written into its context, which a caller
// could copy just as well. The real hold is untouched by either attempt.
func TestAClientWrittenPolicyStepUpRowIsNeverSpentAsAHold(t *testing.T) {
	db := setup(t)
	e := newEnq(db, 0)
	ctx := context.Background()
	d := newDigest()
	real, _ := enqueueCall(t, e, testOrg, d)
	for name, rc := range map[string]map[string]interface{}{
		"the digest alone":             {ContextBindingDigest: d},
		"the digest and hold 1":        {ContextBindingDigest: d, ContextBindingHold: 1},
		"the digest and hold 1 (text)": {ContextBindingDigest: d, ContextBindingHold: "1"},
	} {
		forged := uuid.New()
		if _, _, _, err := Insert(ctx, db, Params{
			RequestID: forged, OrgID: testOrg, TenantID: testTenant, ClientID: callClient, UserID: "someone-else@corp.example",
			OriginalQuery: "routine read of the public products table", RequestType: RequestTypePolicyStepUp,
			RequestContext:    rc,
			TriggeredPolicyID: "pol-benign", TriggeredPolicyName: "benign", TriggerReason: "routine",
			Severity: "low", Status: "pending", ExpiresAt: time.Now().Add(168 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		review(t, db, testOrg, forged, "approved", "ops@corp.example", "ops@corp.example", "user")
		if got := spend(t, db, testOrg, forged, d); got != GrantNotFound {
			t.Errorf("PERMISSIVE (%s): a client-written policy_step_up row (id %s, not a derived hold id, expiry 168h) was classified %s for the real call; want not_found", name, forged, got)
		}
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM hitl_approval_queue WHERE consumed_at IS NOT NULL`); n != 0 {
		t.Fatalf("%d rows consumed; the forged rows must spend nothing", n)
	}
	// CONTROL: the real hold, approved, is spent, so the refusals above are the
	// derivation check and not a spend that can never succeed.
	review(t, db, testOrg, real.RequestID, "approved", "ops@corp.example", "ops@corp.example", "user")
	if got := spend(t, db, testOrg, real.RequestID, d); got != GrantSpent {
		t.Fatalf("CONTROL: the real hold, approved, spent as %s; want spent", got)
	}
}

func TestACallHoldIsValidated(t *testing.T) {
	db := setup(t)
	e := newEnq(db, 0)
	d := newDigest()
	for name, mutate := range map[string]func(*Input){
		"no digest":                func(in *Input) { in.BindingHold.BindingDigest = "" },
		"a request id":             func(in *Input) { in.RequestID = uuid.New() },
		"another request type":     func(in *Input) { in.RequestType = RequestTypeWCPStepGate },
		"a context without it":     func(in *Input) { delete(in.RequestContext, ContextBindingDigest) },
		"a context naming another": func(in *Input) { in.RequestContext[ContextBindingDigest] = newDigest() },
		"a step hold too": func(in *Input) {
			in.StepHold = &StepHold{WorkflowID: "wf", StepID: "s", IDForHold: testIDForHold("wf", "s")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := callInput(testOrg, d, time.Hour)
			mutate(&in)
			if _, _, err := e.Enqueue(context.Background(), in); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestASpendThatExcludesNobodyIsRefused(t *testing.T) {
	db := setup(t)
	if _, _, err := SpendBindingGrant(context.Background(), db, GrantSpend{OrgID: testOrg, RequestID: uuid.New(), BindingDigest: newDigest()}); err == nil {
		t.Fatal("a spend with no caller identifiers was accepted: it could not refuse a self-approval")
	}
}

// F4: a pending call hold past its expiry that the hourly sweeper has not
// reached is not reused - that would answer the caller a pending approval
// nobody can approve any more. The enqueue expires it (with its history row)
// and holds the call again as the next hold.
func TestALapsedPendingCallHoldIsExpiredAndTheCallHeldAgain(t *testing.T) {
	db := setup(t)
	e := newEnq(db, 0)
	d := newDigest()
	first, _, err := e.Enqueue(context.Background(), callInput(testOrg, d, 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond)
	next, o := enqueueCall(t, e, testOrg, d)
	if o != OutcomeCreated || next.RequestID != BindingHoldID(d, 2) {
		t.Fatalf("after a lapsed pending hold: outcome %s id %s; want a NEW hold 2 (%s)", o, next.RequestID, BindingHoldID(d, 2))
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM hitl_approval_queue WHERE request_id = $1 AND status = 'expired'`, first.RequestID); n != 1 {
		t.Fatal("the lapsed hold was not expired")
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM hitl_approval_history WHERE request_id = $1 AND action = 'expired'`, first.RequestID); n != 1 {
		t.Fatal("the lapsed hold's expiry has no history row")
	}
}
