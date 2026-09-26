// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package queue

// THE CALL-BINDING HOLD (#4370): an approval hold on a request plane that
// cannot keep the request open (mcp:request, decide). The plane answers the
// caller a pending approval and forgets the request; the caller retries with
// the approval id, and the approval admits exactly the call it was asked for,
// once.
//
// A WORKFLOW STEP IS HELD BY ITS (workflow, step). A CALL HAS NO SUCH NAME, so
// its hold is keyed on a digest of everything the approval binds (the plane,
// the route, the organization, the tenant, the client, the requester, the
// exact input and the requirement that asked for it: the agent's
// approvalBinding). Two calls that agree on all of it are the same call, and a
// retry of a pending one reuses its row; anything else is another call and
// another approval.
//
// The holds are numbered by the same walk as a step's (walkHoldIDs): pending
// is reused, a decided or spent newest hold is followed by hold n+1, a NEW
// row, so the same call made again after its approval was spent can be held
// again. One difference, deliberately: an APPROVED hold not yet spent is not
// followed by a new one - that caller's approval is waiting for its retry,
// and opening a second hold beside it would put two live approvals on one
// call (ErrHoldApprovedUnspent names it instead).
//
// SINGLE USE is enforced by the write, not by a read-then-write: the consume
// is one UPDATE guarded on consumed_at IS NULL, under FOR UPDATE SKIP LOCKED
// (ConsumeBindingGrantSQL in transitions.go). core/167 added the column, its
// partial indexes (both predicated on request_type = 'policy_step_up') and the
// history action `consumed` for #3509's grant, which #4254 retired; this is
// the same storage, with the binding in place of the retired query hash.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"axonflow/platform/agent/rls"
)

// RequestTypePolicyStepUp is the request_type of a call-binding hold.
//
// It is #3509's value, reused on purpose: core/167's two partial indexes are
// predicated on it (idx_hitl_unconsumed_grant for the consume,
// idx_hitl_open_policy_step_up for the open-hold read), and it means exactly
// this - a policy step-up approval, spent once. Rows written under it before
// #4254 carry no binding_digest, so neither the walk nor the consume can ever
// match one (TestLegacyPolicyStepUpRowsNeverMatchABinding).
const RequestTypePolicyStepUp = "policy_step_up"

// ContextBindingDigest is the request_context key a call-binding hold stores
// its binding under. The consume compares this ONE key; the readable binding
// fields beside it are for the reviewer, never for the match.
const ContextBindingDigest = "binding_digest"

// ContextBindingHold is the request_context key a call-binding hold stores its
// hold number n under, written only by Enqueue. The spend admits a row only
// when its request id IS BindingHoldID(binding_digest, n): a row somebody else
// wrote under a random id - a caller's own policy_step_up row carrying a
// copied digest (#4375 R3 round 1) - is not a hold, whatever its context says.
const ContextBindingHold = "binding_hold"

// BindingHold identifies the call an approval hold belongs to.
type BindingHold struct {
	// BindingDigest is the digest of everything the approval binds.
	BindingDigest string
}

// bindingHoldNamespace is the UUIDv5 namespace a call-binding hold's ids are
// derived in. A fixed value: a changed namespace would renumber every open
// hold, and a retry would open a second row beside its own pending one.
var bindingHoldNamespace = uuid.MustParse("6d0f1c0e-4370-5b1d-9a8e-7c3f2b1a0d4e")

// BindingHoldID is hold n's request id for a binding: the approval id the
// caller is handed and retries with.
func BindingHoldID(bindingDigest string, n int) uuid.UUID {
	return uuid.NewSHA1(bindingHoldNamespace, []byte(fmt.Sprintf("%s#%d", bindingDigest, n)))
}

// BindingHoldAtIDSQL reads one call-binding hold by id: its status, expiry,
// binding, whether it was spent, and whether it is still live by the
// DATABASE clock (the consume's predicate reads the same clock, so the walk
// and the consume cannot disagree about an approval at its deadline).
const BindingHoldAtIDSQL = `
	SELECT status, expires_at,
	       COALESCE(request_context->>'binding_digest', ''),
	       consumed_at IS NOT NULL,
	       expires_at > CURRENT_TIMESTAMP,
	       request_type
	  FROM hitl_approval_queue
	 WHERE request_id = $1`

// ErrHoldApprovedUnspent refuses an enqueue for a call whose newest hold is
// approved, live and not yet spent: the caller's approval is waiting for its
// retry. HoldApprovedUnspentError carries the id to retry with.
var ErrHoldApprovedUnspent = errors.New("hitl enqueue: the call's approval is granted and waiting for its retry")

// HoldApprovedUnspentError names the approved hold.
type HoldApprovedUnspentError struct {
	RequestID uuid.UUID
	ExpiresAt time.Time
}

func (e *HoldApprovedUnspentError) Error() string {
	return fmt.Sprintf("%s (request %s, expires %s)", ErrHoldApprovedUnspent, e.RequestID, e.ExpiresAt.UTC().Format(time.RFC3339))
}

// Unwrap lets callers match with errors.Is(err, ErrHoldApprovedUnspent).
func (e *HoldApprovedUnspentError) Unwrap() error { return ErrHoldApprovedUnspent }

// walkBindingHolds walks a call's holds (walkHoldIDs) inside the caller's
// org-scoped transaction. A row under one of the call's ids that carries
// another binding, or another request type, is ErrHoldOwnership: hold ids are
// names, and only the binding says whose.
func walkBindingHolds(ctx context.Context, tx *sql.Tx, h *BindingHold) (holdWalk, bool, error) {
	lastLive := false
	w, err := walkHoldIDs("call "+shortDigest(h.BindingDigest),
		func(k int) (uuid.UUID, error) { return BindingHoldID(h.BindingDigest, k), nil },
		func(id uuid.UUID) (holdAt, bool, error) {
			var at holdAt
			var binding, requestType string
			var live bool
			err := tx.QueryRowContext(ctx, BindingHoldAtIDSQL, id).Scan(&at.status, &at.expires, &binding, &at.consumed, &live, &requestType)
			if errors.Is(err, sql.ErrNoRows) {
				return holdAt{}, false, nil
			}
			if err != nil {
				return holdAt{}, false, err
			}
			at.owned = binding == h.BindingDigest && requestType == RequestTypePolicyStepUp
			lastLive = live
			return at, true, nil
		}, "call")
	return w, lastLive, err
}

// nextBindingHoldID picks the request id for an enqueue of a call's hold.
// previousStatus is the final state of the hold this one follows ("consumed"
// for a spent approval), empty for a first hold or a reuse.
//
// Concurrency is the step hold's: two callers that both see a decided newest
// hold both derive hold n+1, the unique index on request_id admits one insert,
// and the other meets the winner's PENDING row on the conflict arm (`reused`).
func nextBindingHoldID(ctx context.Context, tx *sql.Tx, h *BindingHold) (id uuid.UUID, n int, previousStatus string, err error) {
	w, lastLive, err := walkBindingHolds(ctx, tx, h)
	if err != nil {
		return uuid.Nil, 0, "", err
	}
	if w.HasPending {
		// The pending hold is the newest one (the walk refuses a hold after it).
		if lastLive {
			return w.Pending, w.Holds, "", nil
		}
		// A pending hold past its expiry that the sweeper has not reached yet
		// (it runs hourly): reusing it would answer the caller a pending
		// approval that can no longer be approved. It is expired here, in this
		// transaction, and the call is held again as the next hold.
		if err := expireLapsedHold(ctx, tx, w.Pending); err != nil {
			return uuid.Nil, 0, "", err
		}
		return BindingHoldID(h.BindingDigest, w.Holds+1), w.Holds + 1, "expired", nil
	}
	if w.Holds > 0 && w.LastStatus == "approved" && !w.LastConsumed && lastLive {
		return uuid.Nil, 0, "", &HoldApprovedUnspentError{RequestID: w.Last, ExpiresAt: w.LastExpires}
	}
	previousStatus = w.LastStatus
	if w.LastConsumed {
		previousStatus = "consumed"
	}
	return BindingHoldID(h.BindingDigest, w.Holds+1), w.Holds + 1, previousStatus, nil
}

// LapsedHoldSQL locks a call hold that is still pending past its expiry, by
// the database clock, and returns what its expiry history row needs. A row
// that is no longer pending, or not yet due, matches nothing.
const LapsedHoldSQL = `
	SELECT id, org_id, tenant_id
	  FROM hitl_approval_queue
	 WHERE request_id = $1
	   AND status = 'pending'
	   AND expires_at <= CURRENT_TIMESTAMP
	 FOR UPDATE`

// expireLapsedHold expires one lapsed call hold through the queue's own expiry
// transition (ExpireByIDs) with its `expired` history row, in the caller's
// transaction. A hold decided meanwhile matches nothing and is refused as a
// changed sequence, never overwritten.
func expireLapsedHold(ctx context.Context, tx *sql.Tx, requestID uuid.UUID) error {
	var id int64
	var orgID, tenantID string
	err := tx.QueryRowContext(ctx, LapsedHoldSQL, requestID).Scan(&id, &orgID, &tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w (hold %s changed while it was being expired; retry the call)", ErrHoldSequence, requestID)
	}
	if err != nil {
		return fmt.Errorf("lock lapsed hold %s: %w", requestID, err)
	}
	if err := ExpireByIDs(ctx, tx, []int64{id}); err != nil {
		return err
	}
	return insertHistory(ctx, tx, HistoryParams{
		RequestID: requestID, OrgID: orgID, TenantID: tenantID, Action: "expired",
		Comment:        "expired when the same call was held again after its expiry",
		PreviousStatus: "pending", NewStatus: "expired",
	})
}

// checkBindingOwner refuses when the row requestID names carries another
// binding (ErrHoldOwnership). A row the org cannot see refuses too.
func checkBindingOwner(ctx context.Context, tx *sql.Tx, requestID uuid.UUID, h *BindingHold) error {
	var status, binding, requestType string
	var expires time.Time
	var consumed, live bool
	err := tx.QueryRowContext(ctx, BindingHoldAtIDSQL, requestID).Scan(&status, &expires, &binding, &consumed, &live, &requestType)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w (request %s is not visible to this organization)", ErrHoldOwnership, requestID)
	}
	if err != nil {
		return fmt.Errorf("read the owner of request %s: %w", requestID, err)
	}
	if binding != h.BindingDigest || requestType != RequestTypePolicyStepUp {
		return fmt.Errorf("%w (request %s)", ErrHoldOwnership, requestID)
	}
	return nil
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// ---------------------------------------------------------------------------
// Spending an approval
// ---------------------------------------------------------------------------

// GrantOutcome is what one attempt to spend a call's approval came to. Each
// refusal is its own value, because each is its own reason on the wire and
// its own countable fact in the audit trail.
type GrantOutcome string

const (
	// GrantSpent - the approval admitted this call and is now consumed.
	GrantSpent GrantOutcome = "spent"
	// GrantNotFound - no call-binding approval with this id is visible to the
	// organization. Another organization's id reads exactly like an unknown
	// one: the caller learns nothing about approvals it cannot see.
	GrantNotFound GrantOutcome = "not_found"
	// GrantPending - nobody has decided it yet.
	GrantPending GrantOutcome = "pending"
	// GrantRejected - a reviewer rejected it (or an operator overrode it).
	GrantRejected GrantOutcome = "rejected"
	// GrantExpired - it timed out, pending or approved; timeout is a deny.
	GrantExpired GrantOutcome = "expired"
	// GrantConsumed - it already admitted its one call (or a concurrent retry
	// holding the row lock spent it first).
	GrantConsumed GrantOutcome = "consumed"
	// GrantBindingMismatch - it was asked for a different call: other
	// arguments, another tool or route, another requester, or a requirement
	// other than the one this call is held by now.
	GrantBindingMismatch GrantOutcome = "binding_mismatch"
	// GrantReviewerUnattributed - it was approved by a credential, not a
	// person (reviewer_role 'service', or no reviewer recorded).
	GrantReviewerUnattributed GrantOutcome = "reviewer_unattributed"
	// GrantReviewerExcluded - it was approved by the caller itself.
	GrantReviewerExcluded GrantOutcome = "reviewer_excluded"
)

// GrantSpend is one attempt to spend a call's approval.
type GrantSpend struct {
	OrgID     string
	RequestID uuid.UUID
	// BindingDigest is the CURRENT call's binding. An approval is spent only
	// by the call it was asked for.
	BindingDigest string
	// Excluded is every identifier that names the caller: its client id, its
	// requester principal and, for a per-user caller, its validated email. A
	// reviewer matching any of them - by reviewer_id OR reviewer_email,
	// case-insensitively - is the caller approving itself. Both identifier
	// spaces are compared because a person reviewer is recorded by email while
	// the requester is a principal: comparing one rendering of an identity
	// against another rendering of the same identity is always "different".
	Excluded []string
	// ActorID names the caller on the `consumed` history row.
	ActorID string
	// Plane names the plane that spent it, on the history row.
	Plane string
}

// Spent is a spent approval: what the caller's audit row names.
type Spent struct {
	TenantID   string
	ReviewerID string
}

// SpendBindingGrant spends a call's approval, or says why it cannot, in ONE
// org-scoped transaction: the consume (ConsumeBindingGrantSQL), and on a spend
// the `consumed` history row beside it, so an approval is never spent without
// its trail. The caller admits the call only after this returns GrantSpent,
// i.e. after COMMIT; any error is a refusal, never an admission.
//
// When the consume matches nothing, one read of the same id classifies the
// refusal. It runs in the same transaction, so it reads the row the consume
// just declined.
func SpendBindingGrant(ctx context.Context, db *sql.DB, p GrantSpend) (GrantOutcome, *Spent, error) {
	if p.OrgID == "" {
		return "", nil, fmt.Errorf("SpendBindingGrant: OrgID must be non-empty (RLS on hitl_approval_queue)")
	}
	if p.BindingDigest == "" {
		return "", nil, fmt.Errorf("SpendBindingGrant: a binding is required; an approval that floats free of its call could be spent on another")
	}
	if p.RequestID == uuid.Nil {
		return GrantNotFound, nil, nil
	}
	excluded := make([]string, 0, len(p.Excluded))
	for _, e := range p.Excluded {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			excluded = append(excluded, e)
		}
	}
	if len(excluded) == 0 {
		// A spend that excludes nobody cannot refuse self-approval.
		return "", nil, fmt.Errorf("SpendBindingGrant: the caller's identifiers are required to exclude a self-approval")
	}

	var outcome GrantOutcome
	var spent *Spent
	err := rls.WithOrgScope(ctx, db, p.OrgID, func(tx *sql.Tx) error {
		// The named id must be a hold the platform wrote for THIS binding: the
		// id derived from the digest and the row's own hold number. A row under
		// any other id (a caller-written policy_step_up row that copied the
		// digest) is classified, never consumed; the consume then re-checks the
		// same number, so the row it spends is the one derived here.
		var holdText string
		switch err := tx.QueryRowContext(ctx, BindingHoldNumberSQL, p.RequestID, p.OrgID).Scan(&holdText); {
		case errors.Is(err, sql.ErrNoRows):
			outcome = GrantNotFound
			return nil
		case err != nil:
			return fmt.Errorf("read approval %s: %w", p.RequestID, err)
		}
		if n, ok := parseHoldNumber(holdText); !ok || BindingHoldID(p.BindingDigest, n) != p.RequestID {
			o, cErr := classifyUnspent(ctx, tx, p, excluded)
			outcome = o
			return cErr
		}
		var requestID uuid.UUID
		var tenantID, reviewerID string
		err := tx.QueryRowContext(ctx, ConsumeBindingGrantSQL, p.RequestID, p.OrgID, p.BindingDigest, pq.Array(excluded), holdText).
			Scan(&requestID, &tenantID, &reviewerID)
		switch {
		case err == nil:
			if hErr := insertHistory(ctx, tx, HistoryParams{
				RequestID:      requestID,
				OrgID:          p.OrgID,
				TenantID:       tenantID,
				Action:         "consumed",
				ActorID:        p.ActorID,
				Comment:        fmt.Sprintf("spent admitting exactly one call on %s", p.Plane),
				PreviousStatus: "approved",
				NewStatus:      "approved",
			}); hErr != nil {
				// Rolls the consume back with it: an approval spent with no
				// record of the spend is a trail that cannot be reconstructed.
				return hErr
			}
			outcome, spent = GrantSpent, &Spent{TenantID: tenantID, ReviewerID: reviewerID}
			return nil
		case errors.Is(err, sql.ErrNoRows):
			o, cErr := classifyUnspent(ctx, tx, p, excluded)
			outcome = o
			return cErr
		default:
			return fmt.Errorf("consume approval %s: %w", p.RequestID, err)
		}
	})
	if err != nil {
		return "", nil, err
	}
	return outcome, spent, nil
}

// BindingHoldNumberSQL reads the hold number a row was written under (empty
// when it has none: another plane's row, a caller's row, a pre-#4370 grant).
const BindingHoldNumberSQL = `
	SELECT COALESCE(request_context->>'binding_hold', '')
	  FROM hitl_approval_queue
	 WHERE request_id = $1 AND org_id = $2`

// parseHoldNumber reads a stored hold number: a positive decimal integer in
// its one canonical spelling, so the text the consume compares is exactly the
// number derived from.
func parseHoldNumber(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || strconv.Itoa(n) != s {
		return 0, false
	}
	return n, true
}

// isDerivedHold says whether a row's request id is the hold id its own binding
// and hold number derive: only Enqueue writes such a row.
func isDerivedHold(requestID uuid.UUID, binding, hold string) bool {
	n, ok := parseHoldNumber(hold)
	return ok && binding != "" && BindingHoldID(binding, n) == requestID
}

// ClassifyGrantSQL reads why an approval could not be spent.
const ClassifyGrantSQL = `
	SELECT request_id, request_type, status,
	       COALESCE(request_context->>'binding_digest', ''),
	       COALESCE(request_context->>'binding_hold', ''),
	       consumed_at IS NOT NULL,
	       expires_at > CURRENT_TIMESTAMP,
	       COALESCE(reviewer_role, ''),
	       lower(COALESCE(reviewer_id, '')),
	       lower(COALESCE(reviewer_email, '')),
	       reviewed_at IS NOT NULL
	  FROM hitl_approval_queue
	 WHERE request_id = $1 AND org_id = $2`

// classifyUnspent names the refusal for an approval the consume declined. The
// order is the order a reader needs: an id that is not a call-binding approval
// of this organization is not found; one asked for another call is that,
// whatever became of it; then its lifecycle; then who approved it. An approval
// the consume should have spent and did not was locked by a concurrent retry
// that spent it (SKIP LOCKED), so it reads as consumed.
func classifyUnspent(ctx context.Context, tx *sql.Tx, p GrantSpend, excluded []string) (GrantOutcome, error) {
	var requestID uuid.UUID
	var requestType, status, binding, hold, reviewerRole, reviewerID, reviewerEmail string
	var consumed, live, reviewed bool
	err := tx.QueryRowContext(ctx, ClassifyGrantSQL, p.RequestID, p.OrgID).
		Scan(&requestID, &requestType, &status, &binding, &hold, &consumed, &live, &reviewerRole, &reviewerID, &reviewerEmail, &reviewed)
	if errors.Is(err, sql.ErrNoRows) {
		return GrantNotFound, nil
	}
	if err != nil {
		return "", fmt.Errorf("classify approval %s: %w", p.RequestID, err)
	}
	return classifyGrant(grantRow{
		requestID: requestID, hold: hold,
		requestType: requestType, status: status, binding: binding, consumed: consumed, live: live,
		reviewerRole: reviewerRole, reviewerID: reviewerID, reviewerEmail: reviewerEmail, reviewed: reviewed,
	}, p.BindingDigest, excluded), nil
}

// grantRow is the classification read's row.
type grantRow struct {
	requestID                               uuid.UUID
	hold                                    string
	requestType, status, binding            string
	consumed, live, reviewed                bool
	reviewerRole, reviewerID, reviewerEmail string
}

// classifyGrant is the classification as a pure function, so every arm is
// testable without a database. It must agree with ConsumeBindingGrantSQL: the
// only row it may call spendable-but-locked is one every clause of that
// statement admits.
func classifyGrant(r grantRow, bindingDigest string, excluded []string) GrantOutcome {
	switch {
	case r.requestType != RequestTypePolicyStepUp || r.binding == "":
		// Another plane's row (a workflow step's, an agent HITL request) or a
		// pre-#4254 grant row: not an approval this call can name.
		return GrantNotFound
	case !isDerivedHold(r.requestID, r.binding, r.hold):
		// Not a hold the platform wrote: its id is not the one its own binding
		// and hold number derive (a caller-written row that copied a digest).
		return GrantNotFound
	case r.binding != bindingDigest:
		return GrantBindingMismatch
	case r.consumed:
		return GrantConsumed
	case r.status == "pending":
		if !r.live {
			return GrantExpired
		}
		return GrantPending
	case r.status == "rejected", r.status == "overridden":
		return GrantRejected
	case r.status == "expired", !r.live:
		return GrantExpired
	case r.status != "approved":
		return GrantNotFound
	case !r.reviewed || r.reviewerID == "" || r.reviewerRole == "" || r.reviewerRole == "service":
		return GrantReviewerUnattributed
	}
	for _, e := range excluded {
		if r.reviewerID == e || (r.reviewerEmail != "" && r.reviewerEmail == e) {
			return GrantReviewerExcluded
		}
	}
	return GrantConsumed
}
