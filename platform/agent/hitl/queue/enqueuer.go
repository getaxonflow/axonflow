// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package queue

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/rls"
)

// ErrTierDisabled is returned when the running process's licence tier does not
// enable HITL approvals.
//
// HITL IS ENTERPRISE-ONLY (operator decision, 2026-08-26): the entitled set is
// Professional, Enterprise and Enterprise Plus. EVALUATION IS NOT ENTITLED and
// was until that decision - an Evaluation deployment using WCP step-gate
// approvals loses them.
//
// DELIBERATELY DOES NOT NAME THE CURRENT TIER. An earlier version of the
// sibling sentinel ended "current tier is Community", which is raised on the
// enterprise binary for Community, Free, Pro, Premium AND now Evaluation - so
// asserting "Community" would send an operator on a valid Evaluation licence
// hunting a licence-loading bug that does not exist. tierRefusal() below names
// the tier the process ACTUALLY resolved.
var ErrTierDisabled = errors.New("HITL approvals require a Professional, Enterprise or Enterprise Plus license tier")

// tierRefusal wraps ErrTierDisabled with the tier the process actually
// resolved, so the log line an operator reads names their real tier.
func tierRefusal(t license.Tier) error {
	return fmt.Errorf("%w; this process resolved tier %q", ErrTierDisabled, string(t))
}

// ErrPendingCapReached is returned when the tenant already holds
// MaxPendingApprovals pending rows and this attempt would create one more.
//
// It is a REFUSAL, never a silent drop and never an admission. Admitting the
// governed request because the review queue is full would turn a capacity
// limit into a governance bypass; dropping the entry silently - which is what
// the pre-#3509 FinCrime seam did at fincrime_seam.go:186, and what
// wcp_policy_adapter.go's `log.Printf` + `return uuid.Nil` did on this plane -
// reproduces the identical invisible dead end under a different cause.
var ErrPendingCapReached = errors.New("pending approval limit reached")

// Outcome is the classification every Enqueue attempt reports, on the returned
// error and on the axonflow_hitl_enqueue_total counter.
type Outcome string

const (
	// OutcomeCreated - a new queue row was written.
	OutcomeCreated Outcome = "created"
	// OutcomeReused - an existing PENDING row with the same deterministic
	// request_id was returned by the ON CONFLICT arm. Not charged against the
	// cap. A conflict with a decided row is OutcomeError (ErrResolvedConflict).
	OutcomeReused Outcome = "reused"
	// OutcomeCapReached - refused by MaxPendingApprovals.
	OutcomeCapReached Outcome = "cap_reached"
	// OutcomeTierDisabled - refused by the licence-tier gate.
	OutcomeTierDisabled Outcome = "tier_disabled"
	// OutcomeError - anything else (validation, database).
	OutcomeError Outcome = "error"
)

// CapError carries the numbers behind an ErrPendingCapReached so the caller
// can put them on the wire and in the log instead of an opaque refusal.
type CapError struct {
	TenantID string
	Pending  int
	Limit    int
}

func (e *CapError) Error() string {
	return fmt.Sprintf("%s: tenant %s holds %d pending approvals (limit %d). Upgrade your license for higher limits: https://getaxonflow.com/enterprise",
		ErrPendingCapReached.Error(), e.TenantID, e.Pending, e.Limit)
}

// Unwrap lets callers match with errors.Is(err, ErrPendingCapReached).
func (e *CapError) Unwrap() error { return ErrPendingCapReached }

// Config configures an Enqueuer.
type Config struct {
	// Plane labels the metric and the log lines. One value per governed
	// plane that enqueues; today the only one is "wcp_step_gate".
	Plane string
	// MaxPendingApprovals is the per-tenant cap. Zero or negative means
	// unlimited - the sentinel license.EnterpriseLimits uses (-1).
	//
	// NO SHIPPED TIER REACHES THIS TODAY, and that is a deliberate, guarded
	// state rather than an oversight. Since the 2026-08-26 operator decision
	// the entitled set is Professional | Enterprise | Enterprise Plus, all of
	// which GetTierLimits maps onto EnterpriseLimits with -1 (unlimited);
	// every tier that declares a FINITE cap (Community, Free, Pro, Premium: 5;
	// Evaluation: 25) has HITLApprovalEnabled false, so the tier gate refuses
	// before any cap is read.
	//
	// The machinery is KEPT rather than deleted, for one reason: a future tier
	// that is both entitled and finite is a product decision away, and the
	// exact-cap accounting here (advisory lock, count-after-insert, rollback)
	// is not something to re-derive under time pressure. What keeps it honest
	// is TestNoShippedTierCanReachTheCap, which FAILS the moment such a tier
	// appears - so nobody gets to add one without re-reading the boundary
	// tests that currently exercise the mechanism rather than a reachable
	// configuration.
	MaxPendingApprovals int
	// DefaultExpiry is applied when an Input carries no ExpiresIn.
	DefaultExpiry time.Duration
}

// Enqueuer is the enforcement chokepoint in front of the single writer: the
// licence-tier gate, the MaxPendingApprovals cap, the ON CONFLICT dedup and
// the hitl_approval_history trail, applied in ONE transaction.
//
// It is the WCP plane's replacement for the two direct INSERTs that used to
// live in platform/orchestrator/hitl_wcp_{community,enterprise}.go. See the
// package doc for why hitl.Service could not be that chokepoint.
type Enqueuer struct {
	db            *sql.DB
	plane         string
	maxPending    int
	defaultExpiry time.Duration
	// currentTier resolves the process's tier on EVERY call rather than at
	// construction, so a hot-reloaded licence takes effect on the next gate
	// instead of at the next restart. Same contract as
	// hitl.Service.currentTier.
	currentTier func(context.Context) license.Tier
}

// NewEnqueuer builds an Enqueuer over db.
func NewEnqueuer(db *sql.DB, cfg Config) *Enqueuer {
	if cfg.DefaultExpiry <= 0 {
		cfg.DefaultExpiry = 24 * time.Hour
	}
	if cfg.Plane == "" {
		cfg.Plane = "unknown"
	}
	return &Enqueuer{
		db:            db,
		plane:         cfg.Plane,
		maxPending:    cfg.MaxPendingApprovals,
		defaultExpiry: cfg.DefaultExpiry,
		currentTier:   license.GetCurrentTier,
	}
}

// SetTierProviderForTest overrides the tier source. Test-only; production
// callers must not invoke it. Mirrors hitl.Service.SetTierProviderForTest.
func (e *Enqueuer) SetTierProviderForTest(p func(context.Context) license.Tier) {
	e.currentTier = p
}

// MaxPending reports the configured cap (<= 0 meaning unlimited). Exposed so
// a caller can put the real number in a user-facing refusal without keeping a
// second copy of the limit.
func (e *Enqueuer) MaxPending() int { return e.maxPending }

// Input is one enqueue attempt.
type Input struct {
	// RequestID is the caller-supplied deterministic id that makes the
	// enqueue idempotent (the ADR-065 bridge's decision id). The WCP plane
	// does not set it: it sets StepHold, and Enqueue names the hold with
	// workflow_control.DeriveHITLApprovalIDForHold - the id the
	// approve/reject response projects for that hold.
	//
	// uuid.Nil means "no natural key": a fresh v4 is minted and the ON
	// CONFLICT arm is unreachable - unless StepHold is set, in which case
	// Enqueue picks the id from the step's holds.
	RequestID uuid.UUID

	OrgID               string
	TenantID            string
	ClientID            string
	UserID              string
	OriginalQuery       string
	RequestType         string
	RequestContext      map[string]interface{}
	TriggeredPolicyID   string
	TriggeredPolicyName string
	TriggerReason       string
	Severity            string
	EUAIActArticle      string
	ComplianceFramework string
	RiskClassification  string
	NotifyURL           string
	ExpiresIn           time.Duration

	// StepHold, when set, makes Enqueue choose the request id itself from the
	// step's existing holds (#4249 row 5700138809); RequestID must then be
	// uuid.Nil. Nil keeps the caller-supplied RequestID path unchanged.
	StepHold *StepHold
	// BindingHold, when set, makes Enqueue choose the request id itself from
	// the call's existing holds (#4370, binding_hold.go); RequestID must then
	// be uuid.Nil and StepHold unset.
	BindingHold *BindingHold
}

// StepHold identifies the workflow step a hold belongs to and names its holds.
//
// A step can be held more than once: a step approved earlier and re-evaluated
// back to require_approval is held again. Each hold is its own queue row,
// because a decided row is the record of that decision (the regulator packs
// read the row, not the history) and must not be reopened. So Enqueue reads
// the step's holds BY ID inside its transaction (walkHolds):
//
//   - none: hold 1, IDForHold(1);
//   - a pending hold: that row - a retry of a live hold, `reused`;
//   - a decided newest hold n: hold n+1, a NEW row, `created`.
//
// IDForHold is supplied by the caller because the derivation lives in the
// workflow plane (workflow_control.DeriveHITLApprovalIDForHold), which this
// package does not import. IDForHold(1) must be the id the step's first hold
// has always had.
type StepHold struct {
	WorkflowID string
	StepID     string
	IDForHold  func(n int) uuid.UUID
}

// ErrResolvedConflict refuses an enqueue whose insert met an existing row that
// is no longer pending. Returning that row as `reused` would answer a live
// hold with a decided one - #4249 row 5700138809 exactly - so it is an error
// on every caller, whatever produced the id.
var ErrResolvedConflict = errors.New("hitl enqueue: the request id names an approval that is already decided")

// ErrHoldSequence refuses an enqueue, or a current-hold read, whose step holds
// are not in the shape this package writes: a hold after a pending one, or more
// than maxHoldsPerStep. Guessing from a sequence this package did not write
// could reuse or skip a hold, so it refuses instead.
var ErrHoldSequence = errors.New("hitl enqueue: the step's queue rows do not follow the hold numbering")

// ErrHoldOwnership refuses an enqueue whose insert met a row that belongs to a
// different step. Hold ids are names, not identities: step "a#2" hashes the
// same string as hold 2 of step "a", and step_id is a client-supplied path
// segment.
var ErrHoldOwnership = errors.New("hitl enqueue: the request id names an approval that belongs to another workflow step")

// Enqueue applies the tier gate and the pending cap, writes (or reuses) the
// queue row, and writes the `created` history entry - all inside one
// transaction, under the org scope mig core/025's RLS requires.
//
// ORDER OF OPERATIONS, and why it is this way:
//
//  1. Validate. Cheap, and it keeps malformed input out of the tier metric.
//  2. Tier gate. A Community-tier process must not reach the database at
//     all - #1998's acceptance criterion 3.
//  3. BEGIN + org scope, plus pg_advisory_xact_lock(org,tenant) WHEN A CAP
//     IS CONFIGURED - see step 5; with no cap there is nothing to serialise.
//  4. INSERT ... ON CONFLICT. Speculative: it runs BEFORE the cap is
//     measured.
//  5. If (and only if) the insert actually created a row, count the
//     tenant's pending rows - the new one included - and roll the whole
//     transaction back when it exceeds the cap.
//
// Step 5 is why the cap is EXACT rather than approximately right. The obvious
// alternative - count first, then insert - cannot be exact under concurrency
// without a lock anyway, and it has a second defect the ordering here avoids:
// it charges a RE-GATE of an already-queued step against the cap, so a
// workflow sitting at the limit could no longer re-poll its own pending gate.
// Counting after the insert makes "did this attempt add a row" the question,
// and ON CONFLICT answers it for free.
//
// The advisory lock serialises step 4+5 per (org, tenant), and is taken ONLY
// when maxPending > 0 - the same predicate step 5 runs under, so it is a
// superset of when the count happens and the cap stays exact. Without it two
// concurrent first-time enqueues each see a count that does not include the
// other's uncommitted row, and the cap overshoots by the number of racers -
// which is exactly the weakness hitl.Service's read-then-write cap still has.
// Taking it on the unlimited tiers would serialise every step gate for an
// org+tenant to protect a limit that is disabled.
func (e *Enqueuer) Enqueue(ctx context.Context, in Input) (row *Row, outcome Outcome, err error) {
	defer func() {
		recordEnqueue(e.plane, outcome)
	}()

	if e.db == nil {
		return nil, OutcomeError, fmt.Errorf("hitl enqueue: database connection not available")
	}
	if err := validate(&in); err != nil {
		return nil, OutcomeError, err
	}

	// FAIL CLOSED ON A MISSING TIER SOURCE. This was
	// `if e.currentTier != nil && !IsEvaluationOrHigher(...)`, so a nil
	// provider meant "admit everything" - the fail-OPEN direction, on a gate
	// whose entire purpose is a refusal. NewEnqueuer always sets one, so
	// production was never exposed; but SetTierProviderForTest is exported and
	// a nil provider is a WIRING defect, not a licence, and a wiring defect
	// must not silently disable a governance gate.
	if e.currentTier == nil {
		return nil, OutcomeTierDisabled, fmt.Errorf("%w; no licence tier source is wired (this is a wiring defect, not a licence problem)", ErrTierDisabled)
	}
	if tier := e.currentTier(ctx); !license.IsHITLApprovalEntitled(tier) {
		return nil, OutcomeTierDisabled, tierRefusal(tier)
	}

	expiresIn := in.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = e.defaultExpiry
	}

	params := Params{
		RequestID:           in.RequestID,
		OrgID:               in.OrgID,
		TenantID:            in.TenantID,
		ClientID:            in.ClientID,
		UserID:              in.UserID,
		OriginalQuery:       in.OriginalQuery,
		RequestType:         in.RequestType,
		RequestContext:      in.RequestContext,
		TriggeredPolicyID:   in.TriggeredPolicyID,
		TriggeredPolicyName: in.TriggeredPolicyName,
		TriggerReason:       in.TriggerReason,
		Severity:            in.Severity,
		EUAIActArticle:      in.EUAIActArticle,
		ComplianceFramework: in.ComplianceFramework,
		RiskClassification:  in.RiskClassification,
		Status:              "pending",
		ExpiresAt:           time.Now().Add(expiresIn),
		NotifyURL:           in.NotifyURL,
	}
	if params.RequestID == uuid.Nil {
		params.RequestID = uuid.New()
	}

	var capErr *CapError
	var result *Row

	scopeErr := rls.WithOrgScope(ctx, e.db, in.OrgID, func(tx *sql.Tx) error {
		// ONLY WHEN THERE IS A CAP TO PROTECT. The lock exists to make the
		// count-after-insert exact under concurrency; with MaxPendingApprovals
		// <= 0 (the -1 unlimited sentinel every paid tier carries) the count
		// never runs, so taking it would serialise every step gate for an
		// org+tenant behind one cluster-wide lock, held across the INSERT, the
		// history INSERT and the commit, to protect a limit that is disabled.
		// An Enterprise tenant fanning out parallel step gates would process
		// them one at a time for nothing. pg_advisory_xact_lock has no timeout
		// of its own; the only bound is the caller's context.
		if e.maxPending > 0 {
			if _, lockErr := tx.ExecContext(ctx,
				"SELECT pg_advisory_xact_lock($1)", capLockKey(in.OrgID, in.TenantID)); lockErr != nil {
				return fmt.Errorf("acquire enqueue lock: %w", lockErr)
			}
		}

		// previousStatus is the final status of the step's previous hold when
		// this call opens a new one; empty for a first hold.
		var previousStatus string
		if h := in.StepHold; h != nil {
			id, prev, holdErr := nextHoldID(ctx, tx, in.RequestType, h)
			if holdErr != nil {
				return holdErr
			}
			params.RequestID, previousStatus = id, prev
		}
		if h := in.BindingHold; h != nil {
			id, n, prev, holdErr := nextBindingHoldID(ctx, tx, h)
			if holdErr != nil {
				return holdErr
			}
			params.RequestID, previousStatus = id, prev
			// The hold number rides in the row, so the spend can prove the
			// row's id is derived (ContextBindingHold). A copy: the caller's
			// map is not the platform's to write.
			rc := make(map[string]interface{}, len(in.RequestContext)+1)
			for k, v := range in.RequestContext {
				rc[k] = v
			}
			rc[ContextBindingHold] = n
			params.RequestContext = rc
		}

		r, insErr := insertIdempotent(ctx, tx, params)
		if insErr != nil {
			return insErr
		}

		if !r.Inserted {
			if r.Status != "pending" {
				return fmt.Errorf("%w (request %s is %s)", ErrResolvedConflict, r.RequestID, r.Status)
			}
			if h := in.StepHold; h != nil {
				if ownErr := checkHoldOwner(ctx, tx, r.RequestID, h); ownErr != nil {
					return ownErr
				}
			}
			if h := in.BindingHold; h != nil {
				if ownErr := checkBindingOwner(ctx, tx, r.RequestID, h); ownErr != nil {
					return ownErr
				}
			}
		}

		if r.Inserted && e.maxPending > 0 {
			pending, cntErr := countPending(ctx, tx, in.TenantID)
			if cntErr != nil {
				return cntErr
			}
			// `pending` already includes the row just inserted, so the
			// boundary is `>` and not `>=`: with a limit of 5, writing the
			// FIFTH pending row yields pending == 5 and is admitted; the
			// sixth yields 6 and is refused.
			if pending > e.maxPending {
				capErr = &CapError{TenantID: in.TenantID, Pending: pending - 1, Limit: e.maxPending}
				return capErr
			}
		}

		if r.Inserted {
			history := HistoryParams{
				RequestID: r.RequestID,
				OrgID:     in.OrgID,
				TenantID:  in.TenantID,
				Action:    "created",
				NewStatus: "pending",
			}
			if previousStatus != "" && in.StepHold != nil {
				history.PreviousStatus = previousStatus
				history.Comment = fmt.Sprintf("re-hold of workflow step %s, whose previous hold ended %s", in.StepHold.StepID, previousStatus)
			}
			if previousStatus != "" && in.BindingHold != nil {
				history.PreviousStatus = previousStatus
				history.Comment = fmt.Sprintf("re-hold of the same call, whose previous approval ended %s", previousStatus)
			}
			if hErr := insertHistory(ctx, tx, history); hErr != nil {
				// Unlike hitl.Service, which logs a history failure and
				// keeps the row, this rolls back. The history row is the
				// EU AI Act Article 14 trail for a human-oversight event;
				// a queue entry with no `created` record is an approval
				// whose provenance cannot be reconstructed, and this
				// transaction can still cheaply refuse rather than ship
				// one. The caller is held either way.
				return hErr
			}
		}

		result = r
		return nil
	})

	if scopeErr != nil {
		if capErr != nil {
			return nil, OutcomeCapReached, capErr
		}
		return nil, OutcomeError, fmt.Errorf("hitl enqueue (%s): %w", e.plane, scopeErr)
	}

	// A conflict that met a decided row, another step's row or an off-sequence
	// step never reaches here: each returned an error inside the transaction.
	// So `reused` below is only ever a still-pending row.
	if result.Inserted {
		return result, OutcomeCreated, nil
	}
	return result, OutcomeReused, nil
}

// nextHoldID picks the request id for an enqueue of h, inside the caller's
// org-scoped transaction. previousStatus is the decided status of the hold this
// one follows, and empty unless a new hold follows a decided one.
//
// The step's holds are read by id (walkHolds): a pending hold is reused (a
// retry); otherwise the next hold is written, after refusing a step that has a
// row outside its hold ids (ErrHoldUnnamedRow).
//
// Concurrency: two callers that both see a decided newest hold both derive
// hold n+1; the unique index on request_id admits one insert and puts the other
// on the conflict arm against the winner's PENDING row, which is `reused`. A
// caller that looks after the winner commits sees that pending hold and reuses
// it. No lock is needed for "one live hold per step".
func nextHoldID(ctx context.Context, tx *sql.Tx, requestType string, h *StepHold) (id uuid.UUID, previousStatus string, err error) {
	w, err := walkHolds(ctx, tx, h)
	if err != nil {
		return uuid.Nil, "", err
	}
	if hook := testHookAfterStepHoldWalk; hook != nil {
		hook(h)
	}
	if w.HasPending {
		return w.Pending, "", nil
	}
	next, err := holdID(h, w.Holds+1)
	if err != nil {
		return uuid.Nil, "", err
	}
	// The next hold's own id is NAMED in the unnamed-row check. A concurrent
	// re-hold of the same step that committed between this call's walk and
	// the check wrote exactly that row: it is this step's next hold, not a
	// stray, and the insert below meets it on the ON CONFLICT arm (`reused`).
	// Before, the check ran on the walk's ids alone and refused it as unnamed:
	// a false refusal of a legitimate re-hold under contention
	// (TestAReHoldWhoseWalkPredatesAConcurrentReHoldReusesIt). A row under any
	// other id still refuses.
	if err := refuseUnnamedStepRow(ctx, tx, requestType, h, append(append([]uuid.UUID(nil), w.IDs...), next)); err != nil {
		return uuid.Nil, "", err
	}
	return next, w.LastStatus, nil
}

// testHookAfterStepHoldWalk, when set, runs after a step hold's walk and
// before anything that walk decides: a point at which a concurrent re-hold of
// the same step can commit between this call's reads (others exist, inside the
// walk and between the check and the insert). Tests set it to make that
// interleaving happen on purpose; it is nil in production.
var testHookAfterStepHoldWalk func(h *StepHold)

func holdID(h *StepHold, n int) (uuid.UUID, error) {
	id := h.IDForHold(n)
	if id == uuid.Nil {
		return uuid.Nil, fmt.Errorf("hitl enqueue: no request id for hold %d of %s/%s", n, h.WorkflowID, h.StepID)
	}
	return id, nil
}

// validate rejects input the queue row's own constraints or its readers
// require.
//
// DELIBERATELY NARROWER THAN hitl.Service.CreateApprovalRequest, in exactly
// one respect: the policy-attribution fields (triggered_policy_id,
// triggered_policy_name, trigger_reason) are NOT required here.
//
// hitl.Service requires them because its callers - the agent's HTTP handler
// and the MCP tool - always have a named policy. The WCP step gate does not:
// wcp_policy_adapter.createHITLApproval falls back to policyName "unknown"
// with an empty policyID when a deny carries neither a severity attribution
// nor an applied-policy list. Requiring attribution here would convert that
// case from "a reviewable, if poorly labelled, pending approval" into "held
// with nothing to approve" - a fail-closed refusal that is strictly worse for
// the operator and that no defect report asks for. The narrowing is confined
// to labelling; every field the RLS predicate, the tenancy scope or the status
// CHECK depends on is required below.
func validate(in *Input) error {
	if in.OrgID == "" {
		return fmt.Errorf("hitl enqueue: org_id is required (RLS on hitl_approval_queue)")
	}
	if in.TenantID == "" {
		return fmt.Errorf("hitl enqueue: tenant_id is required")
	}
	if in.ClientID == "" {
		return fmt.Errorf("hitl enqueue: client_id is required")
	}
	if in.OriginalQuery == "" {
		return fmt.Errorf("hitl enqueue: original_query is required")
	}
	if in.RequestType == "" {
		return fmt.Errorf("hitl enqueue: request_type is required")
	}
	if h := in.StepHold; h != nil {
		if h.WorkflowID == "" || h.StepID == "" || h.IDForHold == nil {
			return fmt.Errorf("hitl enqueue: a step hold needs a workflow_id, a step_id and a hold id function")
		}
		if in.RequestID != uuid.Nil {
			return fmt.Errorf("hitl enqueue: a step hold chooses its own request id; RequestID must be unset")
		}
		// The unnamed-row check on this write passes in.RequestType, and the
		// read path (CurrentHoldExpiry) passes RequestTypeWCPStepGate. Holding
		// every step hold to that one type keeps the two predicates, and the
		// type of the rows they look for, the same value.
		if in.RequestType != RequestTypeWCPStepGate {
			return fmt.Errorf("hitl enqueue: a step hold is written as request_type %q, not %q", RequestTypeWCPStepGate, in.RequestType)
		}
		// The unnamed-row check finds rows that name a step by request_context,
		// so a hold written without the same pair would read as a stray of its
		// own step (the walk itself finds holds by id).
		wf, _ := in.RequestContext["workflow_id"].(string)
		step, _ := in.RequestContext["step_id"].(string)
		if wf != h.WorkflowID || step != h.StepID {
			return fmt.Errorf("hitl enqueue: request_context workflow_id/step_id must equal the step hold's")
		}
	}
	if h := in.BindingHold; h != nil {
		if in.StepHold != nil {
			return fmt.Errorf("hitl enqueue: a hold is a step's or a call's, not both")
		}
		if h.BindingDigest == "" {
			return fmt.Errorf("hitl enqueue: a call hold needs its binding digest")
		}
		if in.RequestID != uuid.Nil {
			return fmt.Errorf("hitl enqueue: a call hold chooses its own request id; RequestID must be unset")
		}
		// The consume and the walk both require this type (binding_hold.go);
		// a call hold written under another would be one nobody could spend.
		if in.RequestType != RequestTypePolicyStepUp {
			return fmt.Errorf("hitl enqueue: a call hold is written as request_type %q, not %q", RequestTypePolicyStepUp, in.RequestType)
		}
		// The walk and the consume find the binding in request_context; a row
		// written without it would read as another call's hold under its own id.
		if b, _ := in.RequestContext[ContextBindingDigest].(string); b != h.BindingDigest {
			return fmt.Errorf("hitl enqueue: request_context %s must equal the call hold's binding digest", ContextBindingDigest)
		}
	}
	if in.Severity == "" {
		in.Severity = "high"
	}
	switch in.Severity {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("hitl enqueue: invalid severity: %s", in.Severity)
	}
	return nil
}
