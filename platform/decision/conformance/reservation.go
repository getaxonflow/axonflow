package conformance

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"axonflow/platform/decision/contract"
)

// ReservationState is the lifecycle state of one reservation.
type ReservationState string

const (
	ReservationReserved  ReservationState = "reserved"
	ReservationCommitted ReservationState = "committed"
	ReservationReleased  ReservationState = "released"
	ReservationExpired   ReservationState = "expired"
)

// Reservation is one held quantity against one fully scoped counter key.
type Reservation struct {
	Key            string
	IdempotencyKey string
	Amount         int64
	State          ReservationState
	ExpiresAt      time.Time
	// Fence increments on every state transition. A commit carrying a stale
	// fence is refused, which is what stops a delayed commit from an earlier
	// attempt consuming capacity a later attempt already released.
	Fence int64
}

// Coordinator is an IN-MEMORY, linearizable reservation service used by the
// conformance corpus.
//
// It is a test double for the decision-side property, not the production
// reservation service: durable storage, fencing across processes, cross-region
// linearizability and reconciliation belong to the stateful-enforcement epic.
// What it does implement faithfully is the part the decision layer depends on:
// one conditional transaction across the required counter, idempotent retries
// keyed on the DECISION BINDING rather than on the tool arguments, an explicit
// reserved, committed, released and expired lifecycle, and a hold that spans
// the approval window.
type Coordinator struct {
	mu       sync.Mutex
	byIdem   map[string]*Reservation
	byKey    map[string][]*Reservation
	consumed map[string]int64
}

// NewCoordinator builds an empty coordinator.
func NewCoordinator() *Coordinator {
	return &Coordinator{
		byIdem:   map[string]*Reservation{},
		byKey:    map[string][]*Reservation{},
		consumed: map[string]int64{},
	}
}

// Held returns the total of committed plus outstanding reserved amounts for a
// key. It includes HELD reservations on purpose: two concurrent requests that
// each pass a check against committed spend alone would both be admitted, and
// the cap would be exceeded by the sum of the two.
func (c *Coordinator) Held(key string, now time.Time) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.heldLocked(key, now)
}

func (c *Coordinator) heldLocked(key string, now time.Time) int64 {
	total := c.consumed[key]
	for _, r := range c.byKey[key] {
		if r.State == ReservationReserved && now.Before(r.ExpiresAt) {
			total += r.Amount
		}
	}
	return total
}

// Reserve performs one conditional update.
//
// An identical scoped retry returns the ORIGINAL reservation rather than a
// second hold, which is what stops a client retry of the same request from
// double-consuming a budget.
func (c *Coordinator) Reserve(key, idem string, amount, limit int64, expiresAt time.Time, now time.Time) (*Reservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.byIdem[idem]; ok {
		if existing.Key != key || existing.Amount != amount {
			return nil, fmt.Errorf("reservation: idempotency key %q was used for a different scope or amount", idem)
		}
		return existing, nil
	}
	if c.heldLocked(key, now)+amount > limit {
		return nil, fmt.Errorf("reservation: %s would reach %d against a limit of %d",
			key, c.heldLocked(key, now)+amount, limit)
	}
	r := &Reservation{Key: key, IdempotencyKey: idem, Amount: amount, State: ReservationReserved, ExpiresAt: expiresAt}
	c.byIdem[idem] = r
	c.byKey[key] = append(c.byKey[key], r)
	return r, nil
}

// Commit consumes a held reservation exactly once.
func (c *Coordinator) Commit(idem string, fence int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.byIdem[idem]
	if !ok {
		return fmt.Errorf("reservation: no reservation for idempotency key %q", idem)
	}
	if r.Fence != fence {
		return fmt.Errorf("reservation: commit carries fence %d, reservation is at %d", fence, r.Fence)
	}
	if r.State != ReservationReserved {
		return fmt.Errorf("reservation: cannot commit a reservation in state %q", r.State)
	}
	r.State = ReservationCommitted
	r.Fence++
	c.consumed[r.Key] += r.Amount
	return nil
}

// Release returns a held reservation to the pool.
func (c *Coordinator) Release(idem string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.byIdem[idem]
	if !ok {
		return fmt.Errorf("reservation: no reservation for idempotency key %q", idem)
	}
	if r.State != ReservationReserved {
		return fmt.Errorf("reservation: cannot release a reservation in state %q", r.State)
	}
	r.State = ReservationReleased
	r.Fence++
	return nil
}

// Reap releases every reservation past its expiry. It is the backstop for the
// case where the timeout handler itself failed: without it, an unanswered
// approval permanently consumes budget.
func (c *Coordinator) Reap(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.byIdem {
		if r.State == ReservationReserved && !now.Before(r.ExpiresAt) {
			r.State = ReservationExpired
			r.Fence++
			n++
		}
	}
	return n
}

// ReservationKey builds the fully scoped counter key from the obligation and
// the request.
//
// Hashing tool arguments alone is prohibited as a reservation key, so the key
// carries organization, counter definition, window, unit and the principal
// scope, and the IDEMPOTENCY key is the decision binding digest rather than an
// argument hash.
func ReservationKey(o contract.Obligation, req *contract.Request) string {
	parts := []string{
		req.Organization.String(),
		o.SourcePolicy,
		o.Params["counter"],
		o.Params["window"],
		o.Params["unit"],
		req.Principal.String(),
	}
	return strings.Join(parts, "|")
}

// ReservationAmount reads the reserved quantity from the attribute the
// obligation names, rather than from a value the obligation carries. The amount
// is caller-supplied data, and a budget that reserved a number the POLICY
// carried would not be measuring the request at all.
func ReservationAmount(o contract.Obligation, req *contract.Request) (int64, error) {
	path := o.Params["amount_from"]
	if path == "" {
		return 0, fmt.Errorf("reservation: obligation from %q declares no amount_from attribute", o.SourcePolicy)
	}
	a := req.Attributes.Lookup(path)
	if a.State != contract.StateKnown {
		return 0, fmt.Errorf("reservation: amount attribute %q is %s", path, a.State)
	}
	switch v := a.Value.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("reservation: amount attribute %q is not numeric (%T)", path, a.Value)
	}
}

// OnApprovalTimeout applies the rule that a challenge which was never
// discharged denies.
//
// It releases every hold the decision took and returns a DENY. A non-response
// never proves approval, and permitting after a timeout would additionally
// admit execution against a reservation that has already been released, so
// there is no configuration under which this returns anything else.
func (c *Coordinator) OnApprovalTimeout(dec *contract.Decision, held []string, now time.Time) (*contract.Decision, error) {
	if dec.Approval == nil {
		return nil, fmt.Errorf("reservation: decision %q carries no approval to time out", dec.DecisionID)
	}
	if now.Before(dec.Approval.ExpiresAt) {
		return nil, fmt.Errorf("reservation: the challenge does not expire until %s", dec.Approval.ExpiresAt.Format(time.RFC3339))
	}
	for _, h := range held {
		_ = c.Release(h)
	}
	c.Reap(now)
	out := *dec
	out.Authorization = contract.AuthzDeny
	out.State = contract.StateDeny
	out.Reason = contract.ReasonApprovalExpired
	out.Obligations = nil
	out.Approval = nil
	if dec.Trace != nil {
		t := *dec.Trace
		t.State = out.State
		t.Reason = out.Reason
		t.Category = contract.CategoryFor(out.Reason)
		t.Obligations = nil
		t.ApprovalExpiresAt = nil
		t.Remediation = "the challenge expired without being discharged; a non-response never proves approval"
		out.Trace = &t
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdmitOutcome is the result of running the reservation phase.
type AdmitOutcome struct {
	// Decision is the decision after reservation. A failed reservation
	// converts an otherwise permitted decision to DENY.
	Decision *contract.Decision
	// Held lists the idempotency keys of the reservations taken.
	Held []string
	// Detail explains a conversion to DENY.
	Detail string
}

// AdmitReservations runs the reservation phase for a decision.
//
// Reservation runs AFTER the decision rather than inside condition evaluation.
// Doing it inside would give every evaluated policy side effects, including
// ones a later constraint overrides, forcing compensating releases across the
// whole policy set. The cost of this order is that a reservation failure
// converts a permit into a deny LATE, so the trace has to say "permitted by G2,
// denied at reservation on daily_spend" rather than reporting a policy denial
// that never happened.
func (c *Coordinator) AdmitReservations(dec *contract.Decision, req *contract.Request, now time.Time) (AdmitOutcome, error) {
	if dec.Authorization != contract.AuthzPermit {
		return AdmitOutcome{Decision: dec}, nil
	}
	binding, err := req.BindingDigest()
	if err != nil {
		return AdmitOutcome{}, err
	}
	// The hold spans the approval window plus execution. If the reservation
	// waited for approval instead, two concurrent requests would both pass the
	// check, both would be approved, and the cap would be exceeded.
	expiry := now.Add(5 * time.Minute)
	if dec.Approval != nil {
		expiry = dec.Approval.ExpiresAt.Add(5 * time.Minute)
	}

	var held []string
	obligations := append([]contract.Obligation(nil), dec.Obligations...)
	sort.Slice(obligations, func(i, j int) bool { return obligations[i].SourcePolicy < obligations[j].SourcePolicy })
	for _, o := range obligations {
		if o.Type != contract.ObQuotaReservation {
			continue
		}
		limit, err := strconv.ParseInt(o.Params["limit"], 10, 64)
		if err != nil {
			return AdmitOutcome{}, fmt.Errorf("reservation: obligation from %q has a non-integer limit %q", o.SourcePolicy, o.Params["limit"])
		}
		amount, err := ReservationAmount(o, req)
		if err != nil {
			return AdmitOutcome{}, err
		}
		key := ReservationKey(o, req)
		idem := binding + "|" + key
		if _, err := c.Reserve(key, idem, amount, limit, expiry, now); err != nil {
			for _, h := range held {
				_ = c.Release(h)
			}
			out := *dec
			out.Authorization = contract.AuthzDeny
			out.State = contract.StateDeny
			out.Reason = contract.ReasonBudgetExhausted
			out.Obligations = nil
			out.Approval = nil
			if out.Trace != nil {
				t := *out.Trace
				t.State = out.State
				t.Reason = out.Reason
				t.Category = contract.CategoryFor(out.Reason)
				t.Obligations = nil
				t.Remediation = err.Error()
				t.Warnings = append(append([]string(nil), t.Warnings...),
					fmt.Sprintf("permitted by %v, then denied at reservation on %s", dec.Determining.MatchedPermissions, o.Params["counter"]))
				out.Trace = &t
			}
			if verr := out.Validate(); verr != nil {
				return AdmitOutcome{}, verr
			}
			return AdmitOutcome{Decision: &out, Detail: err.Error()}, nil
		}
		held = append(held, idem)
	}
	return AdmitOutcome{Decision: dec, Held: held}, nil
}
