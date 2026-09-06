package contract

import (
	"errors"
	"fmt"
	"sort"
)

// Authorization is the four-valued deterministic authorization outcome.
//
// XACML's Permit, Deny, NotApplicable and Indeterminate inform the diagnostics;
// AxonFlow does not adopt the XACML XML model. The lattice stays four-valued
// internally and only the AuthZEN edge collapses it to a boolean.
type Authorization string

const (
	// AuthzPermit means at least one permission matched, no constraint matched
	// or is unknown, and every potentially applicable mandatory requirement
	// has known applicability.
	AuthzPermit Authorization = "permit"
	// AuthzDeny means an explicit constraint matched.
	AuthzDeny Authorization = "deny"
	// AuthzNotApplicable means no permission matched and nothing was unknown.
	AuthzNotApplicable Authorization = "not_applicable"
	// AuthzIndeterminate means the decision could not be established.
	AuthzIndeterminate Authorization = "indeterminate"
)

// AllAuthorizations returns every outcome in a stable order.
func AllAuthorizations() []Authorization {
	return []Authorization{AuthzPermit, AuthzDeny, AuthzNotApplicable, AuthzIndeterminate}
}

// Validate rejects an undeclared outcome.
func (a Authorization) Validate() error {
	for _, k := range AllAuthorizations() {
		if k == a {
			return nil
		}
	}
	return fmt.Errorf("authorization %q is not a declared outcome", a)
}

// OperationalState is what a Policy Enforcement Point acts on.
type OperationalState string

const (
	// StateAllow means authorized and pre-execution obligations satisfied.
	// Execute once, within proof expiry.
	StateAllow OperationalState = "ALLOW"
	// StateDeny means explicit constraint, unmet requirement, unsupported
	// obligation, expiry, or default deny. Do not execute.
	StateDeny OperationalState = "DENY"
	// StateChallenge means stateful requirements remain. Hold or return a
	// challenge; never execute.
	StateChallenge OperationalState = "CHALLENGE"
	// StateError means input, policy, identity, dependency or evaluation is
	// indeterminate. Do not execute; expose a safe reason.
	StateError OperationalState = "ERROR"
)

// Executable reports whether the PEP may proceed. Exactly one state permits
// execution, which is what makes "did we execute?" a one-line audit question.
func (s OperationalState) Executable() bool { return s == StateAllow }

// AllOperationalStates returns every declared state in a stable order.
//
// It exists so the schema-drift tests can enumerate the range rather than
// restate it. A hand-written list in a test is a second declaration of the
// enumeration, and a second declaration is the drift the test is there to catch.
func AllOperationalStates() []OperationalState {
	return []OperationalState{StateAllow, StateDeny, StateChallenge, StateError}
}

// ReasonCode is a stable, safe machine reason.
//
// There is deliberately no code here for a truncated group or resource closure.
// Under ADR-065 a truncated closure is not an admission failure with a reason
// of its own: it arrives as an ordinary tri-state attribute whose unknown
// reason names the truncation, and the DECISION reason is then whichever policy
// could not be evaluated because of it. That keeps one mechanism where the
// source proposal had two, and it is why an untruncated action is unaffected by
// a truncation that could not have changed its answer.
//
// Codes are safe for the enforcement PEP audience; the requester audience receives a coarser category
// derived from the code, never the code itself where it would disclose policy
// structure. See Trace.
type ReasonCode string

const (
	ReasonPermitted             ReasonCode = "permitted"
	ReasonApprovalRequired      ReasonCode = "approval_required"
	ReasonExplicitConstraint    ReasonCode = "explicit_constraint"
	ReasonNoMatchingPermission  ReasonCode = "no_matching_permission"
	ReasonUnknownConstraint     ReasonCode = "unknown_constraint"
	ReasonUnknownPermission     ReasonCode = "unknown_permission"
	ReasonUnknownRequirement    ReasonCode = "unknown_requirement"
	ReasonInvalidInput          ReasonCode = "invalid_input"
	ReasonEvaluationError       ReasonCode = "evaluation_error"
	ReasonUnsupportedObligation ReasonCode = "unsupported_obligation"
	ReasonObligationConflict    ReasonCode = "obligation_conflict"
	ReasonUnknownAction         ReasonCode = "unknown_action"
	ReasonUnknownRealm          ReasonCode = "unknown_realm"
	ReasonSchemaViolation       ReasonCode = "schema_violation"
	ReasonDelegationDepth       ReasonCode = "delegation_depth_exceeded"
	ReasonBudgetExhausted       ReasonCode = "budget_exhausted"
	ReasonBindingMismatch       ReasonCode = "binding_mismatch"
	ReasonApprovalUnsatisfiable ReasonCode = "approval_unsatisfiable"
	ReasonApprovalExpired       ReasonCode = "approval_expired"
	ReasonAuthoringRejected     ReasonCode = "authoring_rejected"
)

// AllReasonCodes returns every declared reason code in a stable order.
func AllReasonCodes() []ReasonCode {
	return []ReasonCode{
		ReasonPermitted, ReasonApprovalRequired, ReasonExplicitConstraint,
		ReasonNoMatchingPermission, ReasonUnknownConstraint, ReasonUnknownPermission,
		ReasonUnknownRequirement, ReasonInvalidInput, ReasonEvaluationError,
		ReasonUnsupportedObligation, ReasonObligationConflict, ReasonUnknownAction,
		ReasonUnknownRealm, ReasonSchemaViolation, ReasonDelegationDepth,
		ReasonBudgetExhausted,
		ReasonBindingMismatch, ReasonApprovalUnsatisfiable, ReasonApprovalExpired,
		ReasonAuthoringRejected,
	}
}

// Validate rejects an undeclared reason code.
func (r ReasonCode) Validate() error {
	for _, k := range AllReasonCodes() {
		if k == r {
			return nil
		}
	}
	return fmt.Errorf("reason code %q is not declared", r)
}

// UnknownPolicy records one policy that could not be evaluated, and why. These
// are retained in diagnostics even when another policy determined the result,
// so that "denied by C2" and "we also could not evaluate C10" are both visible.
type UnknownPolicy struct {
	PolicyID  string        `json:"policy_id"`
	Authority Authority     `json:"authority"`
	Reason    UnknownReason `json:"reason"`
	// Paths are the attribute paths whose state caused the unknown.
	Paths []string `json:"paths,omitempty"`
}

// Determining records which policies produced the outcome.
type Determining struct {
	MatchedPermissions []string        `json:"matched_permissions"`
	MatchedConstraints []string        `json:"matched_constraints"`
	MatchedRequirement []string        `json:"matched_requirements"`
	MatchedInspections []string        `json:"matched_inspections"`
	Unknown            []UnknownPolicy `json:"unknown,omitempty"`
}

// sortStrings keeps determining sets canonically ordered so two evaluations of
// the same request hash identically regardless of map iteration order.
func sortStrings(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// Canonical returns a copy with every collection sorted and duplicate-free.
func (d Determining) Canonical() Determining {
	out := Determining{
		MatchedPermissions: dedupeSorted(d.MatchedPermissions),
		MatchedConstraints: dedupeSorted(d.MatchedConstraints),
		MatchedRequirement: dedupeSorted(d.MatchedRequirement),
		MatchedInspections: dedupeSorted(d.MatchedInspections),
	}
	if len(d.Unknown) > 0 {
		u := append([]UnknownPolicy(nil), d.Unknown...)
		for i := range u {
			u[i].Paths = dedupeSorted(u[i].Paths)
		}
		sort.Slice(u, func(i, j int) bool {
			if u[i].PolicyID != u[j].PolicyID {
				return u[i].PolicyID < u[j].PolicyID
			}
			return u[i].Reason < u[j].Reason
		})
		out.Unknown = u
	}
	return out
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	s := sortStrings(in)
	out := s[:0]
	var prev string
	for i, v := range s {
		if i > 0 && v == prev {
			continue
		}
		out = append(out, v)
		prev = v
	}
	return out
}

// Decision is the complete result of one evaluation.
type Decision struct {
	DecisionID string `json:"decision_id"`
	RequestID  string `json:"request_id"`
	// Authorization is the deterministic four-valued PDP outcome.
	Authorization Authorization `json:"authorization"`
	// State is the operational decision the PEP acts on.
	State OperationalState `json:"state"`
	// Reason is the determining reason code.
	Reason ReasonCode `json:"reason"`
	// Obligations is the composed, conflict-free obligation set. It is
	// populated only when Authorization is Permit.
	Obligations []Obligation `json:"obligations,omitempty"`
	// Approval is the outstanding approval requirement when State is
	// CHALLENGE.
	Approval *ApprovalRequirement `json:"approval,omitempty"`
	// Determining names the policies behind the outcome.
	Determining Determining `json:"determining"`
	// Snapshot is copied from the request so a decision is self-describing.
	Snapshot Snapshot `json:"snapshot"`
	// Trace is the INTERNAL, complete explain payload. It is deliberately not
	// serialized: a decision does not carry a trace on the wire, because every
	// explain payload is built for exactly one declared and independently
	// authorized audience. Callers reach it through Explain, which projects it.
	//
	// Keeping it out of the encoding also keeps it out of the decision digest,
	// which is correct: a trace describes a decision, it is not part of the
	// decision's identity.
	Trace *Trace `json:"-"`
}

// Validate rejects a decision whose fields disagree with each other. It is the
// structural guarantee behind ADR-065 invariant 12: a plane either implements
// the complete decision profile or refuses the request, and a half-populated
// decision is a refusal, not a permit.
func (d *Decision) Validate() error {
	if d == nil {
		return fmt.Errorf("decision: is nil")
	}
	if d.RequestID == "" {
		return fmt.Errorf("decision: request_id is required")
	}
	if d.DecisionID == "" {
		return fmt.Errorf("decision: decision_id is required")
	}
	if err := d.Authorization.Validate(); err != nil {
		return fmt.Errorf("decision: %w", err)
	}
	if err := d.Reason.Validate(); err != nil {
		return fmt.Errorf("decision: %w", err)
	}
	if err := d.Snapshot.Validate(); err != nil {
		return fmt.Errorf("decision: %w", err)
	}
	want, err := StateFor(d.Authorization, d.Approval != nil)
	if err != nil {
		return fmt.Errorf("decision: %w", err)
	}
	if d.State != want {
		return fmt.Errorf("decision: authorization %q with approval=%t requires state %q, got %q",
			d.Authorization, d.Approval != nil, want, d.State)
	}
	if d.Authorization != AuthzPermit && len(d.Obligations) > 0 {
		return fmt.Errorf("decision: obligations are only carried on a permit, got %d on %q",
			len(d.Obligations), d.Authorization)
	}
	if d.Authorization != AuthzPermit && d.Approval != nil {
		return fmt.Errorf("decision: an approval requirement is only carried on a permit, got one on %q", d.Authorization)
	}
	// A refusal raised on a nested shape is re-rooted in the DECISION rather
	// than wrapped in prose. The pointer is the actionable half of the refusal -
	// "/obligations/2/mandatory" tells a caller which member of which entry to
	// supply, where "/mandatory" alone names an offset within a shape the caller
	// never addressed by itself.
	for i, o := range d.Obligations {
		if err := o.Validate(); err != nil {
			var missing *MissingMemberError
			if errors.As(err, &missing) {
				return missing.Prefixed(fmt.Sprintf("/obligations/%d", i))
			}
			return fmt.Errorf("decision: obligations[%d]: %w", i, err)
		}
	}
	if d.Approval != nil {
		if err := d.Approval.Validate(); err != nil {
			var missing *MissingMemberError
			if errors.As(err, &missing) {
				return missing.Prefixed("/approval")
			}
			return fmt.Errorf("decision: %w", err)
		}
	}
	return nil
}

// Explain returns the trace projected for one audience.
//
// There is no path that returns the internal trace. An operator asking why a
// request was denied and a requester being told it was denied are different
// disclosures, and the only way to obtain either is to name which one you are
// entitled to.
func (d *Decision) Explain(aud Audience) (*Trace, error) {
	if d == nil {
		return nil, fmt.Errorf("decision: is nil")
	}
	if d.Trace == nil {
		return nil, fmt.Errorf("decision %q carries no trace", d.DecisionID)
	}
	return d.Trace.Project(aud)
}

// StateFor maps the deterministic authorization outcome to the operational
// state, in one place.
//
// The two mappings that matter are both explicit reversals of the source
// proposal. NotApplicable maps to DENY: ADR-065 owns default deny as a product
// and security decision, and a read-only label is not sufficient reason to fail
// open, because a read can disclose sensitive data, enumerate authorization
// structure, or feed a later write. Indeterminate maps to ERROR rather than to
// a per-tool on_error posture, because a posture whose value can be Permit
// turns any dependency outage into a widening of access.
func StateFor(a Authorization, approvalOutstanding bool) (OperationalState, error) {
	switch a {
	case AuthzPermit:
		if approvalOutstanding {
			return StateChallenge, nil
		}
		return StateAllow, nil
	case AuthzDeny, AuthzNotApplicable:
		if approvalOutstanding {
			return "", fmt.Errorf("an approval requirement cannot accompany authorization %q", a)
		}
		return StateDeny, nil
	case AuthzIndeterminate:
		if approvalOutstanding {
			return "", fmt.Errorf("an approval requirement cannot accompany authorization %q", a)
		}
		return StateError, nil
	default:
		return "", fmt.Errorf("authorization %q is not a declared outcome", a)
	}
}
