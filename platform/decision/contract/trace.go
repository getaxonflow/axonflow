package contract

import (
	"fmt"
	"sort"
	"time"
)

// Audience is the declared consumer of an explain payload. Every trace request
// declares and is independently authorized for exactly one audience; the
// payload is then built for that audience rather than built once and trimmed,
// so a field cannot leak by a caller forgetting to redact it.
type Audience string

const (
	// AudiencePEP is the enforcing policy enforcement point. It receives what
	// it needs to enforce THIS request and nothing about policy structure.
	AudiencePEP Audience = "pep"
	// AudienceRequester is the human requester or the calling agent. It
	// receives an outcome, a coarse category and remediation text.
	AudienceRequester Audience = "requester"
	// AudienceOperator is an organization operator acting within an
	// administered scope.
	AudienceOperator Audience = "operator"
	// AudienceAuditor is a security auditor under separate least-privilege
	// authorization and retention controls.
	AudienceAuditor Audience = "auditor"
)

// AllAudiences returns every declared audience in a stable order.
func AllAudiences() []Audience {
	return []Audience{AudiencePEP, AudienceRequester, AudienceOperator, AudienceAuditor}
}

// Validate rejects an undeclared audience.
func (a Audience) Validate() error {
	for _, k := range AllAudiences() {
		if k == a {
			return nil
		}
	}
	return fmt.Errorf("trace audience %q is not declared", a)
}

// Category is the coarse outcome class safe to return to a requester or agent.
// It deliberately carries no policy identity, no attribute path and no reason
// code, because those disclose authorization structure to the party the
// structure is protecting against.
type Category string

const (
	CategoryAllowed         Category = "allowed"
	CategoryNotPermitted    Category = "not_permitted"
	CategoryApprovalPending Category = "approval_required"
	CategoryUnavailable     Category = "temporarily_unavailable"
	CategoryInvalidRequest  Category = "invalid_request"
)

// AllCategories returns every declared category in a stable order, so the
// schema-drift tests enumerate the range instead of restating it.
func AllCategories() []Category {
	return []Category{
		CategoryAllowed, CategoryNotPermitted, CategoryApprovalPending,
		CategoryUnavailable, CategoryInvalidRequest,
	}
}

// CategoryFor maps a reason code to the coarse requester-safe category.
//
// The mapping is total by construction: an unmapped code returns
// CategoryUnavailable rather than the code itself, because the failure mode
// worth designing against is a new reason code reaching the requester audience
// verbatim, not a requester seeing a slightly vague category.
func CategoryFor(r ReasonCode) Category {
	switch r {
	case ReasonPermitted:
		return CategoryAllowed
	case ReasonApprovalRequired:
		return CategoryApprovalPending
	case ReasonExplicitConstraint, ReasonNoMatchingPermission, ReasonUnsupportedObligation,
		ReasonObligationConflict, ReasonBudgetExhausted, ReasonDelegationDepth,
		ReasonApprovalUnsatisfiable, ReasonApprovalExpired, ReasonAuthoringRejected:
		return CategoryNotPermitted
	case ReasonInvalidInput, ReasonSchemaViolation, ReasonUnknownAction, ReasonBindingMismatch:
		return CategoryInvalidRequest
	default:
		return CategoryUnavailable
	}
}

// Witness names the path and source class needed to explain a decision without
// returning a secret value, a hidden detector rule, an unredacted policy body,
// a cross-realm membership, or an attribute the viewer cannot read.
type Witness struct {
	// Subject is what the witness explains, for example a group identifier
	// whose membership contributed a constraint.
	Subject string `json:"subject"`
	// Path is the shortest path from the principal or resource to Subject.
	Path []string `json:"path"`
	// SourceClass is the provenance class of the facts on the path.
	SourceClass Provenance `json:"source_class"`
}

// NextBound is the next constraint or requirement that would bind if the
// current binding one were resolved. It turns "why did this fail" into "what
// would it take to make this work", and it is operator or auditor data only.
type NextBound struct {
	PolicyID  string    `json:"policy_id"`
	Authority Authority `json:"authority"`
	Summary   string    `json:"summary"`
}

// Trace is the internal, complete explain payload. It is never returned to a
// caller as-is: Project builds the audience-specific view.
type Trace struct {
	Audience    Audience         `json:"audience"`
	State       OperationalState `json:"state"`
	Category    Category         `json:"category"`
	Reason      ReasonCode       `json:"reason,omitempty"`
	Remediation string           `json:"remediation,omitempty"`
	Obligations []Obligation     `json:"obligations,omitempty"`
	// ApprovalExpiresAt, Determining and Snapshot are POINTERS so that an
	// audience which is not entitled to them sees no key at all. A value type
	// with omitempty still serializes a zero struct, and "determining: {}" on
	// a requester response is a disclosure of shape even when it carries no
	// content.
	ApprovalExpiresAt *time.Time        `json:"approval_expires_at,omitempty"`
	Determining       *Determining      `json:"determining,omitempty"`
	BindingPolicy     string            `json:"binding_policy,omitempty"`
	Witnesses         []Witness         `json:"witnesses,omitempty"`
	NextBound         *NextBound        `json:"next_bound,omitempty"`
	ResolvedAncestors map[string]string `json:"resolved_ancestors,omitempty"`
	Snapshot          *Snapshot         `json:"snapshot,omitempty"`
	Warnings          []string          `json:"warnings,omitempty"`
}

// traceFieldAudience declares, per field of Trace, which audiences may receive
// it. It is data rather than a series of assignments so that a projection
// cannot disagree with a review of the table, and so a reflection test can
// prove every field of Trace appears here. A field added to Trace without a row
// here fails that test rather than defaulting to visible.
var traceFieldAudience = map[string][]Audience{
	"Audience":          {AudiencePEP, AudienceRequester, AudienceOperator, AudienceAuditor},
	"State":             {AudiencePEP, AudienceRequester, AudienceOperator, AudienceAuditor},
	"Category":          {AudiencePEP, AudienceRequester, AudienceOperator, AudienceAuditor},
	"Reason":            {AudiencePEP, AudienceOperator, AudienceAuditor},
	"Remediation":       {AudienceRequester, AudienceOperator, AudienceAuditor},
	"Obligations":       {AudiencePEP, AudienceOperator, AudienceAuditor},
	"ApprovalExpiresAt": {AudiencePEP, AudienceRequester, AudienceOperator, AudienceAuditor},
	"Determining":       {AudienceOperator, AudienceAuditor},
	"BindingPolicy":     {AudienceOperator, AudienceAuditor},
	"Witnesses":         {AudienceOperator, AudienceAuditor},
	"NextBound":         {AudienceOperator, AudienceAuditor},
	"ResolvedAncestors": {AudienceAuditor},
	"Snapshot":          {AudiencePEP, AudienceOperator, AudienceAuditor},
	"Warnings":          {AudienceOperator, AudienceAuditor},
}

// TraceFieldAudiences exposes the table for the reflection test.
func TraceFieldAudiences() map[string][]Audience { return traceFieldAudience }

func fieldVisible(field string, aud Audience) bool {
	for _, a := range traceFieldAudience[field] {
		if a == aud {
			return true
		}
	}
	return false
}

// Project builds the audience-specific view of a trace.
//
// It copies field by field through the permission table. The default for a
// field absent from the table is NOT visible, so the failure mode of forgetting
// a table row is an empty field rather than a disclosure.
func (t *Trace) Project(aud Audience) (*Trace, error) {
	if t == nil {
		return nil, fmt.Errorf("trace: is nil")
	}
	if err := aud.Validate(); err != nil {
		return nil, err
	}
	out := &Trace{Audience: aud}
	if fieldVisible("State", aud) {
		out.State = t.State
	}
	if fieldVisible("Category", aud) {
		out.Category = t.Category
	}
	if fieldVisible("Reason", aud) {
		out.Reason = t.Reason
	}
	if fieldVisible("Remediation", aud) {
		out.Remediation = t.Remediation
	}
	if fieldVisible("Obligations", aud) {
		out.Obligations = append([]Obligation(nil), t.Obligations...)
	}
	if fieldVisible("ApprovalExpiresAt", aud) && t.ApprovalExpiresAt != nil {
		v := *t.ApprovalExpiresAt
		out.ApprovalExpiresAt = &v
	}
	if fieldVisible("Determining", aud) && t.Determining != nil {
		c := t.Determining.Canonical()
		out.Determining = &c
	}
	if fieldVisible("BindingPolicy", aud) {
		out.BindingPolicy = t.BindingPolicy
	}
	if fieldVisible("Witnesses", aud) {
		out.Witnesses = append([]Witness(nil), t.Witnesses...)
	}
	if fieldVisible("NextBound", aud) && t.NextBound != nil {
		nb := *t.NextBound
		out.NextBound = &nb
	}
	if fieldVisible("ResolvedAncestors", aud) && len(t.ResolvedAncestors) > 0 {
		m := make(map[string]string, len(t.ResolvedAncestors))
		for k, v := range t.ResolvedAncestors {
			m[k] = v
		}
		out.ResolvedAncestors = m
	}
	if fieldVisible("Snapshot", aud) && t.Snapshot != nil {
		v := *t.Snapshot
		out.Snapshot = &v
	}
	if fieldVisible("Warnings", aud) {
		out.Warnings = dedupeSorted(t.Warnings)
	}
	return out, nil
}

// SortWitnesses puts witnesses in a canonical order.
func SortWitnesses(w []Witness) {
	sort.Slice(w, func(i, j int) bool {
		if w[i].Subject != w[j].Subject {
			return w[i].Subject < w[j].Subject
		}
		return len(w[i].Path) < len(w[j].Path)
	})
}
