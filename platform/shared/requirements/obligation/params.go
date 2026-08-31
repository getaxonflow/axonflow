// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"
	"strings"
)

// --- Disclosure family ----------------------------------------------------

// TransformKind names a disclosure transform.
//
// The five COMPARABLE kinds form ADR-065's fixed information-disclosure order
//
//	remove < constant_redact < one_way_derived < partial_reveal < unchanged
//
// where `<` means "reveals no more information than". It is NOT a severity or
// action ranking, and nothing outside this family may use it.
//
// The remaining kinds are INCOMPARABLE by construction: a reversible transform
// (encryption, tokenization) discloses nothing to a reader without the key but
// everything to a reader with it, so it does not sit anywhere on a scale whose
// meaning is "what a reader learns"; and a format-changing transform is not
// comparable with a value-preserving one at all. Two incomparable transforms
// on the same leaf deny unless the registry carries a reviewed subsumption
// rule.
type TransformKind string

const (
	// TransformRemove deletes the leaf entirely.
	TransformRemove TransformKind = "remove"
	// TransformConstantRedact replaces the leaf with a fixed constant.
	TransformConstantRedact TransformKind = "constant_redact"
	// TransformOneWayDerived replaces the leaf with a one-way derivation
	// (hash, HMAC) - it leaks equality, which a constant does not.
	TransformOneWayDerived TransformKind = "one_way_derived"
	// TransformPartialReveal reveals part of the leaf (last4, domain-only).
	TransformPartialReveal TransformKind = "partial_reveal"
	// TransformUnchanged is the identity: the leaf is released as-is. It is
	// the TOP of the order, so any other comparable transform beats it.
	TransformUnchanged TransformKind = "unchanged"

	// TransformReversibleEncrypt is incomparable (see the type comment).
	TransformReversibleEncrypt TransformKind = "reversible_encrypt"
	// TransformTokenize is incomparable.
	TransformTokenize TransformKind = "tokenize"
	// TransformFormatChange is incomparable.
	TransformFormatChange TransformKind = "format_change"
)

// disclosureRank returns the position of kind in the fixed order, or -1 if the
// kind is incomparable.
//
// Deliberately a closed switch and not a map: an unregistered kind must fall
// to -1 (incomparable, therefore deny) rather than to a map's zero value, and
// a map lookup's zero value is 0 - which is `remove`, the LEAST disclosing
// rank. A typo would have silently become the strongest possible claim.
func disclosureRank(k TransformKind) int {
	switch k {
	case TransformRemove:
		return 0
	case TransformConstantRedact:
		return 1
	case TransformOneWayDerived:
		return 2
	case TransformPartialReveal:
		return 3
	case TransformUnchanged:
		return 4
	}
	return -1
}

// Comparable reports whether k sits on the fixed disclosure order.
func (k TransformKind) Comparable() bool { return disclosureRank(k) >= 0 }

// Transform is one disclosure transform with its parameters.
type Transform struct {
	Kind TransformKind
	// Params are transform-specific (the constant for constant_redact, the
	// reveal window for partial_reveal, the algorithm for one_way_derived).
	// Two transforms of the same kind with DIFFERENT params are incomparable:
	// neither subsumes the other and the plan must not silently pick one.
	Params map[string]string
}

// Canonical renders the transform for digests and deduplication.
func (t Transform) Canonical() string {
	if len(t.Params) == 0 {
		return string(t.Kind)
	}
	return string(t.Kind) + "(" + canonicalKV(t.Params) + ")"
}

// Validate checks a transform in isolation.
func (t Transform) Validate() error {
	switch t.Kind {
	case TransformRemove, TransformConstantRedact, TransformOneWayDerived,
		TransformPartialReveal, TransformUnchanged, TransformReversibleEncrypt,
		TransformTokenize, TransformFormatChange:
	default:
		return fmt.Errorf("disclosure transform: unknown kind %q", t.Kind)
	}
	return rejectSeparators(fmt.Sprintf("disclosure transform %s params", t.Kind), t.Params)
}

// DisclosureParams asks for one transform over one set of field-path patterns.
//
// Paths are PATTERNS, not leaves: `user` is a broad path covering every leaf
// beneath it, `user.ssn` is a narrow one. Normalization to leaves happens in
// the algebra, against a LeafResolver, because only the action's field schema
// knows what `user` contains.
type DisclosureParams struct {
	// Paths are the broad and/or narrow field-path patterns this transform
	// applies to.
	Paths []string
	// Transform is applied to every leaf the paths expand to.
	Transform Transform
}

// Family implements Params.
func (p DisclosureParams) Family() Family { return FamilyDisclosure }

// Canonical implements Params.
func (p DisclosureParams) Canonical() string {
	return "paths=" + strings.Join(sortedUnique(p.Paths), ",") + "|transform=" + p.Transform.Canonical()
}

// Validate implements Params.
func (p DisclosureParams) Validate() error {
	if len(p.Paths) == 0 {
		return fmt.Errorf("disclosure params: at least one field path is required")
	}
	for _, path := range p.Paths {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("disclosure params: empty field path")
		}
		if strings.ContainsAny(path, ",|") {
			return fmt.Errorf("disclosure params: field path %q contains a canonical separator (',' or '|')", path)
		}
	}
	return p.Transform.Validate()
}

// --- Approval family ------------------------------------------------------

// ApprovalClause is one immutable threshold clause: `quorum` distinct eligible
// approvers drawn from `eligible`.
//
// This type is the OBLIGATION-side description of an approval requirement. The
// stateful authority that records approvals, re-checks eligibility and decides
// satisfaction is Enterprise and lives in
// platform/shared/requirements/approval; this package only has to compose
// clauses and hand them on, which is why it can be community-visible.
type ApprovalClause struct {
	Quorum int
	// Eligible are canonical principal or group references in the wire form
	// `<SubjectType>::<realm_id>:<subject_id>` (ADR-065; #3556 owns the type).
	// Kept as opaque strings here on purpose: this package must not become a
	// second place that parses identity.
	Eligible []string
}

// canonical renders the clause for deduplication. Two clauses are the same
// clause iff their quorum and their sorted eligible set are equal.
func (c ApprovalClause) canonical() string {
	return fmt.Sprintf("q%d:[%s]", c.Quorum, strings.Join(sortedUnique(c.Eligible), ","))
}

// Validate checks one clause.
func (c ApprovalClause) Validate() error {
	if c.Quorum < 1 {
		return fmt.Errorf("approval clause: quorum must be >= 1, got %d", c.Quorum)
	}
	elig := sortedUnique(c.Eligible)
	if len(elig) == 0 {
		return fmt.Errorf("approval clause: eligible set is empty (quorum %d could never be met)", c.Quorum)
	}
	if c.Quorum > len(elig) {
		// An unsatisfiable clause is a policy authoring defect, and it must be
		// rejected at authoring rather than becoming a permanent CHALLENGE
		// nobody can discharge. Note this counts DISTINCT eligible entries -
		// a clause listing the same group twice does not gain quorum capacity.
		return fmt.Errorf("approval clause: quorum %d exceeds %d distinct eligible entries; the clause can never be satisfied",
			c.Quorum, len(elig))
	}
	for _, e := range elig {
		if strings.ContainsAny(e, ",[]") {
			return fmt.Errorf("approval clause: eligible entry %q contains a canonical separator (',', '[' or ']')", e)
		}
	}
	return nil
}

// ApprovalParams is a conjunction of clauses plus the whole-requirement flags.
//
// THE CLAUSES ARE NEVER FLATTENED. ADR-065 is explicit that the source spec's
// pool-intersection meet is wrong: 2-of-{A,B} MEET 2-of-{B,C} under an
// intersection algebra becomes 2-of-{B}, which is unsatisfiable, while the
// conjunction is satisfied by {A,B,C}. Composition here deduplicates identical
// clauses and concatenates the rest.
type ApprovalParams struct {
	AllOf              []ApprovalClause
	SeparationOfDuties bool
	// ExpirySeconds is the challenge lifetime. There is deliberately NO
	// on-timeout field: ADR-065 requires `on_timeout=permit` to be
	// UNREPRESENTABLE, and the way to make a value unrepresentable is to have
	// no place to put it. Timeout is always deny, enforced in the approval
	// authority.
	ExpirySeconds int
}

// Family implements Params.
func (p ApprovalParams) Family() Family { return FamilyApproval }

// Canonical implements Params.
func (p ApprovalParams) Canonical() string {
	cs := make([]string, 0, len(p.AllOf))
	for _, c := range p.AllOf {
		cs = append(cs, c.canonical())
	}
	sort.Strings(cs)
	return fmt.Sprintf("all_of=[%s]|sod=%t|expiry_s=%d", strings.Join(cs, "&"), p.SeparationOfDuties, p.ExpirySeconds)
}

// Validate implements Params.
func (p ApprovalParams) Validate() error {
	if len(p.AllOf) == 0 {
		return fmt.Errorf("approval params: all_of must contain at least one clause")
	}
	for i, c := range p.AllOf {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("approval params: clause %d: %w", i, err)
		}
	}
	if p.ExpirySeconds <= 0 {
		return fmt.Errorf("approval params: expiry_seconds must be > 0; an approval that never expires cannot be timed out, and timeout is the only safe terminal state")
	}
	return nil
}

// --- Routing family -------------------------------------------------------

// RoutingParams restricts where a call may be sent.
//
// Both fields are PERMITTED sets, and composition intersects them. A nil
// AllowedDestinations means "this obligation places no destination
// constraint"; an EMPTY non-nil slice means "no destination is permitted",
// which is a deny. Those are different facts and Validate keeps them apart.
type RoutingParams struct {
	// AllowedDestinations is the permitted destination set, or nil for
	// unconstrained.
	AllowedDestinations []string
	// RequiredProperties maps a route property (`tls`, `region`, `method`) to
	// the set of values permitted for it. Composition intersects per key, so a
	// key present in two obligations with disjoint value sets denies.
	RequiredProperties map[string][]string
}

// Family implements Params.
func (p RoutingParams) Family() Family { return FamilyRouting }

// Canonical implements Params.
func (p RoutingParams) Canonical() string {
	var b strings.Builder
	if p.AllowedDestinations == nil {
		b.WriteString("dest=*")
	} else {
		b.WriteString("dest=[" + strings.Join(sortedUnique(p.AllowedDestinations), ",") + "]")
	}
	keys := make([]string, 0, len(p.RequiredProperties))
	for k := range p.RequiredProperties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("|" + k + "=[" + strings.Join(sortedUnique(p.RequiredProperties[k]), ",") + "]")
	}
	return b.String()
}

// Validate implements Params.
func (p RoutingParams) Validate() error {
	if p.AllowedDestinations == nil && len(p.RequiredProperties) == 0 {
		return fmt.Errorf("routing params: obligation constrains nothing (nil destinations and no properties)")
	}
	for _, d := range p.AllowedDestinations {
		if strings.TrimSpace(d) == "" {
			return fmt.Errorf("routing params: empty destination")
		}
		if strings.ContainsAny(d, ",[]|") {
			return fmt.Errorf("routing params: destination %q contains a canonical separator", d)
		}
	}
	for k, vs := range p.RequiredProperties {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("routing params: empty property key")
		}
		if strings.ContainsAny(k, ",[]|=") {
			return fmt.Errorf("routing params: property key %q contains a canonical separator", k)
		}
		if vs == nil {
			return fmt.Errorf("routing params: property %q has a nil value set; use an explicit empty slice to mean 'no value permitted', or omit the key to mean unconstrained", k)
		}
		for _, v := range vs {
			if strings.ContainsAny(v, ",[]|") {
				return fmt.Errorf("routing params: property %q value %q contains a canonical separator", k, v)
			}
		}
	}
	return nil
}

// --- Step-up family -------------------------------------------------------

// StepUpParams requires a minimum authentication assurance and constrains the
// methods that may be used to reach it.
type StepUpParams struct {
	// MinAssurance is an ordinal assurance level (higher is stronger). The
	// scale is the deployment's; composition takes the MAXIMUM, which is
	// correct for any monotonic scale.
	MinAssurance int
	// PermittedMethods is the permitted authentication-method set, or nil for
	// unconstrained. Composition intersects; an empty intersection denies.
	PermittedMethods []string
}

// Family implements Params.
func (p StepUpParams) Family() Family { return FamilyStepUp }

// Canonical implements Params.
func (p StepUpParams) Canonical() string {
	m := "*"
	if p.PermittedMethods != nil {
		m = "[" + strings.Join(sortedUnique(p.PermittedMethods), ",") + "]"
	}
	return fmt.Sprintf("min_assurance=%d|methods=%s", p.MinAssurance, m)
}

// Validate implements Params.
func (p StepUpParams) Validate() error {
	if p.MinAssurance < 1 {
		return fmt.Errorf("step-up params: min_assurance must be >= 1, got %d", p.MinAssurance)
	}
	for _, m := range p.PermittedMethods {
		if strings.TrimSpace(m) == "" {
			return fmt.Errorf("step-up params: empty method")
		}
		if strings.ContainsAny(m, ",[]|") {
			return fmt.Errorf("step-up params: method %q contains a canonical separator", m)
		}
	}
	return nil
}

// --- Budget family --------------------------------------------------------

// BudgetDemand is one counter this obligation must reserve against.
type BudgetDemand struct {
	// CounterID names the counter within the budget definition.
	CounterID string
	// Amount is the quantity in Unit. Integer on purpose: a float budget
	// counter cannot be reserved atomically without rounding drift, and a
	// fractional currency amount belongs in minor units.
	Amount int64
	// Unit is the counter's unit (`tokens`, `calls`, `usd_cents`).
	Unit string
}

func (d BudgetDemand) canonical() string {
	return fmt.Sprintf("%s:%d:%s", d.CounterID, d.Amount, d.Unit)
}

// BudgetParams asks for an atomic reservation across every listed counter.
//
// The reservation KEY is deliberately not built here: ADR-065 requires it to
// include organization, actor scope, client/session scope and decision ID, and
// none of those are obligation parameters - they come from the decision. This
// type carries only the WHAT; platform/shared/requirements/reservation builds
// the key from the decision context. That split is what stops a caller
// reconstructing a key out of tool arguments alone, which ADR-065 prohibits.
type BudgetParams struct {
	// BudgetID and BudgetVersion identify the budget definition.
	BudgetID      string
	BudgetVersion int
	// Demands lists every counter that must be reserved, all-or-nothing.
	Demands []BudgetDemand
	// Window names the accounting window (`day`, `month`, `rolling_1h`).
	Window string
}

// Family implements Params.
func (p BudgetParams) Family() Family { return FamilyBudget }

// Canonical implements Params.
func (p BudgetParams) Canonical() string {
	ds := make([]string, 0, len(p.Demands))
	for _, d := range p.Demands {
		ds = append(ds, d.canonical())
	}
	sort.Strings(ds)
	return fmt.Sprintf("budget=%s@v%d|window=%s|demands=[%s]",
		p.BudgetID, p.BudgetVersion, p.Window, strings.Join(ds, ","))
}

// Validate implements Params.
func (p BudgetParams) Validate() error {
	if p.BudgetID == "" {
		return fmt.Errorf("budget params: budget_id is required")
	}
	if p.BudgetVersion <= 0 {
		return fmt.Errorf("budget params: budget_version must be >= 1, got %d", p.BudgetVersion)
	}
	if p.Window == "" {
		return fmt.Errorf("budget params: window is required")
	}
	if len(p.Demands) == 0 {
		return fmt.Errorf("budget params: at least one demand is required")
	}
	seen := map[string]struct{}{}
	for i, d := range p.Demands {
		if d.CounterID == "" {
			return fmt.Errorf("budget params: demand %d: counter_id is required", i)
		}
		if d.Unit == "" {
			return fmt.Errorf("budget params: demand %d: unit is required", i)
		}
		if d.Amount <= 0 {
			return fmt.Errorf("budget params: demand %d: amount must be > 0, got %d", i, d.Amount)
		}
		// Two demands against the SAME counter in one obligation are a defect,
		// not something to sum: the author has said two different things about
		// one counter and the plan must not pick for them.
		if _, dup := seen[d.CounterID]; dup {
			return fmt.Errorf("budget params: counter %q demanded twice in one obligation", d.CounterID)
		}
		seen[d.CounterID] = struct{}{}
		if strings.ContainsAny(d.CounterID+d.Unit, ",:|[]") {
			return fmt.Errorf("budget params: demand %d contains a canonical separator", i)
		}
	}
	return nil
}

// --- Audit / notification family -----------------------------------------

// AuditNotifyTarget is one audit sink or notification destination.
type AuditNotifyTarget struct {
	// Channel names the sink (`audit_log`, `siem`, `email`, `webhook`).
	Channel string
	// Address is the sink-specific destination.
	Address string
	// Delivery is the guarantee this target requires.
	Delivery DeliveryGuarantee
}

// dedupKey identifies a target for set-union deduplication. Delivery is NOT
// part of it on purpose: the same (channel, address) requested twice with
// different guarantees is ONE target that must carry the STRONGER guarantee,
// which is exactly ADR-065's "set union with stable deduplication and the
// strongest required delivery guarantee". Including Delivery in the key would
// produce two targets and deliver twice.
func (t AuditNotifyTarget) dedupKey() string { return t.Channel + "\x00" + t.Address }

func (t AuditNotifyTarget) canonical() string {
	return fmt.Sprintf("%s@%s/%s", t.Channel, t.Address, t.Delivery)
}

// AuditNotifyParams requires records or notifications to be delivered.
type AuditNotifyParams struct {
	Targets []AuditNotifyTarget
}

// Family implements Params.
func (p AuditNotifyParams) Family() Family { return FamilyAuditNotification }

// Canonical implements Params.
func (p AuditNotifyParams) Canonical() string {
	ts := make([]string, 0, len(p.Targets))
	for _, t := range p.Targets {
		ts = append(ts, t.canonical())
	}
	sort.Strings(ts)
	return "targets=[" + strings.Join(ts, ",") + "]"
}

// Validate implements Params.
func (p AuditNotifyParams) Validate() error {
	if len(p.Targets) == 0 {
		return fmt.Errorf("audit/notification params: at least one target is required")
	}
	for i, t := range p.Targets {
		if t.Channel == "" {
			return fmt.Errorf("audit/notification params: target %d: channel is required", i)
		}
		if t.Address == "" {
			return fmt.Errorf("audit/notification params: target %d: address is required", i)
		}
		if t.Delivery.Rank() < 0 {
			return fmt.Errorf("audit/notification params: target %d: unknown delivery guarantee %q", i, t.Delivery)
		}
		if strings.ContainsAny(t.Channel+t.Address, ",@/[]") {
			return fmt.Errorf("audit/notification params: target %d contains a canonical separator", i)
		}
	}
	return nil
}
