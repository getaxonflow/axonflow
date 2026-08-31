// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"
	"strings"
)

// LeafResolver expands a field-path PATTERN to the atomic leaves it covers.
//
// This is the "normalize to canonical atomic targets" step, and it is an
// interface because only the action's field schema knows what `user` contains.
// The second return value is the tri-state that matters: `known=false` means
// the resolver could not establish the leaf set (unknown action schema, stale
// registry, malformed pattern). It is NOT the same as an empty leaf set, which
// is the positive finding "this pattern covers nothing".
//
// A mandatory disclosure obligation whose paths cannot be resolved has UNKNOWN
// applicability and therefore denies. That is the same correction as the
// obligations-INDET fail-open, applied one level down: the source spec would
// have expanded to nothing and dropped the transform.
type LeafResolver interface {
	Leaves(pattern string) (leaves []string, known bool)
}

// LeafResolverFunc adapts a function to LeafResolver.
type LeafResolverFunc func(pattern string) ([]string, bool)

// Leaves implements LeafResolver.
func (f LeafResolverFunc) Leaves(pattern string) ([]string, bool) { return f(pattern) }

// StaticLeafResolver resolves patterns against a fixed leaf universe: a
// pattern matches a leaf if the leaf equals the pattern or is a dotted
// descendant of it. A pattern that matches nothing at all is reported as
// UNKNOWN rather than empty, because in a fixed universe "no leaf named that"
// means the pattern refers to something this schema does not describe - which
// is a resolution failure, not the positive finding that the field exists and
// is empty.
type StaticLeafResolver struct {
	Universe []string
}

// Leaves implements LeafResolver.
func (r StaticLeafResolver) Leaves(pattern string) ([]string, bool) {
	var out []string
	for _, leaf := range r.Universe {
		if leaf == pattern || strings.HasPrefix(leaf, pattern+".") {
			out = append(out, leaf)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	sort.Strings(out)
	return out, true
}

// ComposedPlan is the result of composing one family's obligations.
type ComposedPlan struct {
	// Disclosure maps each atomic leaf to the single transform that will be
	// applied to it.
	Disclosure map[string]Transform
	// ApprovalClauses is the conjunction, deduplicated, never flattened.
	ApprovalClauses       []ApprovalClause
	SeparationOfDuties    bool
	ApprovalExpirySeconds int
	// RoutingDestinations is the intersected destination set; nil means
	// unconstrained (no routing obligation applied).
	RoutingDestinations []string
	RoutingProperties   map[string][]string
	// StepUpAssurance is the maximum required assurance; 0 means none.
	StepUpAssurance int
	// StepUpMethods is the intersected method set; nil means unconstrained.
	StepUpMethods []string
	// BudgetDemands is the union of demands, keyed by (budget, version,
	// window, counter). Every one must be reserved atomically.
	BudgetDemands []KeyedBudgetDemand
	// AuditTargets is the deduplicated union carrying the strongest guarantee.
	AuditTargets []AuditNotifyTarget
	// Order is the topologically sorted discharge order of the obligation
	// types present in the plan.
	Order []Type
}

// KeyedBudgetDemand is one demand with its budget identity attached, so the
// budget algebra's union has something to deduplicate on.
type KeyedBudgetDemand struct {
	BudgetID      string
	BudgetVersion int
	Window        string
	CounterID     string
	Amount        int64
	Unit          string
}

func (d KeyedBudgetDemand) dedupKey() string {
	return fmt.Sprintf("%s@v%d/%s/%s/%s", d.BudgetID, d.BudgetVersion, d.Window, d.CounterID, d.Unit)
}

// ConflictError is the deny an incomparable or empty composition produces.
//
// It is a distinct type rather than a bare error because the planner has to
// distinguish "these obligations conflict" (a DENY with an operator-actionable
// reason) from "this obligation is malformed" (an ERROR). Collapsing the two
// would report a policy authoring conflict as an outage.
type ConflictError struct {
	Family Family
	// Subject names the leaf, property key or budget counter in conflict.
	Subject string
	Detail  string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("obligation conflict in family %s on %q: %s", e.Family, e.Subject, e.Detail)
}

// algebra is the composition function for one family. UNEXPORTED, and stored
// in an unexported map keyed by Family: there is no way for a schema, a policy
// or a caller outside this package to add, replace or select one.
type algebra func(c *composer, obs []Obligation) error

// familyAlgebras is the closed dispatch table. Exactly one entry per Family.
var familyAlgebras = map[Family]algebra{
	FamilyDisclosure:        composeDisclosure,
	FamilyApproval:          composeApproval,
	FamilyRouting:           composeRouting,
	FamilyStepUp:            composeStepUp,
	FamilyBudget:            composeBudget,
	FamilyAuditNotification: composeAuditNotification,
	// Phase ordering's domain is the whole plan rather than one family's
	// members, so its entry is a no-op here and the real work runs once over
	// the complete plan in composePhaseOrder. The entry exists so that
	// "every family has exactly one algebra" has no exception.
	FamilyPhaseOrdering: func(*composer, []Obligation) error { return nil },
}

type composer struct {
	reg  *Registry
	leaf LeafResolver
	plan ComposedPlan
	// leafTransforms accumulates, per leaf, every transform claimed for it,
	// before the least-disclosing one is chosen. Kept as a list rather than
	// folded pairwise so that a three-way incomparable set is reported with
	// all three members instead of whichever two met first.
	leafTransforms map[string][]Transform
}

// Compose applies every family algebra to obs and returns the composed plan.
//
// obs must already have been filtered to the APPLICABLE obligations; deciding
// what to do with unknown applicability is the planner's job, not the
// algebra's, and mixing the two is how the source spec lost a mandatory
// redaction inside a composition step.
func Compose(reg *Registry, leaf LeafResolver, obs []Obligation) (ComposedPlan, error) {
	c := &composer{
		reg:            reg,
		leaf:           leaf,
		leafTransforms: map[string][]Transform{},
		plan: ComposedPlan{
			Disclosure:        map[string]Transform{},
			RoutingProperties: map[string][]string{},
		},
	}

	byFamily := map[Family][]Obligation{}
	for _, o := range obs {
		s, ok := reg.Lookup(o.Type, o.Version)
		if !ok {
			return ComposedPlan{}, fmt.Errorf("compose: no schema for %s", o.Capability())
		}
		byFamily[s.Family] = append(byFamily[s.Family], o)
	}

	// Iterate AllFamilies rather than the map, so composition order is stable
	// and a trace diffed between two runs is comparable.
	for _, f := range AllFamilies {
		alg, ok := familyAlgebras[f]
		if !ok {
			// Unreachable while AllFamilies and familyAlgebras agree, which
			// TestEveryFamilyHasExactlyOneAlgebra pins. Denying rather than
			// skipping is the safe direction if they ever diverge.
			return ComposedPlan{}, fmt.Errorf("compose: family %q has no algebra", f)
		}
		if err := alg(c, byFamily[f]); err != nil {
			return ComposedPlan{}, err
		}
	}

	if err := c.resolveLeaves(); err != nil {
		return ComposedPlan{}, err
	}
	order, err := composePhaseOrder(reg, obs)
	if err != nil {
		return ComposedPlan{}, err
	}
	c.plan.Order = order
	return c.plan, nil
}

// --- Disclosure -----------------------------------------------------------

// composeDisclosure expands every path to leaves and records each claimed
// transform per leaf. The per-leaf choice happens in resolveLeaves, AFTER
// every disclosure obligation has contributed, which is what makes
// broad-then-narrow and narrow-then-broad produce the same answer.
func composeDisclosure(c *composer, obs []Obligation) error {
	for _, o := range obs {
		p, ok := o.Params.(DisclosureParams)
		if !ok {
			return fmt.Errorf("compose disclosure: %s carries %T", o.Type, o.Params)
		}
		if c.leaf == nil {
			return &ConflictError{
				Family:  FamilyDisclosure,
				Subject: o.SourcePolicyID,
				Detail:  "no leaf resolver is wired, so field paths cannot be normalized to atomic leaves",
			}
		}
		for _, pattern := range p.Paths {
			leaves, known := c.leaf.Leaves(pattern)
			if !known {
				// Fail closed. See the LeafResolver doc: an unresolvable path
				// is not an empty path.
				return &ConflictError{
					Family:  FamilyDisclosure,
					Subject: pattern,
					Detail:  "field path could not be normalized to atomic leaves; a disclosure transform whose target is unknown cannot be discharged",
				}
			}
			for _, leaf := range leaves {
				c.leafTransforms[leaf] = append(c.leafTransforms[leaf], p.Transform)
			}
		}
	}
	return nil
}

// resolveLeaves picks the least-disclosing comparable transform per leaf.
func (c *composer) resolveLeaves() error {
	for leaf, ts := range c.leafTransforms {
		chosen, err := c.leastDisclosing(leaf, ts)
		if err != nil {
			return err
		}
		c.plan.Disclosure[leaf] = chosen
	}
	return nil
}

// leastDisclosing implements the disclosure order on ONE leaf.
//
// The rules, in the order they are applied:
//
//  1. Identical transforms (same kind, same params) deduplicate.
//  2. Different COMPARABLE kinds: the lower rank wins outright. A strictly
//     less-disclosing kind subsumes a more-disclosing one whatever the more-
//     disclosing one's parameters say, because the winner reveals no more than
//     the loser under any parameterisation. `remove` beats `partial_reveal(x)`
//     for every x.
//  3. The SAME comparable kind with DIFFERENT parameters is INCOMPARABLE.
//     partial_reveal(last4) and partial_reveal(first6) each reveal something
//     the other hides; neither subsumes the other, and picking either would
//     silently discard a requirement policy's instruction. ADR-065:
//     "transforms with incompatible parameters are incomparable".
//  4. Any incomparable KIND (reversible encryption, tokenization, format
//     change) is incomparable with everything unless a reviewed registry
//     subsumption rule resolves the exact pair.
//  5. Anything still unresolved DENIES.
func (c *composer) leastDisclosing(leaf string, ts []Transform) (Transform, error) {
	// 1. Deduplicate by canonical rendering.
	uniq := make([]Transform, 0, len(ts))
	seen := map[string]struct{}{}
	for _, t := range ts {
		k := t.Canonical()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		uniq = append(uniq, t)
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i].Canonical() < uniq[j].Canonical() })
	if len(uniq) == 1 {
		return uniq[0], nil
	}

	// 4 (applied first, because a reviewed rule can rescue a pair that rules
	// 2-3 would deny). Repeatedly drop any transform that a reviewed rule says
	// is subsumed by another present transform.
	uniq = c.applySubsumption(uniq)
	if len(uniq) == 1 {
		return uniq[0], nil
	}

	// 2/3. Every remaining transform must be comparable, and the comparable
	// ones must not collide on kind with different params.
	byKind := map[TransformKind][]Transform{}
	for _, t := range uniq {
		if !t.Kind.Comparable() {
			return Transform{}, &ConflictError{
				Family:  FamilyDisclosure,
				Subject: leaf,
				Detail: fmt.Sprintf("transform %s is incomparable with %s and no reviewed subsumption rule resolves the pair",
					t.Canonical(), renderTransforms(uniq)),
			}
		}
		byKind[t.Kind] = append(byKind[t.Kind], t)
	}

	best := uniq[0]
	bestRank := disclosureRank(best.Kind)
	for _, t := range uniq[1:] {
		if r := disclosureRank(t.Kind); r < bestRank {
			best, bestRank = t, r
		}
	}
	// 3. The WINNING kind must be unambiguous. Two partial_reveals with
	// different windows conflict only if partial_reveal is what wins; if
	// `remove` is also present it beats both and the ambiguity is moot,
	// because removing the leaf discharges every one of them.
	if len(byKind[best.Kind]) > 1 {
		return Transform{}, &ConflictError{
			Family:  FamilyDisclosure,
			Subject: leaf,
			Detail: fmt.Sprintf("%d transforms of kind %s with incompatible parameters (%s); neither reveals less than the other",
				len(byKind[best.Kind]), best.Kind, renderTransforms(byKind[best.Kind])),
		}
	}
	return best, nil
}

// applySubsumption drops every transform that a reviewed registry rule says is
// subsumed by another transform present on the same leaf.
func (c *composer) applySubsumption(ts []Transform) []Transform {
	if c.reg == nil || len(c.reg.subsumption) == 0 {
		return ts
	}
	keep := make([]Transform, 0, len(ts))
	for i, t := range ts {
		dropped := false
		for j, other := range ts {
			if i == j {
				continue
			}
			if c.reg.subsumes(t.Canonical(), other.Canonical()) {
				dropped = true
				break
			}
		}
		if !dropped {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		// Every transform was subsumed by another, which can only happen on a
		// cycle - and Build rejects cycles. Returning the input unchanged
		// keeps the caller on the deny path rather than silently applying
		// nothing to the leaf.
		return ts
	}
	return keep
}

func renderTransforms(ts []Transform) string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Canonical())
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// --- Approval -------------------------------------------------------------

// composeApproval concatenates clauses and deduplicates identical ones.
//
// THE POOLS ARE NEVER INTERSECTED OR UNIONED. That is the correction ADR-065
// makes to the source spec: under a pool-intersection meet, 2-of-{A,B} and
// 2-of-{B,C} become 2-of-{B}, which no set of approvers can satisfy, so the
// system denies a request that {A,B,C} plainly should be able to approve.
// Under the conjunction implemented here both clauses survive and {A,B,C}
// satisfies them (with separation of duties OFF - see the approval authority,
// where SoD makes the same input require four distinct approvers).
func composeApproval(c *composer, obs []Obligation) error {
	seen := map[string]struct{}{}
	for _, o := range obs {
		p, ok := o.Params.(ApprovalParams)
		if !ok {
			return fmt.Errorf("compose approval: %s carries %T", o.Type, o.Params)
		}
		for _, cl := range p.AllOf {
			k := cl.canonical()
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			c.plan.ApprovalClauses = append(c.plan.ApprovalClauses, ApprovalClause{
				Quorum:   cl.Quorum,
				Eligible: sortedUnique(cl.Eligible),
			})
		}
		// Separation of duties is a conjunction over a boolean: if ANY
		// requirement policy demands it, it holds. The permissive direction
		// (requiring every policy to agree) would let one lax policy disarm a
		// strict one.
		if p.SeparationOfDuties {
			c.plan.SeparationOfDuties = true
		}
		// The SHORTEST expiry wins. A conjunction of requirements is
		// discharged only while all of them are live, and taking the longest
		// would keep a challenge open past the point one policy said it should
		// have timed out - and timeout is always deny, so extending it is the
		// permissive direction.
		if c.plan.ApprovalExpirySeconds == 0 || p.ExpirySeconds < c.plan.ApprovalExpirySeconds {
			c.plan.ApprovalExpirySeconds = p.ExpirySeconds
		}
	}
	sort.Slice(c.plan.ApprovalClauses, func(i, j int) bool {
		return c.plan.ApprovalClauses[i].canonical() < c.plan.ApprovalClauses[j].canonical()
	})
	return nil
}

// --- Routing --------------------------------------------------------------

func composeRouting(c *composer, obs []Obligation) error {
	var dests []string
	destsSet := false
	for _, o := range obs {
		p, ok := o.Params.(RoutingParams)
		if !ok {
			return fmt.Errorf("compose routing: %s carries %T", o.Type, o.Params)
		}
		if p.AllowedDestinations != nil {
			if !destsSet {
				dests = sortedUnique(p.AllowedDestinations)
				destsSet = true
			} else {
				dests = intersect(dests, p.AllowedDestinations)
			}
			if len(dests) == 0 {
				return &ConflictError{
					Family:  FamilyRouting,
					Subject: "destinations",
					Detail:  "the intersection of allowed destinations is empty",
				}
			}
		}
		for k, vs := range p.RequiredProperties {
			existing, present := c.plan.RoutingProperties[k]
			if !present {
				c.plan.RoutingProperties[k] = sortedUnique(vs)
			} else {
				c.plan.RoutingProperties[k] = intersect(existing, vs)
			}
			if len(c.plan.RoutingProperties[k]) == 0 {
				return &ConflictError{
					Family:  FamilyRouting,
					Subject: k,
					Detail:  "the intersection of permitted values for this route property is empty",
				}
			}
		}
	}
	if destsSet {
		c.plan.RoutingDestinations = dests
	}
	return nil
}

// --- Step-up --------------------------------------------------------------

func composeStepUp(c *composer, obs []Obligation) error {
	var methods []string
	methodsSet := false
	for _, o := range obs {
		p, ok := o.Params.(StepUpParams)
		if !ok {
			return fmt.Errorf("compose step-up: %s carries %T", o.Type, o.Params)
		}
		if p.MinAssurance > c.plan.StepUpAssurance {
			c.plan.StepUpAssurance = p.MinAssurance
		}
		if p.PermittedMethods != nil {
			if !methodsSet {
				methods = sortedUnique(p.PermittedMethods)
				methodsSet = true
			} else {
				methods = intersect(methods, p.PermittedMethods)
			}
			if len(methods) == 0 {
				return &ConflictError{
					Family:  FamilyStepUp,
					Subject: "methods",
					Detail:  "the intersection of permitted authentication methods is empty",
				}
			}
		}
	}
	if methodsSet {
		c.plan.StepUpMethods = methods
	}
	return nil
}

// --- Budget ---------------------------------------------------------------

// composeBudget takes the conjunction: every applicable reservation must
// succeed atomically. Two demands against the SAME counter are summed, because
// two requirement policies each asking for capacity on one counter both need
// their capacity - taking the maximum would let the second policy ride on the
// first policy's reservation for free.
func composeBudget(c *composer, obs []Obligation) error {
	index := map[string]int{}
	for _, o := range obs {
		p, ok := o.Params.(BudgetParams)
		if !ok {
			return fmt.Errorf("compose budget: %s carries %T", o.Type, o.Params)
		}
		for _, d := range p.Demands {
			kd := KeyedBudgetDemand{
				BudgetID:      p.BudgetID,
				BudgetVersion: p.BudgetVersion,
				Window:        p.Window,
				CounterID:     d.CounterID,
				Amount:        d.Amount,
				Unit:          d.Unit,
			}
			if i, dup := index[kd.dedupKey()]; dup {
				sum := c.plan.BudgetDemands[i].Amount + kd.Amount
				if sum < c.plan.BudgetDemands[i].Amount {
					// Refuse rather than wrap. A wrapped total is a NEGATIVE
					// demand, which every conditional reservation would admit.
					return &ConflictError{
						Family:  FamilyBudget,
						Subject: kd.dedupKey(),
						Detail:  "summed demand overflows int64",
					}
				}
				c.plan.BudgetDemands[i].Amount = sum
				continue
			}
			index[kd.dedupKey()] = len(c.plan.BudgetDemands)
			c.plan.BudgetDemands = append(c.plan.BudgetDemands, kd)
		}
	}
	// Two demands on the same counter in DIFFERENT units cannot be summed and
	// must not be silently kept as two independent reservations against one
	// counter: the counter has one unit.
	perCounter := map[string]string{}
	for _, d := range c.plan.BudgetDemands {
		ck := fmt.Sprintf("%s@v%d/%s/%s", d.BudgetID, d.BudgetVersion, d.Window, d.CounterID)
		if u, seen := perCounter[ck]; seen && u != d.Unit {
			return &ConflictError{
				Family:  FamilyBudget,
				Subject: ck,
				Detail:  fmt.Sprintf("counter demanded in two units (%s and %s); conversion is a reservation-service concern with a versioned rate, not something composition may assume", u, d.Unit),
			}
		}
		perCounter[ck] = d.Unit
	}
	sort.Slice(c.plan.BudgetDemands, func(i, j int) bool {
		return c.plan.BudgetDemands[i].dedupKey() < c.plan.BudgetDemands[j].dedupKey()
	})
	return nil
}

// --- Audit / notification -------------------------------------------------

func composeAuditNotification(c *composer, obs []Obligation) error {
	index := map[string]int{}
	for _, o := range obs {
		p, ok := o.Params.(AuditNotifyParams)
		if !ok {
			return fmt.Errorf("compose audit/notification: %s carries %T", o.Type, o.Params)
		}
		for _, t := range p.Targets {
			if i, dup := index[t.dedupKey()]; dup {
				if t.Delivery.Rank() > c.plan.AuditTargets[i].Delivery.Rank() {
					c.plan.AuditTargets[i].Delivery = t.Delivery
				}
				continue
			}
			index[t.dedupKey()] = len(c.plan.AuditTargets)
			c.plan.AuditTargets = append(c.plan.AuditTargets, t)
		}
	}
	sort.Slice(c.plan.AuditTargets, func(i, j int) bool {
		return c.plan.AuditTargets[i].dedupKey() < c.plan.AuditTargets[j].dedupKey()
	})
	return nil
}

// --- Phase ordering -------------------------------------------------------

// composePhaseOrder topologically sorts the obligation types present in the
// plan by their declared dependencies. A cycle denies; so does a dependency on
// a type that IS present but has no registered owner (a missing executor).
//
// A dependency on a type that is ABSENT from the plan is not an error: nothing
// has to run before something that is not running.
func composePhaseOrder(reg *Registry, obs []Obligation) ([]Type, error) {
	present := map[Type]Schema{}
	for _, o := range obs {
		s, ok := reg.Lookup(o.Type, o.Version)
		if !ok {
			return nil, fmt.Errorf("phase order: no schema for %s", o.Capability())
		}
		if s.Owner == "" {
			return nil, &ConflictError{
				Family:  FamilyPhaseOrdering,
				Subject: string(o.Type),
				Detail:  "obligation has no owning executor",
			}
		}
		present[o.Type] = s
	}

	// Kahn's algorithm over the present subgraph, with ties broken by type
	// name so the order is deterministic and a trace is diffable.
	indeg := map[Type]int{}
	edges := map[Type][]Type{} // dep -> dependents
	for t, s := range present {
		if _, ok := indeg[t]; !ok {
			indeg[t] = 0
		}
		for _, dep := range s.DependsOn {
			if _, inPlan := present[dep]; !inPlan {
				continue
			}
			edges[dep] = append(edges[dep], t)
			indeg[t]++
		}
	}

	ready := make([]Type, 0, len(indeg))
	for t, d := range indeg {
		if d == 0 {
			ready = append(ready, t)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i] < ready[j] })

	out := make([]Type, 0, len(indeg))
	for len(ready) > 0 {
		t := ready[0]
		ready = ready[1:]
		out = append(out, t)
		next := append([]Type(nil), edges[t]...)
		sort.Slice(next, func(i, j int) bool { return next[i] < next[j] })
		for _, d := range next {
			indeg[d]--
			if indeg[d] == 0 {
				ready = append(ready, d)
				sort.Slice(ready, func(i, j int) bool { return ready[i] < ready[j] })
			}
		}
	}
	if len(out) != len(indeg) {
		remaining := make([]string, 0)
		for t, d := range indeg {
			if d > 0 {
				remaining = append(remaining, string(t))
			}
		}
		sort.Strings(remaining)
		return nil, &ConflictError{
			Family:  FamilyPhaseOrdering,
			Subject: strings.Join(remaining, ","),
			Detail:  "dependency cycle; no discharge order exists",
		}
	}
	return out, nil
}
