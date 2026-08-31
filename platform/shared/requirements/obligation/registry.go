// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"
)

// Schema is the versioned contract for one obligation type.
//
// WHAT IS DELIBERATELY ABSENT: there is no composition function, no precedence
// list, no "beats" or "overrides" field, and no family override. ADR-065 says
// "a schema can validate its own parameters but cannot redefine its family's
// algebra", and the way to guarantee that is to give the schema nowhere to put
// one. The single func-typed field is ValidateParams, and
// TestSchemaCannotCarryACompositionHook fails if a second one is ever added -
// including one added in good faith with an innocuous name.
type Schema struct {
	// Type and Version are the identity. (Type, Version) is the registry key.
	Type    Type
	Version int

	// Family selects the composition algebra. It is read by the algebra
	// dispatcher and cannot be overridden per-schema.
	Family Family

	// Owner is the named enforcement component that discharges this
	// obligation. ADR-065: "an obligation is a typed instruction owned by a
	// named enforcement component". An obligation with no owner has no
	// executor, and the phase-ordering algebra denies on a missing executor.
	Owner string

	// Phases are the phases in which this obligation may be discharged. An
	// instance's phase is chosen from this set by the planner input.
	Phases []Phase

	// Idempotent says whether discharging twice is safe. A non-idempotent
	// obligation must carry an idempotency key at execution; the executor
	// contract, not this package, enforces that - it is recorded here so a PEP
	// can refuse to retry.
	Idempotent bool

	// CompletionEvidence names the evidence a release-gating obligation must
	// produce before the decision can become ALLOW (for example
	// "engine_redaction_receipt"). Required for every schema whose Phases
	// include a release-gating phase.
	CompletionEvidence string

	// Delivery is the guarantee an out-of-band obligation must have. Required
	// for schemas whose Phases include PhaseOutOfBand.
	Delivery DeliveryGuarantee

	// OnFailure is the failure behaviour. FailRecorded is legal only where the
	// obligation can only ever be advisory.
	OnFailure FailureBehavior

	// AdvisoryOnly marks a schema that may never be instantiated as mandatory.
	AdvisoryOnly bool

	// DependsOn lists obligation types that must be discharged BEFORE this
	// one. It is the input to the phase-ordering DAG. A dependency on a type
	// absent from the plan is not an error (nothing to wait for); a CYCLE is.
	DependsOn []Type

	// ValidateParams is the schema's own parameter validation, run in addition
	// to Params.Validate. This is the ONLY behaviour a schema contributes, and
	// it can only REJECT - it is handed a copy and returns an error, so it
	// cannot rewrite what it was given.
	ValidateParams func(Params) error
}

// Validate checks a schema's internal consistency at registration time.
func (s Schema) Validate() error {
	if s.Type == "" {
		return fmt.Errorf("obligation schema: type is required")
	}
	if s.Version <= 0 {
		return fmt.Errorf("obligation schema %s: version must be >= 1", s.Type)
	}
	if s.Family == "" {
		return fmt.Errorf("obligation schema %s: family is required", s.Type)
	}
	if _, ok := familyAlgebras[s.Family]; !ok {
		return fmt.Errorf("obligation schema %s: family %q has no algebra", s.Type, s.Family)
	}
	if s.Family == FamilyPhaseOrdering {
		// Phase ordering composes the whole plan; no type belongs to it. A
		// schema claiming it would be asking for an algebra whose domain is
		// not a set of obligations.
		return fmt.Errorf("obligation schema %s: family %q is a plan-level algebra and cannot own a type",
			s.Type, FamilyPhaseOrdering)
	}
	if s.Owner == "" {
		return fmt.Errorf("obligation schema %s: owner is required (an obligation with no owner has no executor)", s.Type)
	}
	if len(s.Phases) == 0 {
		return fmt.Errorf("obligation schema %s: at least one phase is required", s.Type)
	}
	gates, oob := false, false
	for _, p := range s.Phases {
		switch p {
		case PhaseRequest, PhaseResponse:
			gates = true
		case PhaseOutOfBand:
			oob = true
		default:
			return fmt.Errorf("obligation schema %s: unknown phase %q", s.Type, p)
		}
	}
	if gates && s.CompletionEvidence == "" {
		return fmt.Errorf("obligation schema %s: a release-gating phase requires completion_evidence (ADR-065 pre-permit proof 5)", s.Type)
	}
	if oob && s.Delivery.Rank() < 0 {
		return fmt.Errorf("obligation schema %s: an out-of-band phase requires a delivery guarantee (ADR-065 pre-permit proof 6)", s.Type)
	}
	switch s.OnFailure {
	case FailClosed:
	case FailRecorded:
		if !s.AdvisoryOnly {
			return fmt.Errorf("obligation schema %s: on_failure %q is only legal on an advisory-only schema; a mandatory obligation that records its own failure and continues is a fail-open",
				s.Type, FailRecorded)
		}
	default:
		return fmt.Errorf("obligation schema %s: on_failure must be %q or %q, got %q", s.Type, FailClosed, FailRecorded, s.OnFailure)
	}
	for _, d := range s.DependsOn {
		if d == s.Type {
			return fmt.Errorf("obligation schema %s: depends on itself", s.Type)
		}
	}
	return nil
}

// SubsumptionRule is the REVIEWED escape hatch ADR-065 allows for otherwise
// incomparable disclosure transforms: "incomparable unless the registry
// contains a reviewed subsumption rule".
//
// It lives on the REGISTRY, not on a schema, and that placement is the whole
// point. A schema is authored per obligation type and could be added by
// anyone extending the type set; a registry entry is platform-owned, reviewed
// once, and applies to the family. This is how the ADR permits an exception
// without letting a policy or schema invent one.
type SubsumptionRule struct {
	// Weaker and Stronger are canonical transform renderings (Transform.Canonical).
	// The rule asserts: Stronger reveals no more than Weaker, so on a leaf
	// carrying both, Stronger wins.
	Weaker   string
	Stronger string
	// Reason records the review that approved the rule. Required: an
	// unexplained subsumption rule is an unreviewed one.
	Reason string
}

// Registry holds the versioned obligation schemas and the reviewed
// disclosure-subsumption rules.
//
// A Registry is immutable after Build. Nothing in the decision path may
// register a schema; a runtime registration would let a request change the
// meaning of the plan that is evaluating it.
type Registry struct {
	schemas     map[Capability]Schema
	subsumption map[string]string // weaker -> stronger
	rules       []SubsumptionRule
	// version identifies the registry snapshot. It is bound into the decision
	// proof, so a registry change invalidates outstanding proofs loudly.
	version string
}

// RegistryBuilder accumulates schemas before Build seals them.
type RegistryBuilder struct {
	version string
	schemas []Schema
	rules   []SubsumptionRule
}

// NewRegistryBuilder starts an empty builder. version is bound into decision
// proofs; it must be non-empty.
func NewRegistryBuilder(version string) *RegistryBuilder {
	return &RegistryBuilder{version: version}
}

// Add stages a schema.
func (b *RegistryBuilder) Add(s Schema) *RegistryBuilder {
	b.schemas = append(b.schemas, s)
	return b
}

// AddSubsumption stages a reviewed disclosure-subsumption rule.
func (b *RegistryBuilder) AddSubsumption(r SubsumptionRule) *RegistryBuilder {
	b.rules = append(b.rules, r)
	return b
}

// Build validates every staged schema and seals the registry.
func (b *RegistryBuilder) Build() (*Registry, error) {
	if b.version == "" {
		return nil, fmt.Errorf("obligation registry: version is required (it is bound into decision proofs)")
	}
	r := &Registry{
		schemas:     make(map[Capability]Schema, len(b.schemas)),
		subsumption: make(map[string]string, len(b.rules)),
		version:     b.version,
	}
	for _, s := range b.schemas {
		if err := s.Validate(); err != nil {
			return nil, err
		}
		key := Capability{Type: s.Type, Version: s.Version}
		if _, dup := r.schemas[key]; dup {
			return nil, fmt.Errorf("obligation registry: duplicate schema %s", key)
		}
		r.schemas[key] = s
	}
	for _, rule := range b.rules {
		if rule.Weaker == "" || rule.Stronger == "" {
			return nil, fmt.Errorf("obligation registry: subsumption rule needs both a weaker and a stronger transform")
		}
		if rule.Reason == "" {
			return nil, fmt.Errorf("obligation registry: subsumption rule %s -> %s has no recorded review reason", rule.Weaker, rule.Stronger)
		}
		if rule.Weaker == rule.Stronger {
			return nil, fmt.Errorf("obligation registry: subsumption rule is reflexive (%s)", rule.Weaker)
		}
		if existing, dup := r.subsumption[rule.Weaker]; dup {
			return nil, fmt.Errorf("obligation registry: %s already subsumed by %s; a second rule (%s) would make resolution order-dependent",
				rule.Weaker, existing, rule.Stronger)
		}
		r.subsumption[rule.Weaker] = rule.Stronger
		r.rules = append(r.rules, rule)
	}
	// A subsumption CYCLE would make "the least-disclosing transform" depend
	// on which one the loop happened to visit first.
	if err := r.checkSubsumptionAcyclic(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) checkSubsumptionAcyclic() error {
	for start := range r.subsumption {
		seen := map[string]struct{}{start: {}}
		cur := start
		for {
			next, ok := r.subsumption[cur]
			if !ok {
				break
			}
			if _, loop := seen[next]; loop {
				return fmt.Errorf("obligation registry: subsumption cycle through %s", next)
			}
			seen[next] = struct{}{}
			cur = next
		}
	}
	return nil
}

// Version reports the registry snapshot version.
func (r *Registry) Version() string { return r.version }

// Lookup returns the schema for an exact (type, version), or false.
//
// There is NO "latest version" lookup, on purpose. ADR-065 requires the PEP to
// advertise the EXACT capability and version; a registry that resolves v0 or a
// missing version to "whatever is newest" would let a v1 PEP be handed a v2
// obligation it cannot discharge.
func (r *Registry) Lookup(t Type, version int) (Schema, bool) {
	s, ok := r.schemas[Capability{Type: t, Version: version}]
	return s, ok
}

// Capabilities lists every (type, version) the registry knows, sorted. Used by
// a PEP to publish "the exact obligation types and versions it supports".
func (r *Registry) Capabilities() []Capability {
	out := make([]Capability, 0, len(r.schemas))
	for c := range r.schemas {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// SubsumptionRules lists the reviewed rules, sorted, for the trace and for
// tests that assert the default registry ships none.
func (r *Registry) SubsumptionRules() []SubsumptionRule {
	out := append([]SubsumptionRule(nil), r.rules...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Weaker != out[j].Weaker {
			return out[i].Weaker < out[j].Weaker
		}
		return out[i].Stronger < out[j].Stronger
	})
	return out
}

// subsumes reports whether stronger subsumes weaker through a reviewed rule,
// following the chain. Both arguments are Transform.Canonical renderings.
func (r *Registry) subsumes(weaker, stronger string) bool {
	cur := weaker
	for i := 0; i < len(r.subsumption)+1; i++ {
		next, ok := r.subsumption[cur]
		if !ok {
			return false
		}
		if next == stronger {
			return true
		}
		cur = next
	}
	return false
}

// ValidateObligation checks one obligation against the registry: instance
// invariants, schema presence, family agreement, advisory-only, and the
// schema's own parameter validation.
func (r *Registry) ValidateObligation(o Obligation) error {
	if err := o.Validate(); err != nil {
		return err
	}
	s, ok := r.Lookup(o.Type, o.Version)
	if !ok {
		return fmt.Errorf("obligation %s: no schema registered for version %d", o.Type, o.Version)
	}
	if s.AdvisoryOnly && o.Enforcement == Mandatory {
		return fmt.Errorf("obligation %s: schema is advisory-only and cannot be instantiated as mandatory", o.Type)
	}
	// A NotApplicable or Unknown obligation may carry nil params (see
	// Obligation.Validate); there is nothing to check against the schema.
	if o.Params == nil {
		return nil
	}
	if o.Params.Family() != s.Family {
		return fmt.Errorf("obligation %s: params belong to family %q but the schema declares %q",
			o.Type, o.Params.Family(), s.Family)
	}
	if err := o.Params.Validate(); err != nil {
		return fmt.Errorf("obligation %s: %w", o.Type, err)
	}
	if s.ValidateParams != nil {
		if err := s.ValidateParams(o.Params); err != nil {
			return fmt.Errorf("obligation %s: schema validation: %w", o.Type, err)
		}
	}
	return nil
}
