// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
)

// Schema is the EXECUTOR REGISTRATION for one obligation type at one version:
// who discharges it, when, with what evidence, and what happens on failure.
//
// WHAT IS DELIBERATELY ABSENT: there is no composition function, no precedence
// list, no "beats" or "overrides" field, no family, and no parameter model.
// ADR-065 says "a schema can validate its own parameters but cannot redefine
// its family's algebra", and the way to guarantee that is to give the schema
// nowhere to put one. The family is a property of the canonical TYPE
// (contract.FamilyOf), so a schema cannot record one axis and have composition
// enforce another. The single func-typed field is ValidateParams, and
// TestSchemaCannotCarryACompositionHook fails if a second one is ever added -
// including one added in good faith with an innocuous name.
type Schema struct {
	// Type and Version are the identity. (Type, Version) is the registry key
	// and is the same identity a PEP advertises (contract.Capability).
	Type    contract.ObligationType
	Version int

	// Owner is the named enforcement component that discharges this
	// obligation. ADR-065: "an obligation is a typed instruction owned by a
	// named enforcement component". An obligation with no owner has no
	// executor, and the phase-ordering pass denies on a missing executor.
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

	// Delivery is the guarantee an out-of-band obligation's EXECUTOR provides,
	// in the canonical vocabulary. Required for schemas whose Phases include
	// PhaseOutOfBand. The guarantee an OBLIGATION demands travels as its
	// `delivery` parameter and is composed by the algebra; this is the
	// executor's side of that contract, and pre-permit proof 6 compares them.
	Delivery contract.Delivery

	// OnFailure is the failure behaviour. FailRecorded is legal only where the
	// obligation can only ever be advisory.
	OnFailure FailureBehavior

	// AdvisoryOnly marks a schema that may never be instantiated as mandatory.
	AdvisoryOnly bool

	// DependsOn lists obligation types that must be discharged BEFORE this
	// one. It is the input to the phase-ordering DAG. A dependency on a type
	// absent from the plan is not an error (nothing to wait for); a CYCLE is.
	DependsOn []contract.ObligationType

	// ValidateParams is the schema's own parameter validation, run in addition
	// to the canonical validator. This is the ONLY behaviour a schema
	// contributes, and it can only REJECT - it is handed a copy and returns an
	// error, so it cannot rewrite what it was given.
	ValidateParams func(contract.Obligation) error
}

// Family returns the composition family of the schema's type. It is derived,
// never declared: a schema has no say in which algebra composes its type.
func (s Schema) Family() (contract.ObligationFamily, error) { return contract.FamilyOf(s.Type) }

// Validate checks a schema's internal consistency at registration time.
func (s Schema) Validate() error {
	if s.Type == "" {
		return fmt.Errorf("obligation schema: type is required")
	}
	if _, err := contract.FamilyOf(s.Type); err != nil {
		return fmt.Errorf("obligation schema: %w; the registry cannot register a type the canonical vocabulary does not declare", err)
	}
	if s.Version <= 0 {
		return fmt.Errorf("obligation schema %s: version must be >= 1", s.Type)
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
	if oob {
		if err := s.Delivery.Validate(); err != nil {
			return fmt.Errorf("obligation schema %s: an out-of-band phase requires a delivery guarantee (ADR-065 pre-permit proof 6): %w", s.Type, err)
		}
	} else if s.Delivery != "" {
		return fmt.Errorf("obligation schema %s: declares delivery %q but no out-of-band phase, so nothing would honour it", s.Type, s.Delivery)
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
		if _, err := contract.FamilyOf(d); err != nil {
			return fmt.Errorf("obligation schema %s: depends on %q, which %v", s.Type, d, err)
		}
	}
	return nil
}

// Registry holds the versioned executor registrations and the reviewed
// disclosure-subsumption rules the algebra is handed.
//
// A Registry is immutable after Build. Nothing in the decision path may
// register a schema; a runtime registration would let a request change the
// meaning of the plan that is evaluating it.
type Registry struct {
	schemas map[contract.Capability]Schema
	// subsumption is contract's validated rule set. The registry HOLDS the
	// reviewed rules - registration is platform-owned - and hands them to the
	// algebra unchanged; it never applies one.
	subsumption *contract.SubsumptionRules
	// version identifies the registry snapshot. It is bound into the decision
	// proof, so a registry change invalidates outstanding proofs loudly.
	version string
}

// RegistryBuilder accumulates schemas before Build seals them.
type RegistryBuilder struct {
	version string
	schemas []Schema
	rules   []contract.SubsumptionRule
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
func (b *RegistryBuilder) AddSubsumption(r contract.SubsumptionRule) *RegistryBuilder {
	b.rules = append(b.rules, r)
	return b
}

// Build validates every staged schema and seals the registry.
func (b *RegistryBuilder) Build() (*Registry, error) {
	if b.version == "" {
		return nil, fmt.Errorf("obligation registry: version is required (it is bound into decision proofs)")
	}
	r := &Registry{
		schemas: make(map[contract.Capability]Schema, len(b.schemas)),
		version: b.version,
	}
	for _, s := range b.schemas {
		if err := s.Validate(); err != nil {
			return nil, err
		}
		key := contract.Capability{Type: s.Type, Version: s.Version}
		if _, dup := r.schemas[key]; dup {
			return nil, fmt.Errorf("obligation registry: duplicate schema %s", key)
		}
		r.schemas[key] = s
	}
	// The rule set is validated by the algebra's own constructor - reason
	// required, no reflexive rule, one stronger per weaker, acyclic, disclosure
	// family only - so that a rule this registry accepts is a rule composition
	// accepts, with no second reading of what a valid rule is.
	rules, err := contract.NewSubsumptionRules(b.rules...)
	if err != nil {
		return nil, fmt.Errorf("obligation registry: %w", err)
	}
	r.subsumption = rules
	return r, nil
}

// Version reports the registry snapshot version.
func (r *Registry) Version() string { return r.version }

// Lookup returns the schema for an exact (type, version), or false.
//
// There is NO "latest version" lookup, on purpose. ADR-065 requires the PEP to
// advertise the EXACT capability and version; a registry that resolves v0 or a
// missing version to "whatever is newest" would let a v1 PEP be handed a v2
// obligation it cannot discharge.
func (r *Registry) Lookup(t contract.ObligationType, version int) (Schema, bool) {
	s, ok := r.schemas[contract.Capability{Type: t, Version: version}]
	return s, ok
}

// Capabilities lists every (type, version) the registry knows, sorted. It is
// the identity set a PEP built from this registry advertises, in the same
// spelling the wire and the handshake use.
func (r *Registry) Capabilities() []contract.Capability {
	out := make([]contract.Capability, 0, len(r.schemas))
	for c := range r.schemas {
		out = append(out, c)
	}
	return contract.SortCapabilities(out)
}

// Profile renders the registry as an enforcement profile advertising every
// capability it registers. A PEP that executes every registered obligation
// advertises exactly this.
func (r *Registry) Profile(id string) *contract.PEPProfile {
	return &contract.PEPProfile{ID: id, Capabilities: r.Capabilities()}
}

// SubsumptionRules lists the reviewed rules, sorted, for the trace and for
// tests that assert the default registry ships none.
func (r *Registry) SubsumptionRules() []contract.SubsumptionRule { return r.subsumption.Rules() }

// Subsumption returns the sealed rule set for the algebra.
func (r *Registry) Subsumption() *contract.SubsumptionRules { return r.subsumption }

// UnknownCapabilities reports capabilities the profile advertises that the
// registry does not define.
//
// This is not a decision gate - a PEP advertising a capability nobody asks for
// is harmless - but it is the tell for a version-skewed deployment, and an
// operator wants it in a startup log rather than discovering it when a
// mandatory obligation denies in production.
func (r *Registry) UnknownCapabilities(p *contract.PEPProfile) []contract.Capability {
	if p == nil {
		return nil
	}
	var unknown []contract.Capability
	for _, c := range contract.SortCapabilities(p.Capabilities) {
		if _, ok := r.schemas[c]; !ok {
			unknown = append(unknown, c)
		}
	}
	return unknown
}

// ValidateObligation checks one obligation against the registry: instance
// invariants, schema presence, phase membership, advisory-only, and the
// schema's own parameter validation.
func (r *Registry) ValidateObligation(o Obligation) error {
	if err := o.Validate(); err != nil {
		return err
	}
	s, ok := r.Lookup(o.Type, o.SchemaVersion)
	if !ok {
		return fmt.Errorf("obligation %s: no schema registered for version %d", o.Type, o.SchemaVersion)
	}
	if s.AdvisoryOnly && o.Mandatory {
		return fmt.Errorf("obligation %s: schema is advisory-only and cannot be instantiated as mandatory", o.Type)
	}
	phaseOK := false
	for _, p := range s.Phases {
		if p == o.Phase {
			phaseOK = true
		}
	}
	if !phaseOK {
		return fmt.Errorf("obligation %s: phase %q is not one the schema declares (%v)", o.Type, o.Phase, s.Phases)
	}
	// A NotApplicable or Unknown obligation carries no parameters (see
	// Obligation.Validate); there is nothing to check against the schema.
	if o.Applicability != Applicable {
		return nil
	}
	if s.ValidateParams != nil {
		if err := s.ValidateParams(o.Obligation); err != nil {
			return fmt.Errorf("obligation %s: schema validation: %w", o.Type, err)
		}
	}
	return nil
}

// sortedTypes renders a type set in a stable order for traces.
func sortedTypes(in map[contract.ObligationType]struct{}) []string {
	out := make([]string, 0, len(in))
	for t := range in {
		out = append(out, string(t))
	}
	sort.Strings(out)
	return out
}
