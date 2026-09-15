// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"reflect"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// TestSchemaCannotCarryACompositionHook is the structural guarantee behind
// ADR-065's "a schema can validate its own parameters but cannot redefine its
// family's algebra".
//
// A source scan for the word "compose" would be beaten by a field called
// `Resolver`, `Combine`, `Precedence` or `Override`. This asserts the SHAPE
// instead: Schema may carry exactly ONE func-typed field, and it must be
// ValidateParams. Any second behavioural hook - whatever it is called - fails
// here, and whoever adds it has to come and argue with this comment.
//
// The signature is pinned too. A ValidateParams that returned an obligation
// could REWRITE what it was handed, which is a composition hook wearing a
// validator's name. And there is no Family field at all: the family is the
// canonical type's, so a schema cannot record one axis while composition
// enforces another.
func TestSchemaCannotCarryACompositionHook(t *testing.T) {
	st := reflect.TypeOf(Schema{})
	var funcFields []string
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if f.Type.Kind() == reflect.Func {
			funcFields = append(funcFields, f.Name)
		}
	}
	if len(funcFields) != 1 || funcFields[0] != "ValidateParams" {
		t.Fatalf("Schema carries func-typed fields %v; exactly one is permitted and it must be ValidateParams.\n"+
			"ADR-065: a schema validates its own parameters and cannot redefine its family's algebra. A second behavioural hook on Schema is that redefinition, whatever it is named.",
			funcFields)
	}
	vp, _ := st.FieldByName("ValidateParams")
	want := reflect.TypeOf(func(contract.Obligation) error { return nil })
	if vp.Type != want {
		t.Fatalf("ValidateParams has signature %s, want %s. A validator that RETURNS an obligation can rewrite what it was handed, which is a composition hook.",
			vp.Type, want)
	}
	if _, has := st.FieldByName("Family"); has {
		t.Fatal("Schema declares a Family; the family is a property of the canonical type (contract.FamilyOf) and a schema must not be able to claim another")
	}
}

// TestSchemaCannotNameAnUnregisteredType: the registry registers EXECUTORS for
// the canonical vocabulary; it cannot introduce a type of its own, because a
// type no decision can carry has nothing to execute.
func TestSchemaCannotNameAnUnregisteredType(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: "field_redaction", Version: 1, Owner: "o", Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", OnFailure: FailClosed})
	_, err := b.Build()
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("err = %v, want a refusal naming the unregistered type", err)
	}
}

// TestReleaseGatingSchemaNeedsCompletionEvidence is pre-permit proof 5
// enforced at registration rather than at decision time: a gating obligation
// with no evidence contract could never be proven discharged, so the planner
// would either hold forever or permit on nothing.
func TestReleaseGatingSchemaNeedsCompletionEvidence(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: contract.ObFieldRedact, Version: 1, Owner: "o", Phases: []Phase{PhaseRequest}, OnFailure: FailClosed})
	_, err := b.Build()
	if err == nil || !strings.Contains(err.Error(), "completion_evidence") {
		t.Fatalf("err = %v, want a completion-evidence refusal", err)
	}
}

// TestOutOfBandSchemaNeedsADeliveryGuarantee is pre-permit proof 6 at
// registration time, in the canonical delivery vocabulary.
func TestOutOfBandSchemaNeedsADeliveryGuarantee(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: contract.ObImmutableAudit, Version: 1, Owner: "o", Phases: []Phase{PhaseOutOfBand}, OnFailure: FailClosed})
	_, err := b.Build()
	if err == nil || !strings.Contains(err.Error(), "delivery guarantee") {
		t.Fatalf("err = %v, want a delivery-guarantee refusal", err)
	}
	b = NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: contract.ObImmutableAudit, Version: 1, Owner: "o", Phases: []Phase{PhaseOutOfBand}, Delivery: "at_least_once_durable", OnFailure: FailClosed})
	_, err = b.Build()
	if err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("err = %v, want the losing spelling refused as undeclared", err)
	}
	b = NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: contract.ObFieldRedact, Version: 1, Owner: "o", Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", Delivery: contract.DeliveryDurable, OnFailure: FailClosed})
	if _, err = b.Build(); err == nil {
		t.Fatal("a delivery guarantee on a schema with no out-of-band phase would be honoured by nothing and must be refused")
	}
}

// TestRecordOnFailureIsOnlyLegalOnAdvisoryOnlySchemas: a MANDATORY obligation
// that records its own failure and continues is a fail-open wearing a
// configuration flag.
func TestRecordOnFailureIsOnlyLegalOnAdvisoryOnlySchemas(t *testing.T) {
	mk := func(advisoryOnly bool) error {
		b := NewRegistryBuilder("test.v1")
		b.Add(Schema{Type: contract.ObNotification, Version: 1, Owner: "o", Phases: []Phase{PhaseOutOfBand},
			Delivery: contract.DeliveryDurable, OnFailure: FailRecorded, AdvisoryOnly: advisoryOnly})
		_, err := b.Build()
		return err
	}
	if err := mk(false); err == nil {
		t.Fatal("on_failure=record on a schema that can be instantiated as mandatory must be rejected")
	}
	if err := mk(true); err != nil {
		t.Fatalf("on_failure=record on an advisory-only schema must be accepted: %v", err)
	}
}

// TestAdvisoryOnlySchemaCannotBeInstantiatedAsMandatory closes the same hole
// from the instance side.
func TestAdvisoryOnlySchemaCannotBeInstantiatedAsMandatory(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: contract.ObNotification, Version: 1, Owner: "o", Phases: []Phase{PhaseOutOfBand},
		Delivery: contract.DeliveryDurable, OnFailure: FailRecorded, AdvisoryOnly: true})
	reg, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = reg.ValidateObligation(canon(contract.ObNotification, "", true, "p", map[string]string{"channel": "c"}))
	if err == nil {
		t.Fatal("an advisory-only schema instantiated as mandatory must be refused")
	}
}

// TestSchemaWithoutAnOwnerIsRejected: an obligation with no owner has no
// executor, and the phase-ordering pass's "missing executor denies" rule can
// only be reached if an ownerless schema could exist in the first place.
// Rejecting at registration means it cannot.
func TestSchemaWithoutAnOwnerIsRejected(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: contract.ObFieldRedact, Version: 1, Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", OnFailure: FailClosed})
	if _, err := b.Build(); err == nil {
		t.Fatal("a schema with no owner must be rejected")
	}
}

// TestInstancePhaseMustBeOneTheSchemaDeclares: a request-phase instance of a
// response-only executor would be scheduled where nothing runs it.
func TestInstancePhaseMustBeOneTheSchemaDeclares(t *testing.T) {
	reg := testRegistry(t)
	ob := canon(contract.ObResponseFilter, "x", true, "p", nil)
	ob.Phase = PhaseRequest
	err := reg.ValidateObligation(ob)
	if err == nil || !strings.Contains(err.Error(), "phase") {
		t.Fatalf("err = %v, want a phase refusal", err)
	}
}

// TestRegistryHasNoLatestVersionLookup: a registry that resolved a missing or
// zero version to "whatever is newest" would hand a v1 PEP a v2 obligation.
// The guard is behavioural - version 0 and an unregistered version both miss.
func TestRegistryHasNoLatestVersionLookup(t *testing.T) {
	reg := testRegistry(t)
	if _, ok := reg.Lookup(contract.ObFieldRedact, 0); ok {
		t.Error("version 0 resolved to a schema; 0 is not 'latest'")
	}
	if _, ok := reg.Lookup(contract.ObFieldRedact, 2); ok {
		t.Error("an unregistered version resolved to a schema")
	}
	if _, ok := reg.Lookup(contract.ObFieldRedact, 1); !ok {
		t.Error("the registered version did not resolve")
	}
}

func TestDuplicateSchemaIsRejected(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	s := Schema{Type: contract.ObFieldRedact, Version: 1, Owner: "o", Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", OnFailure: FailClosed}
	b.Add(s)
	b.Add(s)
	if _, err := b.Build(); err == nil {
		t.Fatal("a duplicate (type, version) must be rejected")
	}
}

func TestRegistryVersionIsRequired(t *testing.T) {
	if _, err := NewRegistryBuilder("").Build(); err == nil {
		t.Fatal("an unversioned registry must be rejected: the version is bound into every decision proof")
	}
}

// ---------------------------------------------------------------------------
// The initial registry
// ---------------------------------------------------------------------------

// TestInitialRegistryDefinesEveryCanonicalType pins the registry to the ONE
// vocabulary in both directions: every type the decision can carry has an
// executor registration, and the registry registers nothing the vocabulary
// does not declare (the second direction is structural - Schema.Validate
// refuses it - and this asserts the first).
func TestInitialRegistryDefinesEveryCanonicalType(t *testing.T) {
	reg := testRegistry(t)
	got := map[contract.ObligationType]bool{}
	for _, c := range reg.Capabilities() {
		got[c.Type] = true
		if c.Version != 1 {
			t.Errorf("%s registered at version %d; the initial registry is v1 throughout", c.Type, c.Version)
		}
	}
	for _, want := range contract.AllObligationTypes() {
		if !got[want] {
			t.Errorf("type %q is in the canonical vocabulary but has no executor registration; a decision carrying it would deny for want of a schema", want)
		}
	}
	if len(got) != len(contract.AllObligationTypes()) {
		t.Fatalf("registry defines %d types, the vocabulary declares %d", len(got), len(contract.AllObligationTypes()))
	}
}

// TestInitialRegistryCoversEveryFamilyThatOwnsTypes: every canonical family
// owns at least one registered type, so every algebra branch is reachable
// through the planner.
func TestInitialRegistryCoversEveryFamilyThatOwnsTypes(t *testing.T) {
	reg := testRegistry(t)
	seen := map[contract.ObligationFamily]bool{}
	for _, c := range reg.Capabilities() {
		s, _ := reg.Lookup(c.Type, c.Version)
		fam, err := s.Family()
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		seen[fam] = true
	}
	for _, f := range contract.AllObligationFamilies() {
		if !seen[f] {
			t.Errorf("family %q owns no type in the initial registry, so its algebra is never exercised through the planner", f)
		}
	}
}

// TestInitialRegistryShipsNoSubsumptionRules keeps ADR-065's escape hatch from
// quietly becoming the norm. Adding a rule requires a recorded review AND a
// deliberate edit here.
func TestInitialRegistryShipsNoSubsumptionRules(t *testing.T) {
	reg := testRegistry(t)
	if rules := reg.SubsumptionRules(); len(rules) != 0 {
		t.Fatalf("the initial registry ships %d subsumption rules: %+v.\n"+
			"ADR-065 makes incomparable disclosure transforms DENY unless a REVIEWED rule says otherwise. Adding one here is a security review, not a code change.",
			len(rules), rules)
	}
}

// TestInitialRegistryMandatoryAuditAndNotificationAreDurable: these are the
// two out-of-band types, and a mandatory instance of either denies unless its
// executor's delivery is durable. Shipping them non-durable would make every
// mandatory audit obligation an automatic deny.
func TestInitialRegistryMandatoryAuditAndNotificationAreDurable(t *testing.T) {
	reg := testRegistry(t)
	for _, tp := range []contract.ObligationType{contract.ObImmutableAudit, contract.ObNotification} {
		s, ok := reg.Lookup(tp, 1)
		if !ok {
			t.Fatalf("%s not registered", tp)
		}
		if s.Delivery != contract.DeliveryDurable {
			t.Errorf("%s delivery = %q, want %q", tp, s.Delivery, contract.DeliveryDurable)
		}
	}
}

// TestInitialRegistryDependenciesAreAcyclic runs the DAG over the full type
// set, not just the subsets the other tests happen to compose.
func TestInitialRegistryDependenciesAreAcyclic(t *testing.T) {
	reg := testRegistry(t)
	var all []contract.Obligation
	for _, c := range reg.Capabilities() {
		all = append(all, contract.Obligation{Type: c.Type, SchemaVersion: c.Version, Mandatory: true})
	}
	order, err := composePhaseOrder(reg, all)
	if err != nil {
		t.Fatalf("the initial dependency graph is not a DAG: %v", err)
	}
	if len(order) != len(reg.Capabilities()) {
		t.Fatalf("order covers %d of %d types", len(order), len(reg.Capabilities()))
	}
}

// TestInitialRegistryOrderingActuallyAppliesTheEdges guards the two-step
// construction: NewInitialRegistryWithOrdering rebuilds the registry from
// NewInitialRegistry and applies initialDependencies. A rebuild that dropped
// the edges would leave a registry that looks right and orders nothing.
func TestInitialRegistryOrderingActuallyAppliesTheEdges(t *testing.T) {
	reg := testRegistry(t)
	s, ok := reg.Lookup(contract.ObApprovalChallenge, 1)
	if !ok {
		t.Fatal("approval_challenge not registered")
	}
	want := map[contract.ObligationType]bool{contract.ObStepUpAuth: true, contract.ObQuotaReservation: true}
	if len(s.DependsOn) != len(want) {
		t.Fatalf("approval_challenge depends on %v, want %d edges", s.DependsOn, len(want))
	}
	for _, d := range s.DependsOn {
		if !want[d] {
			t.Errorf("unexpected dependency %q", d)
		}
	}

	// And the un-ordered constructor must NOT carry them, or the two-step
	// build is pointless and this test would pass on either.
	plain, err := NewInitialRegistry()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ps, _ := plain.Lookup(contract.ObApprovalChallenge, 1)
	if len(ps.DependsOn) != 0 {
		t.Fatalf("NewInitialRegistry already carries edges %v; the ordering step is then untested", ps.DependsOn)
	}
}

// TestApprovalExpiryCeilingIsEnforcedOnTheLivePath.
//
// The ceiling is ADR-065's coordinated approval-and-reservation window, and it
// used to be re-implemented as a ValidateParams hook on this registry with its
// own literal. That hook could never run on a deployment: the ceiling has to
// bind where composition happens, and nothing in production reaches it through
// here. It now lives once, in contract.MaxApprovalExpirySeconds, and this test
// reaches it the way a policy does - through the canonical validator - so a
// green here means the bound actually holds rather than that a second copy of
// it agreed with the first.
func TestApprovalExpiryCeilingIsEnforcedOnTheLivePath(t *testing.T) {
	reg := testRegistry(t)
	ob := canon(contract.ObApprovalChallenge, "", true, "p", map[string]string{
		"quorum": "1", "eligible": "Group::r:a", contract.ParamExpirySeconds: "691200", // 8 days
	})
	err := reg.ValidateObligation(ob)
	if err == nil || !strings.Contains(err.Error(), "maximum an approval hold") {
		t.Fatalf("err = %v, want a schema-level expiry refusal", err)
	}
	ob.Params[contract.ParamExpirySeconds] = "604800" // exactly 7 days
	if err := reg.ValidateObligation(ob); err != nil {
		t.Fatalf("the ceiling is inclusive; got %v", err)
	}
}

// TestUnknownCapabilitiesReportsVersionSkew: a PEP advertising something the
// registry does not define is the tell for a skewed deployment.
func TestUnknownCapabilitiesReportsVersionSkew(t *testing.T) {
	reg := testRegistry(t)
	skew := &contract.PEPProfile{ID: "p", Capabilities: []contract.Capability{
		{Type: contract.ObFieldRedact, Version: 1},
		{Type: contract.ObFieldRedact, Version: 7},
	}}
	got := reg.UnknownCapabilities(skew)
	if !reflect.DeepEqual(got, []contract.Capability{{Type: contract.ObFieldRedact, Version: 7}}) {
		t.Fatalf("unknown = %v, want only the v7", got)
	}
	if reg.UnknownCapabilities(nil) != nil {
		t.Fatal("a nil profile advertises nothing unknown")
	}
}
