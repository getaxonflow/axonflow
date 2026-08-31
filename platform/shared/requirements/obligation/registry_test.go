// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
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
// The signature is pinned too. A ValidateParams that returned (Params, error)
// could REWRITE what it was handed, which is a composition hook wearing a
// validator's name.
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
	want := reflect.TypeOf(func(Params) error { return nil })
	if vp.Type != want {
		t.Fatalf("ValidateParams has signature %s, want %s. A validator that RETURNS a Params can rewrite what it was handed, which is a composition hook.",
			vp.Type, want)
	}
}

// TestSchemaCannotClaimThePlanLevelFamily: FamilyPhaseOrdering composes the
// whole plan, so a type belonging to it would be asking for an algebra whose
// domain is not a set of obligations.
func TestSchemaCannotClaimThePlanLevelFamily(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: "x", Version: 1, Family: FamilyPhaseOrdering, Owner: "o", Phases: []Phase{PhaseOutOfBand},
		Delivery: DeliveryAtLeastOnceDurable, OnFailure: FailClosed})
	if _, err := b.Build(); err == nil {
		t.Fatal("a schema claiming the plan-level family must be rejected")
	}
}

// TestReleaseGatingSchemaNeedsCompletionEvidence is pre-permit proof 5
// enforced at registration rather than at decision time: a gating obligation
// with no evidence contract could never be proven discharged, so the planner
// would either hold forever or permit on nothing.
func TestReleaseGatingSchemaNeedsCompletionEvidence(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: "x", Version: 1, Family: FamilyDisclosure, Owner: "o", Phases: []Phase{PhaseRequest}, OnFailure: FailClosed})
	_, err := b.Build()
	if err == nil || !strings.Contains(err.Error(), "completion_evidence") {
		t.Fatalf("err = %v, want a completion-evidence refusal", err)
	}
}

// TestOutOfBandSchemaNeedsADeliveryGuarantee is pre-permit proof 6 at
// registration time.
func TestOutOfBandSchemaNeedsADeliveryGuarantee(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: "x", Version: 1, Family: FamilyAuditNotification, Owner: "o", Phases: []Phase{PhaseOutOfBand}, OnFailure: FailClosed})
	_, err := b.Build()
	if err == nil || !strings.Contains(err.Error(), "delivery guarantee") {
		t.Fatalf("err = %v, want a delivery-guarantee refusal", err)
	}
}

// TestRecordOnFailureIsOnlyLegalOnAdvisoryOnlySchemas: a MANDATORY obligation
// that records its own failure and continues is a fail-open wearing a
// configuration flag.
func TestRecordOnFailureIsOnlyLegalOnAdvisoryOnlySchemas(t *testing.T) {
	mk := func(advisoryOnly bool) error {
		b := NewRegistryBuilder("test.v1")
		b.Add(Schema{Type: "x", Version: 1, Family: FamilyAuditNotification, Owner: "o", Phases: []Phase{PhaseOutOfBand},
			Delivery: DeliveryAtLeastOnceDurable, OnFailure: FailRecorded, AdvisoryOnly: advisoryOnly})
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
	b.Add(Schema{Type: "x", Version: 1, Family: FamilyAuditNotification, Owner: "o", Phases: []Phase{PhaseOutOfBand},
		Delivery: DeliveryAtLeastOnceDurable, OnFailure: FailRecorded, AdvisoryOnly: true})
	reg, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = reg.ValidateObligation(Obligation{Type: "x", Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		Params: AuditNotifyParams{Targets: []AuditNotifyTarget{{Channel: "c", Address: "a", Delivery: DeliveryNone}}}})
	if err == nil {
		t.Fatal("an advisory-only schema instantiated as mandatory must be refused")
	}
}

// TestSchemaWithoutAnOwnerIsRejected: an obligation with no owner has no
// executor, and the phase-ordering algebra's "missing executor denies" rule
// can only be reached if an ownerless schema could exist in the first place.
// Rejecting at registration means it cannot.
func TestSchemaWithoutAnOwnerIsRejected(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: "x", Version: 1, Family: FamilyDisclosure, Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", OnFailure: FailClosed})
	if _, err := b.Build(); err == nil {
		t.Fatal("a schema with no owner must be rejected")
	}
}

// TestRegistryHasNoLatestVersionLookup: a registry that resolved a missing or
// zero version to "whatever is newest" would hand a v1 PEP a v2 obligation.
// The guard is behavioural - version 0 and an unregistered version both miss.
func TestRegistryHasNoLatestVersionLookup(t *testing.T) {
	reg := testRegistry(t)
	if _, ok := reg.Lookup(TypeFieldRedaction, 0); ok {
		t.Error("version 0 resolved to a schema; 0 is not 'latest'")
	}
	if _, ok := reg.Lookup(TypeFieldRedaction, 2); ok {
		t.Error("an unregistered version resolved to a schema")
	}
	if _, ok := reg.Lookup(TypeFieldRedaction, 1); !ok {
		t.Error("the registered version did not resolve")
	}
}

func TestDuplicateSchemaIsRejected(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	s := Schema{Type: "x", Version: 1, Family: FamilyDisclosure, Owner: "o", Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", OnFailure: FailClosed}
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

// TestInitialRegistryDefinesTheNineTypes pins the ADR's initial type list. A
// tenth type is fine, but it must be a deliberate act with this test updated;
// a type quietly REMOVED would silently disarm every policy that names it.
func TestInitialRegistryDefinesTheNineTypes(t *testing.T) {
	reg := testRegistry(t)
	want := []Type{
		TypeApprovalChallenge, TypeFieldRedaction, TypeSchemaConstrainedTransform,
		TypeRouteRestriction, TypeImmutableAudit, TypeNotification,
		TypeQuotaReservation, TypeStepUpAuthentication, TypeResponseFiltering,
	}
	got := map[Type]bool{}
	for _, c := range reg.Capabilities() {
		got[c.Type] = true
	}
	if len(got) != len(want) {
		t.Fatalf("registry defines %d types, want %d: %v", len(got), len(want), reg.Capabilities())
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("type %q is missing from the initial registry", w)
		}
	}
}

// TestInitialRegistryCoversEveryFamilyThatOwnsTypes: six of the seven families
// own at least one type. The seventh, phase ordering, owns none by design.
func TestInitialRegistryCoversEveryFamilyThatOwnsTypes(t *testing.T) {
	reg := testRegistry(t)
	seen := map[Family]bool{}
	for _, c := range reg.Capabilities() {
		s, _ := reg.Lookup(c.Type, c.Version)
		seen[s.Family] = true
	}
	for _, f := range AllFamilies {
		if f == FamilyPhaseOrdering {
			if seen[f] {
				t.Errorf("family %q owns a type; it is a plan-level algebra", f)
			}
			continue
		}
		if !seen[f] {
			t.Errorf("family %q owns no type in the initial registry, so its algebra is never exercised", f)
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
// delivery is durable. Shipping them non-durable would make every mandatory
// audit obligation an automatic deny.
func TestInitialRegistryMandatoryAuditAndNotificationAreDurable(t *testing.T) {
	reg := testRegistry(t)
	for _, tp := range []Type{TypeImmutableAudit, TypeNotification} {
		s, ok := reg.Lookup(tp, 1)
		if !ok {
			t.Fatalf("%s not registered", tp)
		}
		if s.Delivery != DeliveryAtLeastOnceDurable {
			t.Errorf("%s delivery = %q, want %q", tp, s.Delivery, DeliveryAtLeastOnceDurable)
		}
	}
}

// TestInitialRegistryDependenciesAreAcyclic runs the DAG over the full type
// set, not just the subsets the other tests happen to compose.
func TestInitialRegistryDependenciesAreAcyclic(t *testing.T) {
	reg := testRegistry(t)
	var all []Obligation
	for _, c := range reg.Capabilities() {
		all = append(all, Obligation{Type: c.Type, Version: c.Version, Enforcement: Mandatory, Applicability: Applicable})
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
	s, ok := reg.Lookup(TypeApprovalChallenge, 1)
	if !ok {
		t.Fatal("approval_challenge not registered")
	}
	want := map[Type]bool{TypeStepUpAuthentication: true, TypeQuotaReservation: true}
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
	ps, _ := plain.Lookup(TypeApprovalChallenge, 1)
	if len(ps.DependsOn) != 0 {
		t.Fatalf("NewInitialRegistry already carries edges %v; the ordering step is then untested", ps.DependsOn)
	}
}

// TestApprovalExpiryCeilingIsEnforcedBySchema exercises the one place a schema
// is allowed to have an opinion - its own parameters.
func TestApprovalExpiryCeilingIsEnforcedBySchema(t *testing.T) {
	reg := testRegistry(t)
	ob := Obligation{
		Type: TypeApprovalChallenge, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		Params: ApprovalParams{
			AllOf:         []ApprovalClause{{Quorum: 1, Eligible: []string{"Group::r:a"}}},
			ExpirySeconds: 8 * 24 * 60 * 60,
		},
	}
	err := reg.ValidateObligation(ob)
	if err == nil || !strings.Contains(err.Error(), "maximum an approval hold") {
		t.Fatalf("err = %v, want a schema-level expiry refusal", err)
	}
}

// TestParamsFamilyMismatchIsRejected: a schema declaring one family with
// parameters belonging to another would be dispatched to an algebra that
// cannot read them, and the type assertion inside the algebra would be the
// only thing standing between that and a panic.
func TestParamsFamilyMismatchIsRejected(t *testing.T) {
	reg := testRegistry(t)
	err := reg.ValidateObligation(Obligation{
		Type: TypeFieldRedaction, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		Params: RoutingParams{AllowedDestinations: []string{"eu"}},
	})
	if err == nil || !strings.Contains(err.Error(), "family") {
		t.Fatalf("err = %v, want a family mismatch refusal", err)
	}
}

// TestUnsatisfiableApprovalClauseIsRejectedAtAuthoring: a clause whose quorum
// exceeds its distinct eligible set can never be discharged, and would become
// a permanent CHALLENGE nobody can clear.
func TestUnsatisfiableApprovalClauseIsRejectedAtAuthoring(t *testing.T) {
	cases := []ApprovalClause{
		{Quorum: 3, Eligible: []string{"Group::r:a", "Group::r:b"}},
		// Duplicates do not add quorum capacity.
		{Quorum: 2, Eligible: []string{"Group::r:a", "Group::r:a"}},
		{Quorum: 1, Eligible: nil},
		{Quorum: 0, Eligible: []string{"Group::r:a"}},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			if err := c.Validate(); err == nil {
				t.Fatalf("clause %+v must be rejected", c)
			}
		})
	}
}

// TestCanonicalRenderingsRejectTheirOwnSeparators. Every Canonical() in this
// package joins with a separator, and a value containing that separator would
// make two different parameter sets render identically - a digest collision in
// the obligations digest the decision proof binds.
func TestCanonicalRenderingsRejectTheirOwnSeparators(t *testing.T) {
	cases := []struct {
		name string
		p    Params
	}{
		{"disclosure path with a comma", DisclosureParams{Paths: []string{"a,b"}, Transform: Transform{Kind: TransformRemove}}},
		{"disclosure transform param with a semicolon", DisclosureParams{Paths: []string{"a"}, Transform: Transform{Kind: TransformConstantRedact, Params: map[string]string{"c": "x;y"}}}},
		{"approval eligible with a comma", ApprovalParams{AllOf: []ApprovalClause{{Quorum: 1, Eligible: []string{"Group::r:a,b"}}}, ExpirySeconds: 60}},
		{"routing destination with a pipe", RoutingParams{AllowedDestinations: []string{"eu|west"}}},
		{"step-up method with a comma", StepUpParams{MinAssurance: 1, PermittedMethods: []string{"a,b"}}},
		{"budget counter with a colon", BudgetParams{BudgetID: "b", BudgetVersion: 1, Window: "day", Demands: []BudgetDemand{{CounterID: "a:b", Amount: 1, Unit: "u"}}}},
		{"audit address with an at sign", AuditNotifyParams{Targets: []AuditNotifyTarget{{Channel: "c", Address: "a@b", Delivery: DeliveryNone}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.p.Validate(); err == nil {
				t.Fatalf("%T must reject a value containing its own canonical separator; Canonical() = %q", tc.p, tc.p.Canonical())
			}
		})
	}
}

// TestCanonicalRenderingsDistinguishDifferentParameterSets is the property the
// separator rejection exists to protect: two different parameter sets must
// never render the same.
func TestCanonicalRenderingsDistinguishDifferentParameterSets(t *testing.T) {
	pairs := [][2]Params{
		{DisclosureParams{Paths: []string{"a"}, Transform: Transform{Kind: TransformRemove}},
			DisclosureParams{Paths: []string{"b"}, Transform: Transform{Kind: TransformRemove}}},
		{DisclosureParams{Paths: []string{"a"}, Transform: Transform{Kind: TransformConstantRedact, Params: map[string]string{"c": "x"}}},
			DisclosureParams{Paths: []string{"a"}, Transform: Transform{Kind: TransformConstantRedact, Params: map[string]string{"c": "y"}}}},
		{ApprovalParams{AllOf: []ApprovalClause{{Quorum: 1, Eligible: []string{"Group::r:a"}}}, ExpirySeconds: 60},
			ApprovalParams{AllOf: []ApprovalClause{{Quorum: 2, Eligible: []string{"Group::r:a", "Group::r:b"}}}, ExpirySeconds: 60}},
		{RoutingParams{AllowedDestinations: nil, RequiredProperties: map[string][]string{"tls": {"1.3"}}},
			RoutingParams{AllowedDestinations: []string{}, RequiredProperties: map[string][]string{"tls": {"1.3"}}}},
		{BudgetParams{BudgetID: "b", BudgetVersion: 1, Window: "day", Demands: []BudgetDemand{{CounterID: "c", Amount: 1, Unit: "u"}}},
			BudgetParams{BudgetID: "b", BudgetVersion: 2, Window: "day", Demands: []BudgetDemand{{CounterID: "c", Amount: 1, Unit: "u"}}}},
		{AuditNotifyParams{Targets: []AuditNotifyTarget{{Channel: "c", Address: "a", Delivery: DeliveryNone}}},
			AuditNotifyParams{Targets: []AuditNotifyTarget{{Channel: "c", Address: "a", Delivery: DeliveryAtLeastOnceDurable}}}},
	}
	for i, p := range pairs {
		if p[0].Canonical() == p[1].Canonical() {
			t.Errorf("pair %d renders identically: %q", i, p[0].Canonical())
		}
	}
}

// TestCanonicalRenderingIsOrderIndependent: two obligations that differ only
// in the order a caller listed a collection must produce the same digest, or
// the same policy would bind two different proofs.
func TestCanonicalRenderingIsOrderIndependent(t *testing.T) {
	a := DisclosureParams{Paths: []string{"b", "a"}, Transform: Transform{Kind: TransformRemove}}
	b := DisclosureParams{Paths: []string{"a", "b"}, Transform: Transform{Kind: TransformRemove}}
	if a.Canonical() != b.Canonical() {
		t.Errorf("path order changed the canonical rendering: %q vs %q", a.Canonical(), b.Canonical())
	}
	c := AuditNotifyParams{Targets: []AuditNotifyTarget{{Channel: "b", Address: "1", Delivery: DeliveryNone}, {Channel: "a", Address: "2", Delivery: DeliveryNone}}}
	d := AuditNotifyParams{Targets: []AuditNotifyTarget{{Channel: "a", Address: "2", Delivery: DeliveryNone}, {Channel: "b", Address: "1", Delivery: DeliveryNone}}}
	if c.Canonical() != d.Canonical() {
		t.Errorf("target order changed the canonical rendering: %q vs %q", c.Canonical(), d.Canonical())
	}
}

// TestDisclosureRankZeroValueIsNotRemove is the trap the closed switch in
// disclosureRank avoids: with a map, an unregistered kind would return the
// zero value 0, which is `remove` - the LEAST disclosing rank. A typo would
// have become the strongest possible claim and won every comparison.
func TestDisclosureRankZeroValueIsNotRemove(t *testing.T) {
	if got := disclosureRank(TransformKind("typo_redact")); got != -1 {
		t.Fatalf("disclosureRank(unknown) = %d, want -1 (incomparable). 0 is `remove`, so an unknown kind would win every comparison.", got)
	}
	if disclosureRank(TransformRemove) != 0 {
		t.Fatal("remove is expected to be rank 0; if that changes, re-check the assertion above")
	}
	if TransformKind("typo_redact").Comparable() {
		t.Fatal("an unknown transform kind must not be comparable")
	}
}
