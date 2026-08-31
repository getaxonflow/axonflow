// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func disclosure(policyID string, transform Transform, paths ...string) Obligation {
	return Obligation{
		Type: TypeFieldRedaction, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		SourcePolicyID: policyID,
		Params:         DisclosureParams{Paths: paths, Transform: transform},
	}
}

func mustCompose(t *testing.T, reg *Registry, leaf LeafResolver, obs ...Obligation) ComposedPlan {
	t.Helper()
	p, err := Compose(reg, leaf, obs)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	return p
}

func composeConflict(t *testing.T, reg *Registry, leaf LeafResolver, obs ...Obligation) *ConflictError {
	t.Helper()
	_, err := Compose(reg, leaf, obs)
	if err == nil {
		t.Fatalf("compose: want a conflict, got nil")
	}
	var c *ConflictError
	if !errors.As(err, &c) {
		t.Fatalf("compose: want *ConflictError, got %T: %v", err, err)
	}
	return c
}

// ---------------------------------------------------------------------------
// Disclosure: broad and narrow paths, per leaf, without revealing more data
// ---------------------------------------------------------------------------

// TestBroadRedactPlusNarrowHashResolvesPerLeaf is ADR-065's named case and its
// mirror. The property that must hold in BOTH directions is that no leaf ends
// up with a transform that reveals more than some policy asked for.
//
// Universe: user.name, user.ssn.
//
//	Broad `user` -> constant_redact, narrow `user.ssn` -> one_way_derived:
//	  user.name gets constant_redact (only claim)
//	  user.ssn  gets constant_redact (constant_redact < one_way_derived)
//	The narrow HASH does not weaken the broad REDACT. That is the direction
//	that matters: a hash leaks equality, a constant does not.
//
//	Mirror - broad `user` -> one_way_derived, narrow `user.ssn` -> constant_redact:
//	  user.name gets one_way_derived
//	  user.ssn  gets constant_redact  (the narrow rule is STRICTER, so it wins
//	                                   on its own leaf and only on its own leaf)
//
// The mirror is the case a naive "narrow overrides broad" or "last writer
// wins" implementation gets wrong in one direction or the other; per-leaf
// least-disclosing gets both right for the same reason.
func TestBroadRedactPlusNarrowHashResolvesPerLeaf(t *testing.T) {
	reg := testRegistry(t)
	leaf := StaticLeafResolver{Universe: []string{"user.name", "user.ssn"}}

	t.Run("broad redact, narrow hash", func(t *testing.T) {
		plan := mustCompose(t, reg, leaf,
			disclosure("broad", Transform{Kind: TransformConstantRedact}, "user"),
			disclosure("narrow", Transform{Kind: TransformOneWayDerived}, "user.ssn"),
		)
		want := map[string]TransformKind{
			"user.name": TransformConstantRedact,
			"user.ssn":  TransformConstantRedact,
		}
		assertDisclosure(t, plan, want)
	})

	t.Run("mirror: broad hash, narrow redact", func(t *testing.T) {
		plan := mustCompose(t, reg, leaf,
			disclosure("broad", Transform{Kind: TransformOneWayDerived}, "user"),
			disclosure("narrow", Transform{Kind: TransformConstantRedact}, "user.ssn"),
		)
		want := map[string]TransformKind{
			"user.name": TransformOneWayDerived,
			"user.ssn":  TransformConstantRedact,
		}
		assertDisclosure(t, plan, want)
	})

	t.Run("order of the obligations does not change the answer", func(t *testing.T) {
		a := mustCompose(t, reg, leaf,
			disclosure("broad", Transform{Kind: TransformConstantRedact}, "user"),
			disclosure("narrow", Transform{Kind: TransformOneWayDerived}, "user.ssn"),
		)
		b := mustCompose(t, reg, leaf,
			disclosure("narrow", Transform{Kind: TransformOneWayDerived}, "user.ssn"),
			disclosure("broad", Transform{Kind: TransformConstantRedact}, "user"),
		)
		if !reflect.DeepEqual(a.Disclosure, b.Disclosure) {
			t.Fatalf("composition is order-dependent:\n a=%v\n b=%v", a.Disclosure, b.Disclosure)
		}
	})
}

func assertDisclosure(t *testing.T, plan ComposedPlan, want map[string]TransformKind) {
	t.Helper()
	if len(plan.Disclosure) != len(want) {
		t.Fatalf("disclosure covers %d leaves, want %d: %v", len(plan.Disclosure), len(want), plan.Disclosure)
	}
	for leaf, kind := range want {
		got, ok := plan.Disclosure[leaf]
		if !ok {
			t.Errorf("leaf %q has no transform; an uncovered leaf is released unchanged", leaf)
			continue
		}
		if got.Kind != kind {
			t.Errorf("leaf %q got %s, want %s", leaf, got.Kind, kind)
		}
	}
}

// TestUnchangedIsTheTopOfTheOrder: a policy explicitly asking for `unchanged`
// must never beat a policy asking for anything else.
func TestUnchangedIsTheTopOfTheOrder(t *testing.T) {
	reg := testRegistry(t)
	leaf := StaticLeafResolver{Universe: []string{"user.ssn"}}
	plan := mustCompose(t, reg, leaf,
		disclosure("permissive", Transform{Kind: TransformUnchanged}, "user.ssn"),
		disclosure("strict", Transform{Kind: TransformPartialReveal, Params: map[string]string{"reveal": "last4"}}, "user.ssn"),
	)
	if got := plan.Disclosure["user.ssn"].Kind; got != TransformPartialReveal {
		t.Fatalf("got %s, want %s: `unchanged` must never win", got, TransformPartialReveal)
	}
}

// TestRemoveBeatsEveryComparableKindWhateverItsParameters pins the rule that a
// strictly less-disclosing KIND subsumes a more-disclosing one under any
// parameterisation. Without it, `remove` vs `partial_reveal(last4)` would look
// like a parameter conflict and deny for no reason.
func TestRemoveBeatsEveryComparableKindWhateverItsParameters(t *testing.T) {
	reg := testRegistry(t)
	leaf := StaticLeafResolver{Universe: []string{"x"}}
	for _, other := range []Transform{
		{Kind: TransformConstantRedact, Params: map[string]string{"const": "***"}},
		{Kind: TransformOneWayDerived, Params: map[string]string{"alg": "sha256"}},
		{Kind: TransformPartialReveal, Params: map[string]string{"reveal": "last4"}},
		{Kind: TransformUnchanged},
	} {
		plan := mustCompose(t, reg, leaf,
			disclosure("a", Transform{Kind: TransformRemove}, "x"),
			disclosure("b", other, "x"),
		)
		if got := plan.Disclosure["x"].Kind; got != TransformRemove {
			t.Errorf("remove vs %s: got %s, want remove", other.Canonical(), got)
		}
	}
}

// TestSameKindWithIncompatibleParametersDenies: two partial_reveals with
// different windows each reveal something the other hides. Picking either
// would silently discard a requirement policy's instruction.
func TestSameKindWithIncompatibleParametersDenies(t *testing.T) {
	reg := testRegistry(t)
	leaf := StaticLeafResolver{Universe: []string{"card.number"}}
	c := composeConflict(t, reg, leaf,
		disclosure("a", Transform{Kind: TransformPartialReveal, Params: map[string]string{"reveal": "last4"}}, "card.number"),
		disclosure("b", Transform{Kind: TransformPartialReveal, Params: map[string]string{"reveal": "first6"}}, "card.number"),
	)
	if c.Family != FamilyDisclosure || c.Subject != "card.number" {
		t.Fatalf("conflict = %+v, want a disclosure conflict on card.number", c)
	}
	if !strings.Contains(c.Detail, "last4") || !strings.Contains(c.Detail, "first6") {
		t.Errorf("the conflict must name both transforms; detail=%q", c.Detail)
	}
}

// TestAmbiguousLoserDoesNotDeny is the other half of the rule above: two
// incompatible partial_reveals only conflict if partial_reveal is what WINS.
// With a `remove` also present, removing the leaf discharges all three, so
// denying would be a refusal with no cause.
func TestAmbiguousLoserDoesNotDeny(t *testing.T) {
	reg := testRegistry(t)
	leaf := StaticLeafResolver{Universe: []string{"card.number"}}
	plan := mustCompose(t, reg, leaf,
		disclosure("a", Transform{Kind: TransformPartialReveal, Params: map[string]string{"reveal": "last4"}}, "card.number"),
		disclosure("b", Transform{Kind: TransformPartialReveal, Params: map[string]string{"reveal": "first6"}}, "card.number"),
		disclosure("c", Transform{Kind: TransformRemove}, "card.number"),
	)
	if got := plan.Disclosure["card.number"].Kind; got != TransformRemove {
		t.Fatalf("got %s, want remove", got)
	}
}

// TestIncomparableTransformKindsDeny: reversible encryption, tokenization and
// format changes do not sit on an order whose meaning is "what a reader
// learns", so nothing may pick between them.
func TestIncomparableTransformKindsDeny(t *testing.T) {
	reg := testRegistry(t)
	leaf := StaticLeafResolver{Universe: []string{"x"}}
	for _, k := range []TransformKind{TransformReversibleEncrypt, TransformTokenize, TransformFormatChange} {
		c := composeConflict(t, reg, leaf,
			disclosure("a", Transform{Kind: k}, "x"),
			disclosure("b", Transform{Kind: TransformConstantRedact}, "x"),
		)
		if c.Family != FamilyDisclosure {
			t.Errorf("%s: family=%s, want %s", k, c.Family, FamilyDisclosure)
		}
		if !strings.Contains(c.Detail, "no reviewed subsumption rule") {
			t.Errorf("%s: the deny must say the escape hatch exists and was not taken; detail=%q", k, c.Detail)
		}
	}
}

// TestReviewedSubsumptionRuleResolvesAnIncomparablePair is the registry-owned
// escape hatch ADR-065 permits. It lives on the REGISTRY, so a schema or a
// policy cannot mint one.
func TestReviewedSubsumptionRuleResolvesAnIncomparablePair(t *testing.T) {
	base := testRegistry(t)
	b := NewRegistryBuilder("test.v1")
	for _, c := range base.Capabilities() {
		s, _ := base.Lookup(c.Type, c.Version)
		b.Add(s)
	}
	b.AddSubsumption(SubsumptionRule{
		Weaker:   Transform{Kind: TransformTokenize}.Canonical(),
		Stronger: Transform{Kind: TransformRemove}.Canonical(),
		Reason:   "reviewed 2026-08-30: removal discloses strictly less than a reversible token",
	})
	reg, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	leaf := StaticLeafResolver{Universe: []string{"x"}}
	plan := mustCompose(t, reg, leaf,
		disclosure("a", Transform{Kind: TransformTokenize}, "x"),
		disclosure("b", Transform{Kind: TransformRemove}, "x"),
	)
	if got := plan.Disclosure["x"].Kind; got != TransformRemove {
		t.Fatalf("got %s, want remove via the reviewed rule", got)
	}
}

func TestSubsumptionRuleWithoutAReviewReasonIsRejected(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.AddSubsumption(SubsumptionRule{Weaker: "tokenize", Stronger: "remove"})
	if _, err := b.Build(); err == nil {
		t.Fatal("a subsumption rule with no recorded review reason must be rejected: an unexplained rule is an unreviewed one")
	}
}

func TestSubsumptionCycleIsRejected(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.AddSubsumption(SubsumptionRule{Weaker: "a", Stronger: "b", Reason: "r"})
	b.AddSubsumption(SubsumptionRule{Weaker: "b", Stronger: "a", Reason: "r"})
	if _, err := b.Build(); err == nil {
		t.Fatal("a subsumption cycle must be rejected: it makes the winner depend on iteration order")
	}
}

// TestUnresolvableFieldPathDenies: a path the resolver cannot expand is UNKNOWN,
// not empty. The source spec would have expanded it to nothing and applied no
// transform, which is a silent disclosure.
func TestUnresolvableFieldPathDenies(t *testing.T) {
	reg := testRegistry(t)
	leaf := StaticLeafResolver{Universe: []string{"user.name"}}
	c := composeConflict(t, reg, leaf, disclosure("a", Transform{Kind: TransformRemove}, "account.balance"))
	if c.Subject != "account.balance" {
		t.Fatalf("conflict subject = %q, want the unresolvable path", c.Subject)
	}
}

// TestNoLeafResolverDenies: a disclosure obligation with nothing to normalize
// against must deny rather than compose to an empty transform set.
func TestNoLeafResolverDenies(t *testing.T) {
	reg := testRegistry(t)
	c := composeConflict(t, reg, nil, disclosure("a", Transform{Kind: TransformRemove}, "user"))
	if c.Family != FamilyDisclosure {
		t.Fatalf("family=%s, want %s", c.Family, FamilyDisclosure)
	}
}

// ---------------------------------------------------------------------------
// Approval: the conjunction that must not be flattened
// ---------------------------------------------------------------------------

// TestApprovalClausesAreNeverFlattened is the correction ADR-065 makes to the
// source spec's pool-intersection meet. Under intersection,
// 2-of-{A,B} MEET 2-of-{B,C} becomes 2-of-{B}, which is unsatisfiable and
// would deny a request {A,B,C} can plainly approve.
func TestApprovalClausesAreNeverFlattened(t *testing.T) {
	reg := testRegistry(t)
	c1 := ApprovalClause{Quorum: 2, Eligible: []string{"User::r:A", "User::r:B"}}
	c2 := ApprovalClause{Quorum: 2, Eligible: []string{"User::r:B", "User::r:C"}}

	plan := mustCompose(t, reg, nil, Obligation{
		Type: TypeApprovalChallenge, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		SourcePolicyID: "p1",
		Params:         ApprovalParams{AllOf: []ApprovalClause{c1, c2}, ExpirySeconds: 3600},
	})

	if len(plan.ApprovalClauses) != 2 {
		t.Fatalf("got %d clauses, want 2. Flattening two threshold clauses into one pool is the mathematical error ADR-065 corrects: %+v",
			len(plan.ApprovalClauses), plan.ApprovalClauses)
	}
	// Neither clause may have had its pool narrowed.
	pools := map[string]int{}
	for _, c := range plan.ApprovalClauses {
		pools[strings.Join(c.Eligible, ",")] = c.Quorum
	}
	if q, ok := pools["User::r:A,User::r:B"]; !ok || q != 2 {
		t.Errorf("clause 2-of-{A,B} was altered; got pools %v", pools)
	}
	if q, ok := pools["User::r:B,User::r:C"]; !ok || q != 2 {
		t.Errorf("clause 2-of-{B,C} was altered; got pools %v", pools)
	}
}

// TestIdenticalApprovalClausesDeduplicateWithoutFlattening: two requirement
// policies demanding the same clause must not double the quorum, and must not
// merge the pools of DIFFERENT clauses either.
func TestIdenticalApprovalClausesDeduplicateWithoutFlattening(t *testing.T) {
	reg := testRegistry(t)
	same := ApprovalClause{Quorum: 2, Eligible: []string{"Group::r:sec"}}
	plan := mustCompose(t, reg, nil,
		Obligation{Type: TypeApprovalChallenge, Version: 1, Enforcement: Mandatory, Applicability: Applicable, SourcePolicyID: "p1",
			Params: ApprovalParams{AllOf: []ApprovalClause{same}, ExpirySeconds: 3600}},
		Obligation{Type: TypeApprovalChallenge, Version: 1, Enforcement: Mandatory, Applicability: Applicable, SourcePolicyID: "p2",
			Params: ApprovalParams{AllOf: []ApprovalClause{same}, ExpirySeconds: 3600}},
	)
	if len(plan.ApprovalClauses) != 1 {
		t.Fatalf("identical clauses must deduplicate; got %+v", plan.ApprovalClauses)
	}
	if plan.ApprovalClauses[0].Quorum != 2 {
		t.Fatalf("deduplication must not change the quorum; got %d", plan.ApprovalClauses[0].Quorum)
	}
}

// TestApprovalCompositionTakesTheShortestExpiryAndStrictestSoD: the permissive
// direction on either would let one lax policy disarm a strict one.
func TestApprovalCompositionTakesTheShortestExpiryAndStrictestSoD(t *testing.T) {
	reg := testRegistry(t)
	plan := mustCompose(t, reg, nil,
		Obligation{Type: TypeApprovalChallenge, Version: 1, Enforcement: Mandatory, Applicability: Applicable, SourcePolicyID: "lax",
			Params: ApprovalParams{AllOf: []ApprovalClause{{Quorum: 1, Eligible: []string{"Group::r:a"}}}, ExpirySeconds: 86400, SeparationOfDuties: false}},
		Obligation{Type: TypeApprovalChallenge, Version: 1, Enforcement: Mandatory, Applicability: Applicable, SourcePolicyID: "strict",
			Params: ApprovalParams{AllOf: []ApprovalClause{{Quorum: 1, Eligible: []string{"Group::r:b"}}}, ExpirySeconds: 600, SeparationOfDuties: true}},
	)
	if plan.ApprovalExpirySeconds != 600 {
		t.Errorf("expiry = %d, want 600 (the shortest); extending a challenge past a policy's timeout is the permissive direction", plan.ApprovalExpirySeconds)
	}
	if !plan.SeparationOfDuties {
		t.Error("separation of duties must hold if ANY policy demands it")
	}
}

// ---------------------------------------------------------------------------
// Routing, step-up, budget, audit
// ---------------------------------------------------------------------------

func routing(policyID string, dests []string, props map[string][]string) Obligation {
	return Obligation{Type: TypeRouteRestriction, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		SourcePolicyID: policyID, Params: RoutingParams{AllowedDestinations: dests, RequiredProperties: props}}
}

func TestRoutingIntersectsAndAnEmptyIntersectionDenies(t *testing.T) {
	reg := testRegistry(t)
	plan := mustCompose(t, reg, nil,
		routing("a", []string{"eu-west", "eu-central", "us-east"}, nil),
		routing("b", []string{"eu-central", "us-east"}, nil),
	)
	if !reflect.DeepEqual(plan.RoutingDestinations, []string{"eu-central", "us-east"}) {
		t.Fatalf("destinations = %v, want the intersection", plan.RoutingDestinations)
	}

	c := composeConflict(t, reg, nil,
		routing("a", []string{"eu-west"}, nil),
		routing("b", []string{"us-east"}, nil),
	)
	if c.Subject != "destinations" {
		t.Fatalf("conflict = %+v, want an empty-destination-intersection conflict", c)
	}
}

func TestRoutingPropertiesIntersectPerKey(t *testing.T) {
	reg := testRegistry(t)
	plan := mustCompose(t, reg, nil,
		routing("a", nil, map[string][]string{"tls": {"1.2", "1.3"}, "region": {"eu"}}),
		routing("b", nil, map[string][]string{"tls": {"1.3"}}),
	)
	if !reflect.DeepEqual(plan.RoutingProperties["tls"], []string{"1.3"}) {
		t.Errorf("tls = %v, want [1.3]", plan.RoutingProperties["tls"])
	}
	// A key only one obligation mentions is unconstrained by the other, not
	// intersected to empty.
	if !reflect.DeepEqual(plan.RoutingProperties["region"], []string{"eu"}) {
		t.Errorf("region = %v, want [eu]", plan.RoutingProperties["region"])
	}

	c := composeConflict(t, reg, nil,
		routing("a", nil, map[string][]string{"tls": {"1.2"}}),
		routing("b", nil, map[string][]string{"tls": {"1.3"}}),
	)
	if c.Subject != "tls" {
		t.Fatalf("conflict = %+v, want a tls property conflict", c)
	}
}

// TestNilDestinationsMeansUnconstrainedNotEmpty pins the distinction that
// would otherwise turn "this obligation places no destination constraint" into
// "no destination is allowed", denying every request that carries an
// unrelated routing obligation.
func TestNilDestinationsMeansUnconstrainedNotEmpty(t *testing.T) {
	reg := testRegistry(t)
	plan := mustCompose(t, reg, nil,
		routing("a", []string{"eu-west"}, nil),
		routing("b", nil, map[string][]string{"tls": {"1.3"}}),
	)
	if !reflect.DeepEqual(plan.RoutingDestinations, []string{"eu-west"}) {
		t.Fatalf("destinations = %v, want [eu-west]", plan.RoutingDestinations)
	}
}

func stepUp(policyID string, assurance int, methods []string) Obligation {
	return Obligation{Type: TypeStepUpAuthentication, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		SourcePolicyID: policyID, Params: StepUpParams{MinAssurance: assurance, PermittedMethods: methods}}
}

func TestStepUpTakesTheMaximumAssuranceAndIntersectsMethods(t *testing.T) {
	reg := testRegistry(t)
	plan := mustCompose(t, reg, nil,
		stepUp("a", 2, []string{"webauthn", "totp"}),
		stepUp("b", 3, []string{"webauthn", "push"}),
	)
	if plan.StepUpAssurance != 3 {
		t.Errorf("assurance = %d, want 3 (the maximum)", plan.StepUpAssurance)
	}
	if !reflect.DeepEqual(plan.StepUpMethods, []string{"webauthn"}) {
		t.Errorf("methods = %v, want [webauthn]", plan.StepUpMethods)
	}

	c := composeConflict(t, reg, nil, stepUp("a", 2, []string{"totp"}), stepUp("b", 2, []string{"push"}))
	if c.Subject != "methods" {
		t.Fatalf("conflict = %+v, want an empty-method-intersection conflict", c)
	}
}

func budget(policyID string, demands ...BudgetDemand) Obligation {
	return Obligation{Type: TypeQuotaReservation, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		SourcePolicyID: policyID,
		Params:         BudgetParams{BudgetID: "b1", BudgetVersion: 1, Window: "day", Demands: demands}}
}

// TestBudgetDemandsOnTheSameCounterAreSummedNotMaxed: two requirement policies
// each needing capacity both need it. Taking the maximum would let the second
// ride on the first's reservation for free.
func TestBudgetDemandsOnTheSameCounterAreSummed(t *testing.T) {
	reg := testRegistry(t)
	plan := mustCompose(t, reg, nil,
		budget("a", BudgetDemand{CounterID: "tokens", Amount: 100, Unit: "tokens"}),
		budget("b", BudgetDemand{CounterID: "tokens", Amount: 250, Unit: "tokens"}),
	)
	if len(plan.BudgetDemands) != 1 || plan.BudgetDemands[0].Amount != 350 {
		t.Fatalf("demands = %+v, want one demand of 350", plan.BudgetDemands)
	}
}

func TestBudgetDemandsOnOneCounterInTwoUnitsDeny(t *testing.T) {
	reg := testRegistry(t)
	c := composeConflict(t, reg, nil,
		budget("a", BudgetDemand{CounterID: "spend", Amount: 100, Unit: "usd_cents"}),
		budget("b", BudgetDemand{CounterID: "spend", Amount: 100, Unit: "eur_cents"}),
	)
	if c.Family != FamilyBudget {
		t.Fatalf("conflict = %+v, want a budget conflict", c)
	}
	if !strings.Contains(c.Detail, "versioned rate") {
		t.Errorf("the deny should say where conversion belongs; detail=%q", c.Detail)
	}
}

func audit(policyID string, targets ...AuditNotifyTarget) Obligation {
	return Obligation{Type: TypeImmutableAudit, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		SourcePolicyID: policyID, Params: AuditNotifyParams{Targets: targets}}
}

// TestAuditTargetsUnionAndTakeTheStrongestGuarantee: the same sink asked for
// twice is ONE target carrying the stronger guarantee - not two deliveries.
func TestAuditTargetsUnionAndTakeTheStrongestGuarantee(t *testing.T) {
	reg := testRegistry(t)
	plan := mustCompose(t, reg, nil,
		audit("a", AuditNotifyTarget{Channel: "siem", Address: "sink1", Delivery: DeliveryNone}),
		audit("b", AuditNotifyTarget{Channel: "siem", Address: "sink1", Delivery: DeliveryAtLeastOnceDurable}),
		audit("c", AuditNotifyTarget{Channel: "siem", Address: "sink2", Delivery: DeliveryNone}),
	)
	if len(plan.AuditTargets) != 2 {
		t.Fatalf("targets = %+v, want 2 after deduplication", plan.AuditTargets)
	}
	for _, tgt := range plan.AuditTargets {
		if tgt.Address == "sink1" && tgt.Delivery != DeliveryAtLeastOnceDurable {
			t.Errorf("sink1 delivery = %q, want the stronger guarantee", tgt.Delivery)
		}
	}
}

// ---------------------------------------------------------------------------
// Phase ordering
// ---------------------------------------------------------------------------

// TestPhaseOrderPutsDependenciesFirst: step-up and reservation must precede
// the approval challenge. Asking a human to approve before the session reached
// the required assurance collects an approval from a weakly-authenticated
// principal; asking before capacity is reserved holds an option on capacity
// someone else may take.
func TestPhaseOrderPutsDependenciesFirst(t *testing.T) {
	reg := testRegistry(t)
	plan := mustCompose(t, reg, nil,
		Obligation{Type: TypeApprovalChallenge, Version: 1, Enforcement: Mandatory, Applicability: Applicable, SourcePolicyID: "p",
			Params: ApprovalParams{AllOf: []ApprovalClause{{Quorum: 1, Eligible: []string{"Group::r:a"}}}, ExpirySeconds: 600}},
		stepUp("s", 2, nil),
		budget("b", BudgetDemand{CounterID: "calls", Amount: 1, Unit: "calls"}),
	)
	pos := map[Type]int{}
	for i, tp := range plan.Order {
		pos[tp] = i
	}
	if pos[TypeStepUpAuthentication] > pos[TypeApprovalChallenge] {
		t.Errorf("step-up must precede approval; order = %v", plan.Order)
	}
	if pos[TypeQuotaReservation] > pos[TypeApprovalChallenge] {
		t.Errorf("reservation must precede approval; order = %v", plan.Order)
	}
}

func TestPhaseOrderCycleDenies(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: TypeFieldRedaction, Version: 1, Family: FamilyDisclosure, Owner: "o",
		Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", OnFailure: FailClosed, DependsOn: []Type{TypeResponseFiltering}})
	b.Add(Schema{Type: TypeResponseFiltering, Version: 1, Family: FamilyDisclosure, Owner: "o",
		Phases: []Phase{PhaseResponse}, CompletionEvidence: "e", OnFailure: FailClosed, DependsOn: []Type{TypeFieldRedaction}})
	reg, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	leaf := StaticLeafResolver{Universe: []string{"x"}}
	c := composeConflict(t, reg, leaf,
		disclosure("a", Transform{Kind: TransformRemove}, "x"),
		Obligation{Type: TypeResponseFiltering, Version: 1, Enforcement: Mandatory, Applicability: Applicable, SourcePolicyID: "b",
			Params: DisclosureParams{Paths: []string{"x"}, Transform: Transform{Kind: TransformRemove}}},
	)
	if c.Family != FamilyPhaseOrdering {
		t.Fatalf("conflict = %+v, want a phase-ordering conflict", c)
	}
}

// TestPhaseOrderIgnoresAbsentDependencies: nothing has to run before something
// that is not running. A dependency on an absent type must not deny.
func TestPhaseOrderIgnoresAbsentDependencies(t *testing.T) {
	reg := testRegistry(t)
	plan := mustCompose(t, reg, nil,
		Obligation{Type: TypeApprovalChallenge, Version: 1, Enforcement: Mandatory, Applicability: Applicable, SourcePolicyID: "p",
			Params: ApprovalParams{AllOf: []ApprovalClause{{Quorum: 1, Eligible: []string{"Group::r:a"}}}, ExpirySeconds: 600}},
	)
	if !reflect.DeepEqual(plan.Order, []Type{TypeApprovalChallenge}) {
		t.Fatalf("order = %v, want just the approval challenge", plan.Order)
	}
}

// TestPhaseOrderIsDeterministic: a trace diffed between two runs must be
// comparable, so ties are broken by name rather than by map iteration order.
func TestPhaseOrderIsDeterministic(t *testing.T) {
	reg := testRegistry(t)
	obs := []Obligation{
		stepUp("s", 2, nil),
		budget("b", BudgetDemand{CounterID: "calls", Amount: 1, Unit: "calls"}),
		audit("a", AuditNotifyTarget{Channel: "siem", Address: "s1", Delivery: DeliveryAtLeastOnceDurable}),
	}
	first, err := composePhaseOrder(reg, obs)
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	for i := 0; i < 50; i++ {
		got, err := composePhaseOrder(reg, obs)
		if err != nil {
			t.Fatalf("order: %v", err)
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("phase order is not deterministic: %v vs %v", got, first)
		}
	}
}

// ---------------------------------------------------------------------------
// Structural guards on the algebra dispatch
// ---------------------------------------------------------------------------

// TestEveryFamilyHasExactlyOneAlgebra pins the ADR's "one algebra per family"
// against both directions of drift: a family with no algebra (Compose would
// deny every plan containing it) and an algebra for a family that is not in
// AllFamilies (Compose iterates AllFamilies, so it would never run).
func TestEveryFamilyHasExactlyOneAlgebra(t *testing.T) {
	if len(familyAlgebras) != len(AllFamilies) {
		t.Fatalf("%d algebras for %d families", len(familyAlgebras), len(AllFamilies))
	}
	for _, f := range AllFamilies {
		if _, ok := familyAlgebras[f]; !ok {
			t.Errorf("family %q has no algebra", f)
		}
	}
	seen := map[Family]struct{}{}
	for _, f := range AllFamilies {
		if _, dup := seen[f]; dup {
			t.Errorf("family %q listed twice in AllFamilies", f)
		}
		seen[f] = struct{}{}
	}
	for f := range familyAlgebras {
		if _, ok := seen[f]; !ok {
			t.Errorf("algebra registered for %q, which is not in AllFamilies and would never run", f)
		}
	}
}

// TestNoNumericRankingAcrossFamilies: the only ordering in this package is the
// disclosure order (within one family, over one property) and the delivery
// guarantee rank (likewise). Nothing compares obligations of DIFFERENT
// families, which is the `block > redact > warn > log` scale ADR-065 deletes.
//
// The check is behavioural, not a source scan: composing one obligation of
// every family must produce a plan that retains ALL of them. A severity
// ranking would have discarded the "less severe" ones.
func TestNoNumericRankingAcrossFamilies(t *testing.T) {
	reg := testRegistry(t)
	leaf := StaticLeafResolver{Universe: []string{"user.ssn"}}
	plan := mustCompose(t, reg, leaf,
		disclosure("d", Transform{Kind: TransformRemove}, "user.ssn"),
		Obligation{Type: TypeApprovalChallenge, Version: 1, Enforcement: Mandatory, Applicability: Applicable, SourcePolicyID: "p",
			Params: ApprovalParams{AllOf: []ApprovalClause{{Quorum: 1, Eligible: []string{"Group::r:a"}}}, ExpirySeconds: 600}},
		routing("r", []string{"eu"}, nil),
		stepUp("s", 2, nil),
		budget("b", BudgetDemand{CounterID: "calls", Amount: 1, Unit: "calls"}),
		audit("a", AuditNotifyTarget{Channel: "siem", Address: "s1", Delivery: DeliveryAtLeastOnceDurable}),
	)
	if len(plan.Disclosure) == 0 {
		t.Error("the disclosure transform was discarded")
	}
	if len(plan.ApprovalClauses) == 0 {
		t.Error("the approval clause was discarded")
	}
	if len(plan.RoutingDestinations) == 0 {
		t.Error("the routing restriction was discarded")
	}
	if plan.StepUpAssurance == 0 {
		t.Error("the step-up requirement was discarded")
	}
	if len(plan.BudgetDemands) == 0 {
		t.Error("the budget demand was discarded")
	}
	if len(plan.AuditTargets) == 0 {
		t.Error("the audit target was discarded")
	}
	if len(plan.Order) != 6 {
		got := make([]string, 0, len(plan.Order))
		for _, o := range plan.Order {
			got = append(got, string(o))
		}
		sort.Strings(got)
		t.Errorf("order covers %d types, want 6: %v", len(plan.Order), got)
	}
}
