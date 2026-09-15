// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// These tests drive the ONE algebra through the planner and assert LITERAL
// results. They are what makes "the planner consumes contract.ComposeObligations"
// a checkable claim rather than a comment: every expectation here is the same
// literal the contract golden table pins, reached through Plan. None reads
// the expected value back from the algebra.

// render is the planner-side rendering of a composed instruction, written to
// match the literals in contract's golden table: `type target binding sources
// params`.
func render(o contract.Obligation) string {
	binding := "advisory"
	if o.Mandatory {
		binding = "mandatory"
	}
	target := o.Target
	if target == "" {
		target = "-"
	}
	keys := make([]string, 0, len(o.Params))
	for k := range o.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+o.Params[k])
	}
	params := strings.Join(parts, ";")
	if params == "" {
		params = "-"
	}
	return fmt.Sprintf("%s %s %s %s %s", o.Type, target, binding, o.SourcePolicy, params)
}

func renderPlan(p ComposedPlan) []string {
	out := make([]string, 0, len(p.Obligations))
	for _, o := range p.Obligations {
		out = append(out, render(o))
	}
	return out
}

func mustPlan(t *testing.T, reg *Registry, payload contract.PayloadLeaves, obs ...Obligation) PlanResult {
	t.Helper()
	res := Plan(PlanInput{
		Registry: reg, Payload: payload, Obligations: obs, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg),
		ApprovalExpiry: testNow.Add(time.Hour), Now: testNow,
	})
	if res.Outcome != OutcomeAllow {
		t.Fatalf("outcome=%q, want ALLOW; reasons=%v details=%v", res.Outcome, res.Reasons, res.Details)
	}
	return res
}

func mustDeny(t *testing.T, reg *Registry, payload contract.PayloadLeaves, obs ...Obligation) PlanResult {
	t.Helper()
	res := Plan(PlanInput{
		Registry: reg, Payload: payload, Obligations: obs, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg),
		ApprovalExpiry: testNow.Add(time.Hour), Now: testNow,
	})
	if res.Outcome != OutcomeDeny {
		t.Fatalf("outcome=%q, want DENY; reasons=%v details=%v", res.Outcome, res.Reasons, res.Details)
	}
	return res
}

func wantPlan(t *testing.T, got ComposedPlan, want ...string) {
	t.Helper()
	if g := renderPlan(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("plan =\n  %s\nwant\n  %s", strings.Join(g, "\n  "), strings.Join(want, "\n  "))
	}
}

// ---------------------------------------------------------------------------
// Disclosure: broad and narrow paths, per leaf, without revealing more data
// ---------------------------------------------------------------------------

// TestBroadRedactPlusNarrowHashResolvesPerLeaf is ADR-065's named case and its
// mirror. The property that must hold in BOTH directions is that no leaf ends
// up with a transform that reveals more than some policy asked for.
func TestBroadRedactPlusNarrowHashResolvesPerLeaf(t *testing.T) {
	reg := testRegistry(t)
	payload := contract.KnownPayloadLeaves("user.name", "user.ssn")

	t.Run("broad redact, narrow hash", func(t *testing.T) {
		res := mustPlan(t, reg, payload,
			redact("broad", "user"),
			canon(contract.ObFieldHash, "user.ssn", true, "narrow", nil),
		)
		wantPlan(t, res.Plan,
			"field_redact user.name mandatory broad -",
			"field_redact user.ssn mandatory broad,narrow -",
		)
	})

	t.Run("mirror: broad hash, narrow redact", func(t *testing.T) {
		res := mustPlan(t, reg, payload,
			canon(contract.ObFieldHash, "user", true, "broad", nil),
			redact("narrow", "user.ssn"),
		)
		wantPlan(t, res.Plan,
			"field_hash user.name mandatory broad -",
			"field_redact user.ssn mandatory broad,narrow -",
		)
	})

	t.Run("order of the obligations does not change the answer", func(t *testing.T) {
		a := mustPlan(t, reg, payload, redact("broad", "user"), canon(contract.ObFieldHash, "user.ssn", true, "narrow", nil))
		b := mustPlan(t, reg, payload, canon(contract.ObFieldHash, "user.ssn", true, "narrow", nil), redact("broad", "user"))
		if !reflect.DeepEqual(renderPlan(a.Plan), renderPlan(b.Plan)) {
			t.Fatalf("composition is order-dependent:\n a=%v\n b=%v", renderPlan(a.Plan), renderPlan(b.Plan))
		}
	})
}

// TestAnnotateIsTheTopOfTheOrder: annotate reveals the whole value, so a
// policy asking for it must never beat a policy asking for anything else.
func TestAnnotateIsTheTopOfTheOrder(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.KnownPayloadLeaves("user.ssn"),
		canon(contract.ObFieldAnnotate, "user.ssn", true, "permissive", map[string]string{"note": "pii"}),
		canon(contract.ObFieldMask, "user.ssn", true, "strict", map[string]string{"keep": "last4"}),
	)
	wantPlan(t, res.Plan, "field_mask user.ssn mandatory permissive,strict keep=last4")
}

// TestRemoveBeatsEveryComparableKindWhateverItsParameters pins the rule that a
// strictly less-disclosing KIND subsumes a more-disclosing one under any
// parameterisation.
func TestRemoveBeatsEveryComparableKindWhateverItsParameters(t *testing.T) {
	reg := testRegistry(t)
	for _, other := range []Obligation{
		canon(contract.ObFieldRedact, "x", true, "b", map[string]string{"const": "***"}),
		canon(contract.ObFieldHash, "x", true, "b", map[string]string{"alg": "sha256"}),
		canon(contract.ObFieldMask, "x", true, "b", map[string]string{"keep": "last4"}),
		canon(contract.ObFieldAnnotate, "x", true, "b", nil),
	} {
		res := mustPlan(t, reg, contract.KnownPayloadLeaves("x"), canon(contract.ObFieldRemove, "x", true, "a", nil), other)
		wantPlan(t, res.Plan, "field_remove x mandatory a,b -")
	}
}

// TestSameKindWithIncompatibleParametersDenies: two masks with different
// windows each reveal something the other hides. Picking either would
// silently discard a requirement policy's instruction.
func TestSameKindWithIncompatibleParametersDenies(t *testing.T) {
	reg := testRegistry(t)
	res := mustDeny(t, reg, contract.KnownPayloadLeaves("card.number"),
		canon(contract.ObFieldMask, "card.number", true, "a", map[string]string{"keep": "last4"}),
		canon(contract.ObFieldMask, "card.number", true, "b", map[string]string{"keep": "first6"}),
	)
	if !hasReason(res, ReasonConflict) {
		t.Fatalf("reasons=%v, want %q", res.Reasons, ReasonConflict)
	}
	d := joinedDetails(res)
	if !strings.Contains(d, "card.number") || !strings.Contains(d, "last4") || !strings.Contains(d, "first6") {
		t.Errorf("the conflict must name the leaf and both parameter sets; details=%q", d)
	}
}

// TestAmbiguousLoserDoesNotDeny is the other half of the rule above: two
// incompatible masks only conflict if a mask is what WINS. With a remove also
// present, removing the leaf discharges all three.
func TestAmbiguousLoserDoesNotDeny(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.KnownPayloadLeaves("card.number"),
		canon(contract.ObFieldMask, "card.number", true, "a", map[string]string{"keep": "last4"}),
		canon(contract.ObFieldMask, "card.number", true, "b", map[string]string{"keep": "first6"}),
		canon(contract.ObFieldRemove, "card.number", true, "c", nil),
	)
	wantPlan(t, res.Plan, "field_remove card.number mandatory a,b,c -")
}

// TestIncomparableTransformKindsDeny: a reversible surrogate, a schema
// transform and a row filter do not sit on an order whose meaning is "what a
// reader learns", so nothing may pick between them and a comparable transform.
func TestIncomparableTransformKindsDeny(t *testing.T) {
	reg := testRegistry(t)
	for _, k := range []contract.ObligationType{contract.ObFieldTokenize, contract.ObSchemaTransform, contract.ObResponseFilter} {
		other := canon(k, "x", true, "a", nil)
		other.Phase = PhaseResponse // response_filter is response-only; the others allow it too
		res := mustDeny(t, reg, contract.KnownPayloadLeaves("x"), other, redact("b", "x"))
		if !hasReason(res, ReasonConflict) {
			t.Errorf("%s: reasons=%v, want %q", k, res.Reasons, ReasonConflict)
		}
		if !strings.Contains(joinedDetails(res), "no reviewed subsumption rule") {
			t.Errorf("%s: the deny must say the escape hatch exists and was not taken; details=%q", k, joinedDetails(res))
		}
	}
}

// TestReviewedSubsumptionRuleResolvesAnIncomparablePair is the registry-held
// escape hatch ADR-065 permits: the registry HOLDS the reviewed rule and the
// algebra APPLIES it, so a schema or a policy cannot mint one.
func TestReviewedSubsumptionRuleResolvesAnIncomparablePair(t *testing.T) {
	base := testRegistry(t)
	b := NewRegistryBuilder("test.v1")
	for _, c := range base.Capabilities() {
		s, _ := base.Lookup(c.Type, c.Version)
		b.Add(s)
	}
	b.AddSubsumption(contract.SubsumptionRule{
		Weaker:   contract.TransformRef{Type: contract.ObFieldTokenize},
		Stronger: contract.TransformRef{Type: contract.ObFieldRemove},
		Reason:   "reviewed 2026-08-30: removal discloses strictly less than a reversible token",
	})
	reg, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	res := mustPlan(t, reg, contract.KnownPayloadLeaves("x"),
		canon(contract.ObFieldTokenize, "x", true, "a", nil),
		canon(contract.ObFieldRemove, "x", true, "b", nil),
	)
	wantPlan(t, res.Plan, "field_remove x mandatory a,b -")
	if got := reg.SubsumptionRules(); len(got) != 1 || got[0].Reason == "" {
		t.Fatalf("the registry must expose the reviewed rule for the trace; got %+v", got)
	}
}

func TestSubsumptionRuleWithoutAReviewReasonIsRejected(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.AddSubsumption(contract.SubsumptionRule{
		Weaker: contract.TransformRef{Type: contract.ObFieldTokenize}, Stronger: contract.TransformRef{Type: contract.ObFieldRemove}})
	if _, err := b.Build(); err == nil {
		t.Fatal("a subsumption rule with no recorded review reason must be rejected: an unexplained rule is an unreviewed one")
	}
}

func TestSubsumptionCycleIsRejected(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.AddSubsumption(contract.SubsumptionRule{Weaker: contract.TransformRef{Type: contract.ObFieldTokenize}, Stronger: contract.TransformRef{Type: contract.ObSchemaTransform}, Reason: "r"})
	b.AddSubsumption(contract.SubsumptionRule{Weaker: contract.TransformRef{Type: contract.ObSchemaTransform}, Stronger: contract.TransformRef{Type: contract.ObFieldTokenize}, Reason: "r"})
	if _, err := b.Build(); err == nil {
		t.Fatal("a subsumption cycle must be rejected: it makes the winner depend on iteration order")
	}
}

// TestUnresolvableFieldPathDenies is the absent/unknown distinction from the
// planner's side, in both directions. A target against an UNKNOWN schema
// cannot be resolved and denies; the SAME target against a KNOWN schema that
// lacks it is absent, and is reported rather than denied. The two shipped
// algebras answered these two inputs in opposite ways (#3891).
func TestUnresolvableFieldPathDenies(t *testing.T) {
	reg := testRegistry(t)
	ob := canon(contract.ObFieldRemove, "account.balance", true, "a", nil)

	res := mustDeny(t, reg, contract.UnknownPayloadLeaves(contract.ReasonSchemaMismatch), ob)
	if !hasReason(res, ReasonConflict) {
		t.Fatalf("reasons=%v, want %q", res.Reasons, ReasonConflict)
	}
	if d := joinedDetails(res); !strings.Contains(d, "unknown (schema_mismatch)") {
		t.Errorf("the deny must name why the schema is unknown; details=%q", d)
	}

	absent := mustPlan(t, reg, contract.KnownPayloadLeaves("user.name"), ob)
	if !hasReason(absent, ReasonTargetAbsentFromSchema) || len(absent.Plan.Unplaced) != 1 {
		t.Fatalf("an absent target on a known schema must be reported, not denied; reasons=%v unplaced=%+v", absent.Reasons, absent.Plan.Unplaced)
	}
}

// TestUnknownPayloadSchemaDenies: a disclosure obligation with nothing to
// normalize against must deny rather than compose to an empty transform set.
// A zero-value PayloadLeaves is not "no schema needed": it is a malformed
// evaluator input and pages rather than permits.
func TestUnknownPayloadSchemaDenies(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{Registry: reg, Obligations: []Obligation{redact("a", "user")}, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg)})
	if res.Outcome != OutcomeError || !hasReason(res, ReasonMalformedInput) {
		t.Fatalf("outcome=%q reasons=%v, want ERROR with %q for a zero-value payload schema", res.Outcome, res.Reasons, ReasonMalformedInput)
	}
	// And a non-disclosure plan never reads it, so the zero value is harmless there.
	ok := Plan(PlanInput{Registry: reg, Obligations: []Obligation{canon(contract.ObImmutableAudit, "", true, "a", map[string]string{"channel": "siem"})},
		PEP: fullPEP(t, reg), Evidence: allSatisfied(reg)})
	if ok.Outcome != OutcomeAllow {
		t.Fatalf("outcome=%q, want ALLOW: a plan with no disclosure obligation does not need a payload schema; reasons=%v", ok.Outcome, ok.Reasons)
	}
}

// ---------------------------------------------------------------------------
// Approval: the conjunction that must not be flattened
// ---------------------------------------------------------------------------

func approval(src string, quorum int, eligible string, extra map[string]string) Obligation {
	params := map[string]string{"quorum": fmt.Sprint(quorum), "eligible": eligible}
	for k, v := range extra {
		params[k] = v
	}
	return canon(contract.ObApprovalChallenge, "", true, src, params)
}

func clauseKeys(req *contract.ApprovalRequirement) []string {
	var out []string
	for _, c := range req.AllOf {
		ids := make([]string, 0, len(c.Eligible))
		for _, e := range c.Eligible {
			ids = append(ids, e.String())
		}
		out = append(out, fmt.Sprintf("%d|%s", c.Quorum, strings.Join(ids, ",")))
	}
	return out
}

// TestApprovalClausesAreNeverFlattened is the correction ADR-065 makes to the
// source spec's pool-intersection meet. Under intersection,
// 2-of-{A,B} MEET 2-of-{B,C} becomes 2-of-{B}, which is unsatisfiable and
// would deny a request {A,B,C} can plainly approve.
func TestApprovalClausesAreNeverFlattened(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{},
		approval("p1", 2, "Group::r:A,Group::r:B", nil),
		approval("p2", 2, "Group::r:B,Group::r:C", nil),
	)
	if res.Plan.Approval == nil {
		t.Fatal("no approval requirement was composed")
	}
	want := []string{"2|Group::r:A,Group::r:B", "2|Group::r:B,Group::r:C"}
	if got := clauseKeys(res.Plan.Approval); !reflect.DeepEqual(got, want) {
		t.Fatalf("clauses = %v, want %v. Flattening two threshold clauses into one pool is the mathematical error ADR-065 corrects", got, want)
	}
}

// TestIdenticalApprovalClausesDeduplicateWithoutFlattening: two requirement
// policies demanding the same clause must not double the quorum, and must not
// merge the pools of DIFFERENT clauses either.
func TestIdenticalApprovalClausesDeduplicateWithoutFlattening(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{},
		approval("p1", 2, "Group::r:sec", nil),
		approval("p2", 2, "Group::r:sec", nil),
	)
	if got := clauseKeys(res.Plan.Approval); !reflect.DeepEqual(got, []string{"2|Group::r:sec"}) {
		t.Fatalf("identical clauses must deduplicate without changing the quorum; got %v", got)
	}
}

// TestApprovalCompositionTakesTheShortestExpiryAndStrictestSoD: the permissive
// direction on either would let one lax policy disarm a strict one.
func TestApprovalCompositionTakesTheShortestExpiryAndStrictestSoD(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{},
		approval("lax", 1, "Group::r:a", map[string]string{contract.ParamExpirySeconds: "86400", "separation_of_duties": "false"}),
		approval("strict", 1, "Group::r:b", map[string]string{contract.ParamExpirySeconds: "600", "separation_of_duties": "true"}),
	)
	if want := testNow.Add(600 * time.Second); !res.Plan.Approval.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %s, want %s (the shortest); extending a challenge past a policy's timeout is the permissive direction", res.Plan.Approval.ExpiresAt, want)
	}
	if !res.Plan.Approval.SeparationOfDuties {
		t.Error("separation of duties must hold if ANY policy demands it")
	}
	// The evaluator's own stamp takes part in the same minimum.
	stamped := Plan(PlanInput{
		Registry: reg, Obligations: []Obligation{approval("lax", 1, "Group::r:a", map[string]string{contract.ParamExpirySeconds: "86400"})},
		PEP: fullPEP(t, reg), Evidence: allSatisfied(reg), ApprovalExpiry: testNow.Add(90 * time.Second), Now: testNow,
	})
	if stamped.Outcome != OutcomeAllow || !stamped.Plan.Approval.ExpiresAt.Equal(testNow.Add(90*time.Second)) {
		t.Errorf("outcome=%q expires_at=%v, want ALLOW at the evaluator's shorter stamp", stamped.Outcome, stamped.Plan.Approval)
	}
}

// ---------------------------------------------------------------------------
// Routing, step-up, budget, audit
// ---------------------------------------------------------------------------

func routing(src string, dests string, props map[string]string) Obligation {
	params := map[string]string{contract.ParamAllowedDestinations: dests}
	for k, v := range props {
		params[k] = v
	}
	return canon(contract.ObRouteRestriction, "", true, src, params)
}

func TestRoutingIntersectsAndAnEmptyIntersectionDenies(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{},
		routing("a", "eu-west,eu-central,us-east", nil),
		routing("b", "eu-central,us-east", nil),
	)
	wantPlan(t, res.Plan, "route_restriction - mandatory a,b allowed_destinations=eu-central,us-east")

	deny := mustDeny(t, reg, contract.PayloadLeaves{}, routing("a", "eu-west", nil), routing("b", "us-east", nil))
	if !hasReason(deny, ReasonConflict) || !strings.Contains(joinedDetails(deny), "empty destination set") {
		t.Fatalf("reasons=%v details=%v, want an empty-destination-intersection conflict", deny.Reasons, deny.Details)
	}
}

func TestRoutingPropertiesIntersectPerKey(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{},
		routing("a", "eu", map[string]string{"route.tls": "1.2,1.3", "route.region": "eu"}),
		routing("b", "eu", map[string]string{"route.tls": "1.3"}),
	)
	// A key only one obligation mentions is unconstrained by the other, not
	// intersected to empty.
	wantPlan(t, res.Plan, "route_restriction - mandatory a,b allowed_destinations=eu;route.region=eu;route.tls=1.3")

	deny := mustDeny(t, reg, contract.PayloadLeaves{},
		routing("a", "eu", map[string]string{"route.tls": "1.2"}),
		routing("b", "eu", map[string]string{"route.tls": "1.3"}),
	)
	if !strings.Contains(joinedDetails(deny), `route property "route.tls"`) {
		t.Fatalf("details=%v, want a tls property conflict", deny.Details)
	}
}

func stepUp(src, assurance, methods string) Obligation {
	return canon(contract.ObStepUpAuth, "", true, src, map[string]string{"assurance": assurance, "methods": methods})
}

func TestStepUpTakesTheMaximumAssuranceAndIntersectsMethods(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{},
		stepUp("a", "aal2", "webauthn,totp"),
		stepUp("b", "aal3", "webauthn,push"),
	)
	wantPlan(t, res.Plan, "step_up_authentication - mandatory a,b assurance=aal3;methods=webauthn")

	deny := mustDeny(t, reg, contract.PayloadLeaves{}, stepUp("a", "aal2", "totp"), stepUp("b", "aal2", "push"))
	if !strings.Contains(joinedDetails(deny), "empty authentication method set") {
		t.Fatalf("details=%v, want an empty-method-intersection conflict", deny.Details)
	}
}

// budget builds a quota_reservation in the vocabulary the tree emits: the CAP
// is carried and the quantity is an attribute reference the reservation
// service resolves from the request.
func budget(src, counter, limit string) Obligation {
	return canon(contract.ObQuotaReservation, "", true, src, map[string]string{
		contract.ParamCounter: counter, contract.ParamWindow: "P1D", contract.ParamUnit: "cents",
		contract.ParamLimit: limit, contract.ParamAmountFrom: "args.amount_cents",
	})
}

// TestBudgetConstraintsConjoinAndIdenticalOnesDeduplicate.
//
// Composition does NOT sum, and the reason is the parameter model rather than
// a preference: a reservation's quantity is not in the policy at all. The
// obligation names an attribute with `amount_from` and the reservation service
// resolves it per request, so there is no per-policy amount to add - and an
// implementation that summed would be adding the CAPS, which loosens rather
// than tightens. Two policies stating the same cap are one constraint stated
// twice; two stating different caps are two constraints the reservation must
// each satisfy, so the tighter binds without composition deciding it here.
func TestBudgetConstraintsConjoinAndIdenticalOnesDeduplicate(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{},
		budget("a", "tokens", "100"),
		budget("b", "tokens", "250"),
		budget("c", "tokens", "100"),
	)
	wantPlan(t, res.Plan,
		"quota_reservation - mandatory a,c amount_from=args.amount_cents;counter=tokens;limit=100;unit=cents;window=P1D",
		"quota_reservation - mandatory b amount_from=args.amount_cents;counter=tokens;limit=250;unit=cents;window=P1D",
	)

	// A reservation the family would never read a parameter of is refused
	// rather than silently carried to the reservation service.
	bad := canon(contract.ObQuotaReservation, "", true, "x", map[string]string{
		contract.ParamCounter: "c", contract.ParamWindow: "P1D", contract.ParamUnit: "cents",
		contract.ParamLimit: "100", contract.ParamAmountFrom: "args.amount_cents", "amount": "50",
	})
	// ERROR rather than DENY, and the distinction is the planner's documented
	// one: the canonical validator refuses it in the structural pass, before
	// any proof runs, and a malformed instruction is a plumbing defect that
	// should page the owning service rather than a governance verdict. Both
	// refuse to execute; only one wakes somebody.
	refused := Plan(PlanInput{Registry: reg, Obligations: []Obligation{bad}, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg)})
	if refused.Outcome != OutcomeError || !hasReason(refused, ReasonMalformedInput) {
		t.Fatalf("outcome=%q reasons=%v, want ERROR with %q for a parameter the family never reads", refused.Outcome, refused.Reasons, ReasonMalformedInput)
	}
	if !strings.Contains(joinedDetails(refused), `declares no "amount" parameter`) {
		t.Errorf("the refusal must name the parameter nothing reads; details=%v", refused.Details)
	}
}

func audit(src, channel string, delivery contract.Delivery) Obligation {
	params := map[string]string{"channel": channel, "address": "sink1"}
	if delivery != "" {
		params["delivery"] = string(delivery)
	}
	return canon(contract.ObImmutableAudit, "", true, src, params)
}

// TestAuditTargetsUnionAndTakeTheStrongestGuarantee: the same sink asked for
// twice is ONE instruction carrying the stronger guarantee - not two
// deliveries.
func TestAuditTargetsUnionAndTakeTheStrongestGuarantee(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{},
		audit("a", "siem", contract.DeliveryBestEffort),
		audit("b", "siem", contract.DeliveryDurable),
		audit("c", "syslog", ""),
	)
	wantPlan(t, res.Plan,
		"immutable_audit - mandatory a,b address=sink1;channel=siem;delivery=durable",
		"immutable_audit - mandatory c address=sink1;channel=syslog",
	)
}

// ---------------------------------------------------------------------------
// Phase ordering (scheduling, owned here)
// ---------------------------------------------------------------------------

// TestPhaseOrderPutsDependenciesFirst: step-up and reservation must precede
// the approval challenge. Asking a human to approve before the session reached
// the required assurance collects an approval from a weakly-authenticated
// principal; asking before capacity is reserved holds an option on capacity
// someone else may take.
func TestPhaseOrderPutsDependenciesFirst(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{},
		approval("p", 1, "Group::r:a", nil),
		stepUp("s", "aal2", "totp"),
		budget("b", "calls", "1"),
	)
	pos := map[contract.ObligationType]int{}
	for i, tp := range res.Plan.Order {
		pos[tp] = i
	}
	if pos[contract.ObStepUpAuth] > pos[contract.ObApprovalChallenge] {
		t.Errorf("step-up must precede approval; order = %v", res.Plan.Order)
	}
	if pos[contract.ObQuotaReservation] > pos[contract.ObApprovalChallenge] {
		t.Errorf("reservation must precede approval; order = %v", res.Plan.Order)
	}
}

func TestPhaseOrderCycleDenies(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{Type: contract.ObFieldRedact, Version: 1, Owner: "o",
		Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", OnFailure: FailClosed, DependsOn: []contract.ObligationType{contract.ObFieldHash}})
	b.Add(Schema{Type: contract.ObFieldHash, Version: 1, Owner: "o",
		Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", OnFailure: FailClosed, DependsOn: []contract.ObligationType{contract.ObFieldRedact}})
	reg, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	res := mustDeny(t, reg, contract.KnownPayloadLeaves("x", "y"),
		redact("a", "x"),
		canon(contract.ObFieldHash, "y", true, "b", nil),
	)
	if !hasReason(res, ReasonConflict) || !strings.Contains(joinedDetails(res), "dependency cycle") {
		t.Fatalf("reasons=%v details=%v, want a phase-ordering cycle conflict", res.Reasons, res.Details)
	}
}

// TestPhaseOrderIgnoresAbsentDependencies: nothing has to run before something
// that is not running. A dependency on an absent type must not deny.
func TestPhaseOrderIgnoresAbsentDependencies(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.PayloadLeaves{}, approval("p", 1, "Group::r:a", nil))
	if !reflect.DeepEqual(res.Plan.Order, []contract.ObligationType{contract.ObApprovalChallenge}) {
		t.Fatalf("order = %v, want just the approval challenge", res.Plan.Order)
	}
}

// TestPhaseOrderIsDeterministic: a trace diffed between two runs must be
// comparable, so ties are broken by name rather than by map iteration order.
func TestPhaseOrderIsDeterministic(t *testing.T) {
	reg := testRegistry(t)
	obs := []contract.Obligation{
		stepUp("s", "aal2", "totp").Obligation,
		budget("b", "calls", "1").Obligation,
		audit("a", "siem", contract.DeliveryDurable).Obligation,
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

// TestNoNumericRankingAcrossFamilies: composing one obligation of every family
// must produce a plan that retains ALL of them. A severity ranking would have
// discarded the "less severe" ones. The check is behavioural, not a source
// scan.
func TestNoNumericRankingAcrossFamilies(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.KnownPayloadLeaves("user.ssn"),
		canon(contract.ObFieldRemove, "user.ssn", true, "d", nil),
		approval("p", 1, "Group::r:a", nil),
		routing("r", "eu", nil),
		stepUp("s", "aal2", "totp"),
		budget("b", "calls", "1"),
		audit("a", "siem", contract.DeliveryDurable),
	)
	wantPlan(t, res.Plan,
		"approval_challenge - mandatory p eligible=Group::r:a;quorum=1",
		"field_remove user.ssn mandatory d -",
		"immutable_audit - mandatory a address=sink1;channel=siem;delivery=durable",
		"quota_reservation - mandatory b amount_from=args.amount_cents;counter=calls;limit=1;unit=cents;window=P1D",
		"route_restriction - mandatory r allowed_destinations=eu",
		"step_up_authentication - mandatory s assurance=aal2;methods=totp",
	)
	if res.Plan.Approval == nil {
		t.Error("the approval requirement was discarded")
	}
	if len(res.Plan.Order) != 6 {
		t.Errorf("order covers %d types, want 6: %v", len(res.Plan.Order), res.Plan.Order)
	}
}

// TestAdvisoryThatDoesNotComposeIsDroppedAndRecorded: the algebra's advisory
// rule reaches the planner's trace. A detector's contribution must not be
// able to refuse a request, and the drop must be visible.
func TestAdvisoryThatDoesNotComposeIsDroppedAndRecorded(t *testing.T) {
	reg := testRegistry(t)
	res := mustPlan(t, reg, contract.KnownPayloadLeaves("user.ssn"),
		redact("p1", "user.ssn"),
		canon(contract.ObFieldTokenize, "user.ssn", false, "d1", nil),
	)
	wantPlan(t, res.Plan, "field_redact user.ssn mandatory p1 -")
	if len(res.Plan.DroppedAdvisory) != 1 || res.Plan.DroppedAdvisory[0].Type != contract.ObFieldTokenize {
		t.Fatalf("dropped advisory = %+v, want the tokenize", res.Plan.DroppedAdvisory)
	}
	found := false
	for _, d := range res.Dropped {
		if d.Reason == "advisory_does_not_compose" && d.Type == contract.ObFieldTokenize && !d.Mandatory {
			found = true
		}
	}
	if !found {
		t.Fatalf("the drop must be recorded in the trace; dropped=%+v", res.Dropped)
	}
}
