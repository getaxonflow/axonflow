package conformance

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/registry"
)

// ADR-065 ACCEPTANCE GATE 15: "Every plane produces the same normalized outcome
// and reason codes."
//
// #3555 filed this HIGH: "No test evaluates one request on two ADR-065 planes
// and compares; the PDP and the corpus have no plane dimension." The corpus
// gains that dimension here, and the gate becomes executable rather than
// aspirational.
//
// # THE GATE HAS TO BE STATED MORE PRECISELY THAN ITS ONE SENTENCE
//
// Taken literally, "every plane produces the same outcome" is FALSE by design
// and must be: ADR-065 invariant 8 says a mandatory obligation the enforcement
// point cannot discharge produces DENY, and the twelve legacy planes advertise
// genuinely different capability sets (the MCP plane discharges field_redact;
// the OpenAI-compatible plane does not). A test asserting bare equality would
// therefore fail on correct behaviour, and the only ways to make it pass would
// be to give every plane the same capabilities - which erases the handshake the
// gate exists alongside - or to weaken the assertion until it proves nothing.
//
// The precise property, and the one asserted here, is in two parts:
//
//  1. TWO PLANES WITH THE SAME CAPABILITIES PRODUCE THE IDENTICAL DECISION:
//     same operational state, same reason codes, same determining set, same
//     composed obligations. No plane may have a private rule.
//  2. TWO PLANES WITH DIFFERENT CAPABILITIES DIFFER ONLY BY THE CAPABILITY
//     REFUSAL. Where they differ, the less capable plane must be the one that
//     denied, and it must have denied for the unsupported-obligation reason -
//     never for some other reason, and never in the permissive direction.
//
// Part 2 is the half that would be missing from a naive test, and it is the
// half that catches the dangerous shape: a plane that is MORE permissive than
// its capabilities justify.

// planePEPs returns one PEP profile per implemented plane, for one edition,
// from the registry's checked-in table.
//
// DERIVED, not listed here. registry.LegacyPlanePEPs reads
// legacy_plane_peps.tsv, whose plane vocabulary a sibling test proves equal to
// the shadow harness's - so a plane added to the model reaches this gate
// automatically, and a plane whose capabilities change is re-measured without
// anybody remembering to.
func planePEPs(t *testing.T, edition registry.Edition) map[string]*contract.PEPProfile {
	t.Helper()
	records, err := registry.LegacyPlanePEPs(edition)
	if err != nil {
		t.Fatalf("reading the legacy plane enforcement points: %v", err)
	}
	if len(records) == 0 {
		t.Fatalf("no enforcement point is declared for edition %s; this gate would then compare "+
			"nothing and pass", edition)
	}
	out := map[string]*contract.PEPProfile{}
	for _, r := range records {
		rec := r
		out[strings.TrimPrefix(rec.ID, registry.LegacyPlanePEPPrefix)] = &contract.PEPProfile{
			ID:           rec.ID,
			Capabilities: rec.Capabilities,
		}
	}
	return out
}

// capabilityKey renders a profile's capability set as a comparable string, so
// two planes can be grouped by "advertises the same thing".
func capabilityKey(p *contract.PEPProfile) string {
	parts := make([]string, 0, len(p.Capabilities))
	for _, c := range p.Capabilities {
		parts = append(parts, fmt.Sprintf("%s@%d", c.Type, c.Version))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// normalized is the comparable projection of a decision: the operational
// outcome and the reason codes, plus the determining set and the composed
// obligations.
//
// It deliberately does NOT include the trace, the request id or any timestamp.
// Those differ per evaluation by construction, and including them would make
// every comparison differ for a reason that has nothing to do with the plane -
// the shape that turns a real gate into one everybody ignores.
type normalized struct {
	State       contract.OperationalState
	Reason      string
	Determining string
	Obligations string
	Approval    int
}

func normalize(d *contract.Decision) normalized {
	n := normalized{State: d.State, Reason: string(d.Reason)}
	det := append([]string(nil), d.Determining.MatchedConstraints...)
	det = append(det, d.Determining.MatchedRequirement...)
	det = append(det, d.Determining.MatchedPermissions...)
	det = append(det, d.Determining.MatchedInspections...)
	sort.Strings(det)
	n.Determining = strings.Join(det, ",")

	obs := make([]string, 0, len(d.Obligations))
	for _, o := range d.Obligations {
		obs = append(obs, fmt.Sprintf("%s@%d/%s/%v", o.Type, o.SchemaVersion, o.Target, o.Mandatory))
	}
	sort.Strings(obs)
	n.Obligations = strings.Join(obs, ",")
	if d.Approval != nil {
		n.Approval = len(d.Approval.AllOf)
	}
	return n
}

// TestGate15CrossPlaneOutcomeEquality is ADR-065 gate 15, executable.
func TestGate15CrossPlaneOutcomeEquality(t *testing.T) {
	ctx := context.Background()

	for _, edition := range []registry.Edition{registry.EditionCommunity, registry.EditionEnterprise} {
		edition := edition
		t.Run(string(edition.String()), func(t *testing.T) {
			peps := planePEPs(t, edition)

			// ANTI-VACUITY, ON BOTH AXES, DERIVED RATHER THAN CALIBRATED.
			//
			// A gate whose corpus is empty, or whose plane set is a single
			// plane, passes forever and passes hardest when it is broken. It
			// is the product of the two axes that has to be non-trivial, not
			// either one: twenty cases on one plane compare nothing, and
			// twelve planes over zero cases compare nothing
			// ([[feedback_an_antivacuity_floor_cannot_see_a_missing_dimension]]).
			scenarios := crossPlaneScenarios()
			if len(scenarios) == 0 {
				t.Fatal("no scenario; this gate would compare nothing")
			}
			if len(peps) < 2 {
				t.Fatalf("only %d plane(s) for edition %s; a cross-PLANE gate needs at least two",
					len(peps), edition)
			}
			// And the plane set must contain at least two DIFFERENT capability
			// groups, or part 2 of the gate is unexercised - every comparison
			// would take the same-capability arm and the capability-refusal
			// half would never run.
			groups := map[string]bool{}
			for _, p := range peps {
				groups[capabilityKey(p)] = true
			}
			if len(groups) < 2 {
				t.Fatalf("every plane in edition %s advertises the same capabilities (%d group), "+
					"so the capability-difference half of this gate is unexercised", edition, len(groups))
			}

			// THE THIRD AXIS, AND THE ONE THIS GATE ORIGINALLY MISSED.
			//
			// The two floors above check the CORPUS axis and the PLANE axis,
			// and a gate can still be vacuous with both satisfied: if every
			// scenario resolves to the same outcome on every plane, 726
			// comparisons compare DENY to DENY and the gate passes forever.
			// That is exactly what happened here - see the trap recorded on
			// crossPlaneScenarios - and neither existing floor could see it,
			// because a floor over one dimension cannot report a missing one
			// ([[feedback_an_antivacuity_floor_cannot_see_a_missing_dimension]]).
			//
			// The remedy is to floor the axes' PRODUCT: the outcomes actually
			// observed must span more than one operational state, and at least
			// one must be non-restrictive. A permit is the specific thing a
			// DENY-only corpus cannot measure, and it is the half of the gate
			// a regression would land in.
			statesSeen := map[contract.OperationalState]int{}
			reasonsSeen := map[string]int{}

			comparisons := 0
			differences := 0
			for _, sc := range scenarios {
				sc := sc
				t.Run(sc.name, func(t *testing.T) {
					// What THIS scenario asks an enforcement point to
					// discharge, read from a world with no enforcement point.
					//
					// It has to be read there and nowhere else: a plane that
					// cannot discharge an obligation emits no obligation, so
					// reading the demand off a PEP-constrained decision makes
					// the demand disappear exactly when it is the thing being
					// refused - and the refusal would then look unexplained.
					demandedHere := mandatoryObligationsDemanded(t, sc.scenario)

					// One decision per plane, from a world built with THAT
					// plane's capability profile and nothing else different.
					got := map[string]normalized{}
					for plane, pep := range peps {
						w, err := NewWorld(ctx, WithPEP(pep))
						if err != nil {
							t.Fatalf("building the %s world: %v", plane, err)
						}
						d, err := w.Decide(ctx, sc.scenario)
						if err != nil {
							t.Fatalf("%s: %v", plane, err)
						}
						got[plane] = normalize(d)
						// Recorded for the outcome-dimension floor below. The
						// subtests here are sequential (none calls t.Parallel),
						// so a plain map is correct; making them parallel would
						// need this to move behind a mutex, and the floor would
						// silently under-count if it did not.
						statesSeen[d.State]++
						reasonsSeen[string(d.Reason)]++
					}

					planes := make([]string, 0, len(got))
					for p := range got {
						planes = append(planes, p)
					}
					sort.Strings(planes)

					for i := 0; i < len(planes); i++ {
						for j := i + 1; j < len(planes); j++ {
							a, b := planes[i], planes[j]
							comparisons++
							if got[a] == got[b] {
								continue
							}
							differences++
							sameCaps := capabilityKey(peps[a]) == capabilityKey(peps[b])
							if sameCaps {
								t.Errorf("GATE 15 VIOLATION: planes %q and %q advertise identical "+
									"capabilities (%s) and produced DIFFERENT decisions for %s.\n"+
									"  %s: %+v\n  %s: %+v\n"+
									"Two planes with the same capabilities have no licence to "+
									"disagree; a plane with a private rule is a plane whose "+
									"cutover cannot be reasoned about from any other plane's window.",
									a, b, capabilityKey(peps[a]), sc.name, a, got[a], b, got[b])
								continue
							}
							// Different capabilities. The ONLY licensed
							// difference is the capability refusal, and it must
							// run in the restrictive direction.
							assertCapabilityRefusalExplains(t, sc.name, demandedHere,
								a, got[a], peps[a], b, got[b], peps[b])
						}
					}
				})
			}

			if comparisons == 0 {
				t.Fatal("no pair was compared")
			}

			// The outcome-dimension floor, asserted rather than assumed.
			if len(statesSeen) < 2 {
				t.Fatalf("every one of the %d decision(s) in edition %s resolved to the SAME "+
					"operational state (%v); this gate then compares a state to itself %d times "+
					"and cannot see a regression in any other outcome class",
					comparisons, edition, statesSeen, comparisons)
			}
			permissive := 0
			for st, n := range statesSeen {
				if st != contract.StateDeny {
					permissive += n
				}
			}
			if permissive == 0 {
				t.Fatalf("edition %s: every decision DENIED (reasons: %v). A cross-plane gate over "+
					"denials alone cannot measure the permit path, which is the half a "+
					"plane-private rule would land in", edition, reasonsSeen)
			}

			// THE LICENSED-DIFFERENCE FLOOR, DERIVED PER EDITION.
			//
			// Part 2 of this gate can only fire if the corpus DEMANDS a
			// capability that the planes DISAGREE about advertising. That is
			// computable from the two inputs, so it is computed here rather
			// than written down as an expected count: a hardcoded "expect >= 1"
			// would be wrong in the community edition (where no plane
			// advertises approval_challenge, so every plane refuses alike and
			// zero is the correct answer), and calibrating it to whatever came
			// out would make it a tautology
			// ([[feedback_an_antivacuity_floor_must_be_derived_not_calibrated]]).
			if discriminating := discriminatingCapabilities(t, peps); len(discriminating) > 0 && differences == 0 {
				t.Fatalf("edition %s: the planes disagree about advertising %v and the corpus demands "+
					"it, so some pair MUST have differed - yet every pair agreed. Either the "+
					"capability refusal stopped being applied or the scenario that exercised it "+
					"stopped reaching it; both make part 2 of this gate unexercised while it "+
					"still reports %d green comparisons", edition, discriminating, comparisons)
			}

			t.Logf("edition %s: %d plane-pair comparison(s) over %d scenario(s), %d licensed difference(s), "+
				"%d capability group(s); states observed %v", edition, comparisons, len(scenarios),
				differences, len(groups), statesSeen)
		})
	}
}

// assertCapabilityRefusalExplains checks the only licensed reason two planes
// may differ.
func assertCapabilityRefusalExplains(
	t *testing.T, caseName string, demanded []string,
	a string, na normalized, pa *contract.PEPProfile,
	b string, nb normalized, pb *contract.PEPProfile,
) {
	t.Helper()

	// Exactly one of the two must have denied, and it must be the one whose
	// capabilities are a strict subset. A plane that is MORE permissive than
	// another with a superset of its capabilities is the dangerous direction,
	// and it is what this arm exists to catch.
	denier, permitter := a, b
	dn, pn := na, nb
	dp, pp := pa, pb
	if na.State != contract.StateDeny && nb.State == contract.StateDeny {
		denier, permitter = b, a
		dn, pn = nb, na
		dp, pp = pb, pa
	}
	if dn.State != contract.StateDeny {
		t.Errorf("GATE 15 VIOLATION: planes %q and %q differ for %s and NEITHER denied.\n"+
			"  %s: %+v\n  %s: %+v\n"+
			"A capability difference may only ever make a plane MORE restrictive "+
			"(ADR-065 invariant 8); two differing permits mean one of them has a rule "+
			"the other does not, which is a plane-private rule wearing a capability "+
			"difference as a disguise.",
			a, b, caseName, a, na, b, nb)
		return
	}
	// THE DENIER MUST BE MISSING SOMETHING THE PERMITTER HAS, AND THAT SOMETHING
	// MUST BE ONE OF THE OBLIGATIONS THIS SCENARIO ACTUALLY DEMANDED.
	//
	// The first version of this arm asked whether the denier's capabilities were
	// a SUBSET of the permitter's, and that is the wrong relation: the twelve
	// plane profiles are not totally ordered. cowork_ingest advertises
	// {field_redact, immutable_audit} and decide advertises
	// {approval_challenge, immutable_audit} - incomparable in both directions -
	// so on a scenario demanding an approval challenge, cowork_ingest correctly
	// refuses while decide correctly challenges, and a subset test reports
	// thirty-five GATE 15 VIOLATIONS against entirely correct behaviour. That
	// the denier also holds a capability the permitter lacks is irrelevant to
	// THIS refusal.
	//
	// The relation that is actually invariant 8 is narrower AND stronger: the
	// permitter discharged an obligation the denier cannot, so the denier must
	// lack a DEMANDED capability the permitter advertises. Anything else - a
	// denial while holding everything the scenario asked for - is a
	// plane-private rule wearing a capability difference as a disguise, which is
	// what this arm exists to catch.
	missing := demandedCapabilitiesMissing(demanded, dp, pp)
	if len(missing) == 0 {
		t.Errorf("GATE 15 VIOLATION: for %s, plane %q denied while %q permitted, but %q "+
			"advertises every capability this scenario demanded (%v) that %q does.\n"+
			"  denier %q: %s\n  permitter %q: %s\n"+
			"The denial is therefore NOT explained by a missing capability, and an "+
			"unexplained per-plane denial is a plane-private rule.",
			caseName, denier, permitter, denier, demanded, permitter,
			denier, capabilityKey(dp), permitter, capabilityKey(pp))
		return
	}
	if dn.Reason != string(contract.ReasonUnsupportedObligation) {
		t.Errorf("GATE 15 VIOLATION: for %s, plane %q denied with reason %q rather than %q.\n"+
			"A capability difference explains exactly ONE refusal reason. Any other reason "+
			"means the two planes disagreed about the POLICY and the capability difference "+
			"is a coincidence - which is precisely the difference this gate must not absorb.",
			caseName, denier, dn.Reason, contract.ReasonUnsupportedObligation)
	}
	_ = pn
}

// mandatoryObligationsDemanded returns the mandatory obligations one scenario's
// policies attach, evaluated against a world with NO enforcement point.
func mandatoryObligationsDemanded(t *testing.T, sc Scenario) []string {
	t.Helper()
	ctx := context.Background()
	w, err := NewWorld(ctx)
	if err != nil {
		t.Fatalf("building the unconstrained world: %v", err)
	}
	d, err := w.Decide(ctx, sc)
	if err != nil {
		t.Fatalf("deciding against the unconstrained world: %v", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, o := range d.Obligations {
		if !o.Mandatory {
			continue
		}
		k := fmt.Sprintf("%s@%d", o.Type, o.SchemaVersion)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// demandedCapabilitiesMissing returns the capabilities this scenario demanded
// that the permitter advertises and the denier does not.
//
// Deliberately NOT a subset relation between the two profiles: see the comment
// at its call site. Only the demanded capabilities are considered, because a
// capability nothing asked for cannot explain a refusal.
func demandedCapabilitiesMissing(demanded []string, denier, permitter *contract.PEPProfile) []string {
	has := func(p *contract.PEPProfile, cap string) bool {
		for _, c := range p.Capabilities {
			if fmt.Sprintf("%s@%d", c.Type, c.Version) == cap {
				return true
			}
		}
		return false
	}
	var out []string
	for _, cap := range demanded {
		if has(permitter, cap) && !has(denier, cap) {
			out = append(out, cap)
		}
	}
	return out
}

// capabilitiesSubsetOf reports whether every capability of a is advertised by b.
//
// It is a FIXTURE SANITY CHECK, used only by the synthetic-profile test where
// the two profiles are built in a deliberate subset relation. It is NOT the
// gate's rule: the twelve shipped plane profiles are not totally ordered, and
// using this as the rule reported thirty-five violations against correct
// behaviour. See assertCapabilityRefusalExplains.
func capabilitiesSubsetOf(a, b *contract.PEPProfile) bool {
	have := map[string]bool{}
	for _, c := range b.Capabilities {
		have[fmt.Sprintf("%s@%d", c.Type, c.Version)] = true
	}
	for _, c := range a.Capabilities {
		if !have[fmt.Sprintf("%s@%d", c.Type, c.Version)] {
			return false
		}
	}
	return true
}

// discriminatingCapabilities returns the capability types that can actually
// make two planes differ over this corpus.
//
// It is the precondition for part 2 of gate 15 firing at all, and it is derived
// from the gate's own two inputs so that it moves when either does. Three
// conditions, and the third is the one a first pass gets wrong:
//
//  1. the corpus DEMANDS it, read from an unconstrained world;
//  2. the planes DISAGREE about advertising it - strictly between nobody and
//     everybody, since a capability all twelve hold discriminates nothing and
//     one none of them holds makes them all refuse together;
//  3. some scenario demands it WITHOUT also demanding a capability that no
//     plane advertises. Measured: field_redact@1 satisfies (1) and (2), yet
//     never discriminates, because C5 attaches it to the `pii` tag and C6
//     attaches field_mask@1 to the SAME tag - so every request that demands a
//     redaction also demands a mask, no plane can mask, and all twelve refuse
//     for the mask before the redaction is ever reached. Without this condition
//     the floor below fails the community edition against entirely correct
//     behaviour, which is a floor that would have to be deleted rather than
//     satisfied. That co-occurrence is itself a finding, routed to #3564.
func discriminatingCapabilities(t *testing.T, peps map[string]*contract.PEPProfile) []string {
	t.Helper()

	advertisedBy := map[string]int{}
	for _, p := range peps {
		for _, c := range p.Capabilities {
			advertisedBy[fmt.Sprintf("%s@%d", c.Type, c.Version)]++
		}
	}
	disagreed := func(cap string) bool {
		n := advertisedBy[cap]
		return n > 0 && n < len(peps)
	}

	seen := map[string]bool{}
	var out []string
	for _, sc := range crossPlaneScenarios() {
		demanded := mandatoryObligationsDemanded(t, sc.scenario)
		blocked := false
		for _, cap := range demanded {
			if advertisedBy[cap] == 0 {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		for _, cap := range demanded {
			if disagreed(cap) && !seen[cap] {
				seen[cap] = true
				out = append(out, cap)
			}
		}
	}
	sort.Strings(out)
	return out
}

// crossPlaneScenario is one corpus entry with a name.
type crossPlaneScenario struct {
	name     string
	scenario Scenario
}

// crossPlaneScenarios is the set every plane is evaluated over.
//
// It deliberately spans the OUTCOME classes rather than a single happy path,
// and "deliberately" here means MEASURED: the gate asserts the spread it claims
// (see the outcome-dimension floor in TestGate15CrossPlaneOutcomeEquality),
// because the first version of this list claimed the spread in this comment and
// did not have it.
//
// THE TRAP THIS LIST WALKED INTO, RECORDED SO IT IS NOT REPEATED. The scenarios
// below named `spend_*` and `pii_*` looked like a permit and a
// permit-with-obligations, and they are - against a world with no enforcement
// point. Against the REAL legacy plane profiles they are neither: C8 attaches a
// mandatory quota_reservation@1 to every `spend` action and C6 a mandatory
// field_mask@1 to every `pii` action, and NO legacy plane advertises either
// (the union of all twelve planes' capabilities is
// {approval_challenge@1, field_redact@1, immutable_audit@1}). Invariant 8 then
// makes every plane DENY for unsupported_obligation - correctly, identically,
// and uninformatively. A list of only those scenarios compares DENY to DENY 726
// times and passes hardest when the permit path is most broken.
//
// So `permit_every_plane_discharges` and `challenge_only_capable_planes_can_discharge`
// are load-bearing rather than decorative: T5 is tagged `reversible`, which no
// obligation-attaching requirement selects on, so it is the one action in the
// corpus whose permit survives a real plane profile. The contractor variant
// then attaches approval_challenge@1 ALONE (C4, scoped to all-contractors,
// Actions.Any), which is the only corpus obligation any plane advertises - and
// so the only way part 2 of this gate fires against the shipped capability
// table rather than against profiles a test invented.
func crossPlaneScenarios() []crossPlaneScenario {
	return []crossPlaneScenario{
		// A PERMIT EVERY PLANE CAN ACTUALLY DISCHARGE. alice is in
		// support-tier2 (G8 permits T5) and is not a contractor, so no
		// requirement attaches an obligation at all: ALLOW/permitted on all
		// twelve planes in both editions. This is the scenario that keeps the
		// same-capability arm from being a DENY==DENY tautology.
		{"permit_every_plane_discharges", Scenario{
			Principal: "alice", Action: "T5", Resource: "SUP-42",
			Args: map[string]any{"ticket_id": "SUP-42", "to_status": "done"},
		}},
		// THE CAPABILITY DIFFERENCE, ON THE REAL TABLE. bob is in
		// support-tier2 AND contractors-emea, whose closure contains
		// all-contractors, so C4 attaches approval_challenge@1 - mandatory,
		// and alone. Measured: in the enterprise edition this CHALLENGEs on
		// {decide, gateway_request, map, proxy_request, wcp} and DENYs for
		// unsupported_obligation on the other seven, which is part 2 of this
		// gate firing over shipped capabilities. In the community edition no
		// plane advertises approval_challenge, so all deny alike - itself worth
		// knowing, and the reason the licensed-difference floor below is
		// derived per edition instead of being a constant.
		{"challenge_only_capable_planes_can_discharge", Scenario{
			Principal: "bob", Action: "T5", Resource: "SUP-42",
			Args: map[string]any{"ticket_id": "SUP-42", "to_status": "done"},
		}},
		// A GENUINE INDETERMINATE. agent.trust_level is read by a constraint,
		// so failing to resolve it leaves the constraint undecided and the
		// decision ERRORs for unknown_constraint on every plane alike - unknown
		// cannot permit, and it cannot permit differently on different planes
		// either. (The scenario that used to carry this name overrode a
		// DECLARED ARGUMENT to unknown, which is a schema violation rather than
		// an indeterminate, so it asserted the wrong class under the right
		// name. Both now appear, each under its own.)
		{"unresolved_attribute_is_indeterminate", Scenario{
			Principal: "alice", Action: "T5", Resource: "LEG-7",
			Args: map[string]any{"ticket_id": "LEG-7", "to_status": "done"},
			Overrides: map[string]*contract.Attribute{
				PathAgentTrust: UnknownAttr(PathAgentTrust, contract.ReasonResolutionFailed),
			},
		}},
		// A spend permit. Against a real plane profile this is a
		// DENY/unsupported_obligation, because C8's quota_reservation@1 is
		// discharged by no plane - which is a finding routed to #3564, not a
		// defect in this gate, and is kept here because it is the shape the
		// window will actually see once the spend planes are shadowed.
		{"spend_permit_no_plane_can_reserve_quota", Scenario{
			Principal: "alice", Action: "T1", Resource: "SUP-42",
			Args: map[string]any{"amount_cents": 30000},
		}},
		// A PII export. Its field_redact@1 obligations ARE advertised by some
		// planes, but C6 attaches field_mask@1 to the same `pii` tag and no
		// plane advertises that, so every plane refuses together. The
		// co-occurrence is the finding: field_redact can never be the
		// discriminating capability anywhere in this corpus.
		{"pii_permit_no_plane_can_mask", Scenario{
			Principal: "dana", Action: "T2", Args: map[string]any{"segment": "all"},
		}},
		// An explicit constraint deny. Capability differences must not change
		// it: ADR-065 carries obligations only on a permit, so a denied
		// request has nothing for a plane to fail to discharge.
		{"constraint_denies", Scenario{
			Principal: "alice", Action: "T2", Args: map[string]any{"segment": "all"},
		}},
		// No permission matches, which is default deny.
		{"no_permission_matches", Scenario{
			Principal: "alice", Action: "T3", Args: map[string]any{"query": "invoices"},
		}},
		// A DECLARED ARGUMENT that failed to resolve, which is a schema
		// violation rather than an indeterminate. Kept under its true name
		// beside the indeterminate above, because the two deny for different
		// reasons and a gate that conflated them would absorb a real
		// divergence between planes as "unknown-ish".
		{"unresolved_declared_argument_is_a_schema_violation", Scenario{
			Principal: "alice", Action: "T1", Resource: "SUP-42",
			Args: map[string]any{"amount_cents": 30000},
			Overrides: map[string]*contract.Attribute{
				PathArgsAmount: UnknownAttr(PathArgsAmount, contract.ReasonResolutionFailed),
			},
		}},
		// An approval challenge stacked on top of the PII obligations, so the
		// mask refusal wins on every plane. Distinct from
		// challenge_only_capable_planes_can_discharge, where the challenge is
		// the ONLY obligation and therefore decides.
		{"approval_challenge_behind_an_undischargeable_mask", Scenario{
			Principal: "frank", Action: "T2", Args: map[string]any{"segment": "all"},
		}},
	}
}

// TestPlaneVocabularyIsShared pins the two plane lists to each other.
//
// registry.LegacyPlanePEPs and legacycompile.AllPlanes are two independent
// statements of "the enforcement planes", in two modules, and this gate reads
// the first while the shadow harness reads the second. If they drift, this gate
// silently measures a different set of planes than the one being migrated -
// which is the worst failure available to a gate whose whole output is
// coverage.
func TestPlaneVocabularyIsShared(t *testing.T) {
	fromRegistry := map[string]bool{}
	for _, edition := range []registry.Edition{registry.EditionCommunity, registry.EditionEnterprise} {
		records, err := registry.LegacyPlanePEPs(edition)
		if err != nil {
			t.Fatalf("reading the plane enforcement points: %v", err)
		}
		for _, r := range records {
			fromRegistry[strings.TrimPrefix(r.ID, registry.LegacyPlanePEPPrefix)] = true
		}
	}
	fromCompiler := map[string]bool{}
	for _, p := range legacycompile.AllPlanes() {
		fromCompiler[string(p)] = true
	}

	var onlyRegistry, onlyCompiler []string
	for p := range fromRegistry {
		if !fromCompiler[p] {
			onlyRegistry = append(onlyRegistry, p)
		}
	}
	for p := range fromCompiler {
		if !fromRegistry[p] {
			onlyCompiler = append(onlyCompiler, p)
		}
	}
	sort.Strings(onlyRegistry)
	sort.Strings(onlyCompiler)

	if len(onlyRegistry) > 0 {
		t.Errorf("the PEP registry declares plane(s) %v that the compiler's plane model does not. "+
			"This gate would measure a plane nothing compiles policy for.", onlyRegistry)
	}
	if len(onlyCompiler) > 0 {
		t.Errorf("the compiler's plane model declares plane(s) %v that the PEP registry does not. "+
			"Those planes are dual-evaluated in production and are NOT covered by gate 15.", onlyCompiler)
	}
	if len(fromRegistry) == 0 || len(fromCompiler) == 0 {
		t.Fatal("one of the two plane lists is empty; the comparison above would pass vacuously")
	}
}

// TestGate15CapabilityRefusalArmIsExercised is the OTHER HALF of gate 15,
// exercised deliberately - and it exists because the sweep above does not
// reach it.
//
// # THE FINDING THAT MADE THIS TEST NECESSARY
//
// Over the whole corpus and all twelve real plane profiles, part 2 of the gate
// fires ZERO times: 726 plane-pair comparisons, no licensed differences. That
// is not the planes agreeing about capabilities. It is that the obligations
// this corpus produces are `quota_reservation@1` and `field_mask@1`, which NO
// legacy plane advertises in legacy_plane_peps.tsv, and `field_redact@1` /
// `approval_challenge@1`, which in every corpus scenario CO-OCCUR with one of
// those two. Every plane is therefore equally incapable, every plane denies,
// and the planes agree - correctly, and without ever taking the branch that
// checks WHY they would be allowed to disagree.
//
// A dead arm in a gate is worse than no arm: it reads as coverage. So the arm
// is exercised here against profiles that differ on exactly one capability the
// corpus really produces. The profiles are SYNTHETIC and that is stated rather
// than disguised - what is under test is the classifier's rule, not the
// contents of the capability table.
//
// The finding about the table itself is real and is routed on #3564: either
// those planes genuinely cannot discharge a quota reservation or a field mask -
// in which case every one of them refuses every request that needs one, which
// is a cutover blocker the capability handshake is telling us about - or the
// table under-declares them.
func TestGate15CapabilityRefusalArmIsExercised(t *testing.T) {
	ctx := context.Background()

	// The obligations dana/T2 actually produces, so the "capable" profile can
	// discharge all of them and the "incapable" one exactly one fewer.
	scenario := Scenario{Principal: "dana", Action: "T2", Args: map[string]any{"segment": "all"}}

	capable := &contract.PEPProfile{ID: "test:capable", Capabilities: []contract.Capability{
		{Type: contract.ObApprovalChallenge, Version: 1},
		{Type: contract.ObFieldMask, Version: 1},
		{Type: contract.ObFieldRedact, Version: 1},
		{Type: contract.ObImmutableAudit, Version: 1},
		{Type: contract.ObQuotaReservation, Version: 1},
	}}
	// The SAME set minus field_redact. A strict subset, so the licensed
	// difference is unambiguous.
	incapable := &contract.PEPProfile{ID: "test:incapable", Capabilities: []contract.Capability{
		{Type: contract.ObApprovalChallenge, Version: 1},
		{Type: contract.ObFieldMask, Version: 1},
		{Type: contract.ObImmutableAudit, Version: 1},
		{Type: contract.ObQuotaReservation, Version: 1},
	}}

	decide := func(p *contract.PEPProfile) normalized {
		w, err := NewWorld(ctx, WithPEP(p))
		if err != nil {
			t.Fatalf("building the %s world: %v", p.ID, err)
		}
		d, err := w.Decide(ctx, scenario)
		if err != nil {
			t.Fatalf("%s: %v", p.ID, err)
		}
		return normalize(d)
	}

	ok := decide(capable)
	refused := decide(incapable)

	// ANTI-VACUITY: if the two agree, this test is asserting nothing about the
	// arm, and the arm stays dead behind a green run.
	if ok == refused {
		t.Fatalf("the capable and incapable profiles produced the IDENTICAL decision (%+v). "+
			"Either this scenario stopped producing a mandatory field_redact - in which case "+
			"the arm is dead again and the fixture must be re-chosen - or the PEP profile has "+
			"stopped being consulted at all, which is ADR-065 invariant 8 not being enforced.", ok)
	}
	if !capabilitiesSubsetOf(incapable, capable) {
		t.Fatal("the fixture profiles are not in a subset relation; the assertion below would " +
			"be checking something other than a capability difference")
	}

	// The licensed difference, checked by the SAME function the sweep uses, so
	// this test exercises the production rule rather than a copy of it. The
	// demanded set is read the same way the sweep reads it - from an
	// unconstrained world - rather than being asserted here, so a fixture that
	// stopped demanding a field redaction fails at the anti-vacuity check above
	// instead of quietly passing a hand-written list to the assertion.
	assertCapabilityRefusalExplains(t, "capability_refusal_fixture",
		mandatoryObligationsDemanded(t, scenario),
		"capable", ok, capable, "incapable", refused, incapable)

	// And the direction, stated once more explicitly, because it is the whole
	// safety property: the plane that cannot discharge is the plane that
	// refuses. A capability difference may only ever make a plane MORE
	// restrictive.
	if refused.State != contract.StateDeny {
		t.Fatalf("the plane that cannot discharge a mandatory obligation produced %s, not DENY. "+
			"ADR-065 invariant 8 says an obligation the enforcement point cannot understand or "+
			"enforce produces deny; anything else is a control the request was told about and "+
			"nothing applied.", refused.State)
	}
	if ok.State == contract.StateDeny {
		t.Fatal("the fully capable plane also denied, so the comparison above proves nothing " +
			"about capabilities")
	}
}
