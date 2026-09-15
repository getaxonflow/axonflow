// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"axonflow/platform/decision/contract"
)

// Outcome is ADR-065's operational decision contract, restricted to what the
// obligation planner can conclude.
type Outcome string

const (
	// OutcomeAllow - every mandatory obligation is known, supported,
	// conflict-free and discharged.
	OutcomeAllow Outcome = "ALLOW"
	// OutcomeDeny - an explicit constraint, an unmet requirement, an
	// unsupported obligation, an unresolved conflict, or a failed discharge.
	OutcomeDeny Outcome = "DENY"
	// OutcomeChallenge - stateful requirements remain: a release-gating
	// mandatory obligation has no completion evidence YET.
	OutcomeChallenge Outcome = "CHALLENGE"
	// OutcomeError - the planner's own input is malformed. Distinct from DENY
	// because it is an outage signal, not a governance verdict; the
	// coordinator applies the action's fail-closed posture, which for every
	// production action is also "do not execute".
	OutcomeError Outcome = "ERROR"
)

// Reason codes. Closed set, safe to expose: they name a class, never a value.
const (
	ReasonApplicabilityUnknown   = "mandatory_obligation_applicability_unknown"
	ReasonSchemaUnknown          = "mandatory_obligation_schema_unknown"
	ReasonSchemaInvalid          = "mandatory_obligation_schema_invalid"
	ReasonCapabilityUnsupported  = "mandatory_obligation_capability_unsupported"
	ReasonConflict               = "mandatory_obligation_conflict"
	ReasonApprovalUnsatisfiable  = "mandatory_obligation_approval_unsatisfiable"
	ReasonDischargeFailed        = "mandatory_obligation_discharge_failed"
	ReasonEvidenceMissing        = "mandatory_obligation_awaiting_completion_evidence"
	ReasonDeliveryNotDurable     = "mandatory_out_of_band_obligation_not_durable"
	ReasonAdvisoryCannotSatisfy  = "mandatory_requirement_has_only_an_advisory_obligation"
	ReasonRequirementMissing     = "mandatory_requirement_absent_from_plan"
	ReasonLegacyActionUnmapped   = "legacy_action_has_no_typed_obligation"
	ReasonMalformedInput         = "obligation_planner_input_malformed"
	ReasonTargetAbsentFromSchema = "mandatory_disclosure_target_absent_from_payload"
)

// compositionDenials is the ONE-TO-ONE translation from the algebra's reason
// codes to the planner's, so a composition denial is carried into the plan
// verdict under the planner's closed set without being re-decided. A code the
// table does not know is an ERROR: the algebra grew a reason this planner
// cannot classify, and a governance verdict must not be guessed at.
var compositionDenials = map[contract.ReasonCode]struct {
	code    string
	outcome Outcome
}{
	contract.ReasonObligationConflict:    {ReasonConflict, OutcomeDeny},
	contract.ReasonApprovalUnsatisfiable: {ReasonApprovalUnsatisfiable, OutcomeDeny},
	// The algebra's "unsupported" covers an instruction it cannot compose (a
	// clause with no quorum, an undeclared assurance) as well as a capability
	// the profile lacks; proof 3 has already refused the second, so what
	// reaches here is the first, which is a schema-level defect in a mandatory
	// instruction and denies.
	contract.ReasonUnsupportedObligation: {ReasonSchemaInvalid, OutcomeDeny},
	// A decoded document that omitted a required member is a plumbing defect,
	// not a governance verdict.
	contract.ReasonSchemaViolation: {ReasonMalformedInput, OutcomeError},
}

// EvidenceState is what the coordinator knows about a release-gating
// obligation's discharge.
//
// Three states, not two, and the third is why: `Missing` and `Failed` produce
// DIFFERENT outcomes. Missing is CHALLENGE - the work has not been done yet
// and the caller should be held. Failed is DENY - the work was attempted and
// did not succeed, and holding the caller forever in the hope it will start
// working is not a governance decision. Collapsing them into one boolean is
// how a failed redaction becomes an indefinite hold, or worse, a permit.
type EvidenceState string

const (
	// EvidenceSatisfied - the obligation was discharged and the evidence the
	// schema names was produced.
	EvidenceSatisfied EvidenceState = "satisfied"
	// EvidenceMissing - not yet discharged.
	EvidenceMissing EvidenceState = "missing"
	// EvidenceFailed - discharge was attempted and failed.
	EvidenceFailed EvidenceState = "failed"
)

// PlanInput is everything the planner needs. Immutable: Plan does not mutate
// it, and every slice it keeps is copied.
type PlanInput struct {
	// Registry is the sealed executor registry. Required.
	Registry *Registry
	// Payload is the tri-state leaf schema disclosure targets expand over. It
	// is handed to the algebra unchanged; the planner does not resolve leaves.
	// A zero value is an unknown schema with no reason, which the algebra
	// refuses as malformed when a disclosure obligation is present.
	Payload contract.PayloadLeaves
	// Obligations are the candidate obligations produced by the requirement
	// policies, INCLUDING the ones whose applicability is unknown. Filtering
	// them out before the planner sees them is precisely the source-spec bug.
	Obligations []Obligation
	// PEP is the enforcement plane's capability advertisement, in the same
	// type the handshake decodes to. Required and must carry an identifier:
	// an unidentified plane cannot be bound into a decision proof.
	PEP *contract.PEPProfile
	// Evidence maps a capability to what is known about its discharge.
	// A release-gating mandatory obligation absent from this map is treated as
	// EvidenceMissing (CHALLENGE), never as satisfied.
	Evidence map[contract.Capability]EvidenceState
	// RequiredMandatory names obligation types that MUST be present as
	// applicable mandatory obligations. It is how "advisory obligations cannot
	// satisfy a mandatory requirement" becomes checkable: an advisory
	// field_redact does not discharge a required mandatory field_redact.
	RequiredMandatory []contract.ObligationType
	// UnmappedLegacyActions are legacy action strings the adapter could not
	// map to a typed obligation. A non-empty list DENIES: an enforcement
	// instruction that survived into the new plane as an unrecognised string
	// must not be silently dropped, which is what the legacy engine's
	// default-case did.
	UnmappedLegacyActions []string
	// ApprovalExpiry and Now are handed to the algebra for the approval
	// family's expiry rule. See contract.ComposeInput.
	ApprovalExpiry time.Time
	Now            time.Time
}

// Dropped records one obligation the planner did not carry into the plan, and
// why. Every drop is recorded; nothing leaves the planner silently, because
// the whole class of bug ADR-065 is correcting is a silent drop.
type Dropped struct {
	Type    contract.ObligationType
	Version int
	// Mandatory of the dropped obligation, so a trace reader can see at a
	// glance that only advisory obligations were dropped for soft reasons.
	Mandatory bool
	Reason    string
	Detail    string
}

// ComposedPlan is the composed result the executors are handed. It IS the algebra's
// outcome plus a discharge order; the planner adds nothing to the instructions
// and removes nothing from them.
type ComposedPlan struct {
	// Obligations is the composed, conflict-free instruction set, canonically
	// ordered, exactly as contract.ComposeObligations produced it. An executor
	// selects its work by Type.
	Obligations []contract.Obligation
	// Approval is the composed approval requirement, or nil.
	Approval *contract.ApprovalRequirement
	// Unplaced names mandatory disclosure transforms whose target is ABSENT
	// from the known payload schema. They are vacuously satisfied, reported so
	// the drift case stays visible, and excluded from the completion-evidence
	// proof: nothing waits on a receipt for a field that does not exist.
	Unplaced []contract.Obligation
	// DroppedAdvisory names advisory obligations the algebra could not compose
	// beside the required set, and DropDetail says why.
	DroppedAdvisory []contract.Obligation
	DropDetail      string
	// Order is the topologically sorted discharge order of the obligation
	// types present in the plan.
	Order []contract.ObligationType
}

// PlanResult is the planner's verdict plus the full trace.
type PlanResult struct {
	Outcome Outcome
	// Reasons are closed-set reason codes, sorted and deduplicated.
	Reasons []string
	// Details are human-readable expansions, sorted. Safe for an operator
	// audience; they name policies, types and field paths, never values.
	Details []string
	// Plan is the composed plan. Populated on ALLOW and on CHALLENGE (a
	// challenge still needs to know what it is holding for); empty on DENY and
	// ERROR.
	Plan ComposedPlan
	// Applied lists the applicable mandatory obligations that reached the
	// algebra.
	Applied []Obligation
	// Advisory lists the applicable advisory obligations that reached the
	// algebra.
	Advisory []Obligation
	// Dropped is every obligation that did not reach the plan, with a reason.
	Dropped []Dropped
	// AwaitingEvidence lists the capabilities a CHALLENGE is waiting on.
	AwaitingEvidence []contract.Capability
}

func (r *PlanResult) addReason(code, detail string) {
	r.Reasons = append(r.Reasons, code)
	if detail != "" {
		r.Details = append(r.Details, detail)
	}
}

func (r *PlanResult) drop(o Obligation, reason, detail string) {
	r.Dropped = append(r.Dropped, Dropped{
		Type: o.Type, Version: o.SchemaVersion, Mandatory: o.Mandatory, Reason: reason, Detail: detail,
	})
}

func (r *PlanResult) finish(o Outcome) PlanResult {
	r.Outcome = o
	r.Reasons = sortedUnique(r.Reasons)
	r.Details = sortedUnique(r.Details)
	sort.Slice(r.Dropped, func(i, j int) bool {
		if r.Dropped[i].Type != r.Dropped[j].Type {
			return r.Dropped[i].Type < r.Dropped[j].Type
		}
		return r.Dropped[i].Reason < r.Dropped[j].Reason
	})
	return *r
}

// Plan runs ADR-065's six pre-permit proofs and returns the outcome.
//
// The proofs, in the order they are applied and with the outcome each can
// produce:
//
//  1. every potentially applicable MANDATORY obligation has KNOWN
//     applicability                                            -> else DENY
//  2. every applicable obligation has a known schema and version -> else DENY
//     (mandatory) / dropped-and-recorded (advisory)
//  3. the PEP advertises the EXACT capability and version        -> else DENY
//     (mandatory) / dropped-and-recorded (advisory)
//  4. the set has no unresolved conflict                         -> else DENY
//  5. pre-execution (release-gating) obligations have completion
//     evidence                             -> missing: CHALLENGE, failed: DENY
//  6. required post-execution obligations have a durable delivery
//     contract                                                   -> else DENY
//
// Proof 1 runs FIRST and over the unfiltered candidate list, which is the
// whole correction: the source spec's evaluator had already discarded the
// unknown-applicability obligation by the time anything equivalent to proofs
// 2-6 ran, so there was nothing left to deny on.
//
// PROOF 4 IS NOT DECIDED HERE. The planner hands the surviving candidates to
// contract.ComposeObligations - the same call the PDP makes - and consumes
// its outcome. There is no family dispatch, no disclosure order and no
// parameter merge in this package; TestEveryFamilyHasExactlyOneAlgebra fails
// the build the day one appears.
func Plan(in PlanInput) PlanResult {
	res := &PlanResult{}

	if in.Registry == nil {
		res.addReason(ReasonMalformedInput, "no obligation registry supplied")
		return res.finish(OutcomeError)
	}
	if err := validateProfile(in.PEP); err != nil {
		res.addReason(ReasonMalformedInput, err.Error())
		return res.finish(OutcomeError)
	}

	// A legacy action that could not be mapped is an enforcement instruction
	// with nowhere to go. Denying here, before anything else, is deliberate:
	// it is not conditional on what the mapped obligations happen to say.
	if len(in.UnmappedLegacyActions) > 0 {
		res.addReason(ReasonLegacyActionUnmapped,
			fmt.Sprintf("legacy actions with no typed obligation: %s", strings.Join(sortedUnique(in.UnmappedLegacyActions), ", ")))
		return res.finish(OutcomeDeny)
	}

	// Structural validation of the planner's own input. A malformed
	// Obligation (empty type, version 0, unknown applicability enum) is a
	// plumbing defect, so it is ERROR rather than DENY - both refuse to
	// execute, but only one of them pages the owning service.
	for i, o := range in.Obligations {
		if err := o.Validate(); err != nil {
			res.addReason(ReasonMalformedInput, fmt.Sprintf("obligation %d: %v", i, err))
			return res.finish(OutcomeError)
		}
	}

	deny := false

	// --- Proof 1: applicability -----------------------------------------
	var candidates []Obligation
	for _, o := range in.Obligations {
		switch o.Applicability {
		case Unknown:
			if o.Mandatory {
				deny = true
				res.addReason(ReasonApplicabilityUnknown, fmt.Sprintf(
					"mandatory obligation %s (policy %s) has unknown applicability: %s",
					o.Type, policyLabel(o.SourcePolicy), applicabilityDetail(o)))
				res.drop(o, ReasonApplicabilityUnknown, applicabilityDetail(o))
				continue
			}
			// Advisory: dropped and recorded. An advisory obligation cannot
			// deny, and an advisory obligation whose applicability is unknown
			// is not evidence of anything.
			res.drop(o, "advisory_applicability_unknown", applicabilityDetail(o))
		case NotApplicable:
			res.drop(o, "not_applicable", "the requirement policy's condition did not match")
		case Applicable:
			candidates = append(candidates, o)
		}
	}

	// --- Proof 2: schema and version -------------------------------------
	var known []Obligation
	for _, o := range candidates {
		if err := in.Registry.ValidateObligation(o); err != nil {
			code := ReasonSchemaInvalid
			if _, ok := in.Registry.Lookup(o.Type, o.SchemaVersion); !ok {
				code = ReasonSchemaUnknown
			}
			if o.Mandatory {
				deny = true
				res.addReason(code, err.Error())
				res.drop(o, code, err.Error())
				continue
			}
			res.drop(o, "advisory_"+code, err.Error())
			continue
		}
		known = append(known, o)
	}

	// --- Proof 3: PEP capability -----------------------------------------
	var supported []Obligation
	for _, o := range known {
		if in.PEP.Supports(o.Obligation) {
			supported = append(supported, o)
			continue
		}
		detail := fmt.Sprintf("PEP %q does not advertise %s (it advertises versions %v of that type)",
			in.PEP.ID, o.Capability(), supportedVersionsOf(in.PEP, o.Type))
		if o.Mandatory {
			deny = true
			res.addReason(ReasonCapabilityUnsupported, detail)
			res.drop(o, ReasonCapabilityUnsupported, detail)
			continue
		}
		res.drop(o, "advisory_"+ReasonCapabilityUnsupported, detail)
	}

	// --- "advisory cannot satisfy a mandatory requirement" ----------------
	//
	// Checked over `supported` - the obligations that actually reached the
	// plan - and it deliberately looks for a MANDATORY instance. An advisory
	// obligation of the required type is present, discharged and recorded, and
	// still does not satisfy the requirement.
	for _, want := range sortedUnique(typeStrings(in.RequiredMandatory)) {
		wantType := contract.ObligationType(want)
		var haveMandatory, haveAdvisory bool
		for _, o := range supported {
			if o.Type != wantType {
				continue
			}
			if o.Mandatory {
				haveMandatory = true
			} else {
				haveAdvisory = true
			}
		}
		if haveMandatory {
			continue
		}
		deny = true
		if haveAdvisory {
			res.addReason(ReasonAdvisoryCannotSatisfy, fmt.Sprintf(
				"requirement %s is mandatory, but the plan carries only an advisory instance of it", wantType))
		} else {
			res.addReason(ReasonRequirementMissing, fmt.Sprintf(
				"requirement %s is mandatory and no applicable, supported instance reached the plan", wantType))
		}
	}

	// Split before composition so a later reader can tell which obligations
	// were binding. Composition itself runs over BOTH: an advisory redaction
	// still has to be composed, because it changes what is applied to a leaf,
	// and dropping it from composition would silently ignore it.
	canonical := make([]contract.Obligation, 0, len(supported))
	for _, o := range supported {
		if o.Mandatory {
			res.Applied = append(res.Applied, o)
		} else {
			res.Advisory = append(res.Advisory, o)
		}
		canonical = append(canonical, o.Obligation)
	}

	// --- Proof 4: no unresolved conflict - THE ALGEBRA, CONSUMED ----------
	composed := contract.ComposeObligations(contract.ComposeInput{
		Obligations:    canonical,
		Payload:        in.Payload,
		PEP:            in.PEP,
		ApprovalExpiry: in.ApprovalExpiry,
		Now:            in.Now,
		Subsumption:    in.Registry.Subsumption(),
	})
	if composed.Denied {
		translated, known := compositionDenials[composed.Reason]
		if !known {
			res.addReason(ReasonMalformedInput, fmt.Sprintf("composition denied with reason %q, which this planner cannot classify: %s", composed.Reason, composed.Detail))
			return res.finish(OutcomeError)
		}
		res.addReason(translated.code, fmt.Sprintf("%s: %s", composed.Reason, composed.Detail))
		return res.finish(translated.outcome)
	}
	for _, o := range composed.Unplaced {
		res.addReason(ReasonTargetAbsentFromSchema, fmt.Sprintf(
			"mandatory %s targeting %q (policy %s) names no leaf of the known payload schema and is vacuously satisfied; "+
				"if the schema has drifted behind the real payload this is a redaction deleted rather than honoured",
			o.Type, o.Target, policyLabel(o.SourcePolicy)))
	}
	plan := ComposedPlan{
		Obligations:     composed.Obligations,
		Approval:        composed.Approval,
		Unplaced:        composed.Unplaced,
		DroppedAdvisory: composed.DroppedAdvisory,
		DropDetail:      composed.DropDetail,
	}
	for _, o := range composed.DroppedAdvisory {
		res.Dropped = append(res.Dropped, Dropped{
			Type: o.Type, Version: o.SchemaVersion, Mandatory: false,
			Reason: "advisory_does_not_compose", Detail: composed.DropDetail,
		})
	}

	// --- Discharge order: scheduling, not composition ---------------------
	order, err := composePhaseOrder(in.Registry, composed.Obligations)
	if err != nil {
		res.addReason(ReasonConflict, err.Error())
		return res.finish(OutcomeDeny)
	}
	plan.Order = order
	// The plan is published here so a CHALLENGE can say what it is holding
	// for. EVERY path out of this function that is not ALLOW or CHALLENGE must
	// clear it again: handing a caller a composed plan for a decision that
	// denied or errored invites an enforcement point to act on it, and the two
	// ERROR paths below are as capable of that as the DENY path at the end.
	res.Plan = plan

	// --- Proofs 5 and 6: evidence and delivery ----------------------------
	//
	// Over the COMPOSED set. A transform the algebra merged away, and a
	// mandatory transform whose target is absent, are not waiting on anything.
	challenge := false
	for _, o := range composed.Obligations {
		if !o.Mandatory {
			continue
		}
		s, ok := in.Registry.Lookup(o.Type, o.SchemaVersion)
		if !ok {
			// Unreachable while the algebra only merges obligations of the
			// types it was handed, all of which passed proof 2. Refusing
			// rather than skipping is the safe direction if that ever changes.
			res.addReason(ReasonMalformedInput, fmt.Sprintf("composed obligation %s has no registered schema", o.CapabilityOf()))
			res.Plan = ComposedPlan{}
			return res.finish(OutcomeError)
		}
		gates, outOfBand := false, false
		for _, p := range s.Phases {
			if p.GatesRelease() {
				gates = true
			}
			if p == PhaseOutOfBand {
				outOfBand = true
			}
		}
		if gates {
			state, present := in.Evidence[o.CapabilityOf()]
			if !present {
				state = EvidenceMissing
			}
			switch state {
			case EvidenceSatisfied:
			case EvidenceFailed:
				deny = true
				res.addReason(ReasonDischargeFailed, fmt.Sprintf(
					"mandatory obligation %s failed to discharge; its schema's failure behaviour is %q", o.CapabilityOf(), s.OnFailure))
			case EvidenceMissing:
				challenge = true
				res.addReason(ReasonEvidenceMissing, fmt.Sprintf(
					"mandatory obligation %s has not produced its completion evidence (%s)", o.CapabilityOf(), s.CompletionEvidence))
				res.AwaitingEvidence = append(res.AwaitingEvidence, o.CapabilityOf())
			default:
				res.addReason(ReasonMalformedInput, fmt.Sprintf("unknown evidence state %q for %s", state, o.CapabilityOf()))
				res.Plan = ComposedPlan{}
				return res.finish(OutcomeError)
			}
		}
		if outOfBand && s.Delivery != contract.DeliveryDurable {
			deny = true
			res.addReason(ReasonDeliveryNotDurable, fmt.Sprintf(
				"mandatory out-of-band obligation %s is executed under delivery %q; ADR-065 requires a durable delivery contract (%q)",
				o.CapabilityOf(), s.Delivery, contract.DeliveryDurable))
		}
	}

	// DENY beats CHALLENGE. A challenge invites the caller back; if any
	// mandatory obligation has already established that this request cannot
	// proceed, inviting them back would be a lie and would keep an approval
	// queue entry alive for a request that can never be approved.
	if deny {
		res.Plan = ComposedPlan{}
		return res.finish(OutcomeDeny)
	}
	if challenge {
		res.AwaitingEvidence = contract.SortCapabilities(res.AwaitingEvidence)
		return res.finish(OutcomeChallenge)
	}
	return res.finish(OutcomeAllow)
}

// validateProfile refuses an advertisement that cannot be bound into a proof.
func validateProfile(p *contract.PEPProfile) error {
	if p == nil {
		return fmt.Errorf("pep profile: none supplied; an enforcement point that advertised nothing is not admitted")
	}
	if p.ID == "" {
		return fmt.Errorf("pep profile: id is required")
	}
	for _, c := range p.Capabilities {
		if c.Type == "" {
			return fmt.Errorf("pep profile: capability with empty type")
		}
		if c.Version <= 0 {
			return fmt.Errorf("pep profile: %s advertises version %d; 0 does not mean 'any'", c.Type, c.Version)
		}
	}
	return nil
}

// supportedVersionsOf lists the versions of one type a profile advertises.
// Used only to build a helpful refusal ("you support v1, the plan needs v2"),
// never to relax the exact-version rule.
func supportedVersionsOf(p *contract.PEPProfile, t contract.ObligationType) []int {
	var vs []int
	for _, c := range p.Capabilities {
		if c.Type == t {
			vs = append(vs, c.Version)
		}
	}
	sort.Ints(vs)
	return vs
}

func applicabilityDetail(o Obligation) string {
	if o.ApplicabilityDetail == "" {
		return string(o.ApplicabilityReason)
	}
	return string(o.ApplicabilityReason) + ": " + o.ApplicabilityDetail
}

func policyLabel(id string) string {
	if id == "" {
		return "<unattributed>"
	}
	return id
}

func typeStrings(ts []contract.ObligationType) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}

// composePhaseOrder topologically sorts the obligation types present in the
// plan by their declared dependencies. A cycle denies; so does a dependency on
// a type that IS present but has no registered owner (a missing executor).
//
// A dependency on a type that is ABSENT from the plan is not an error: nothing
// has to run before something that is not running.
//
// This is SCHEDULING, not composition: it reads the executor registry, never
// an obligation's parameters, and it cannot change what any instruction says.
func composePhaseOrder(reg *Registry, obs []contract.Obligation) ([]contract.ObligationType, error) {
	present := map[contract.ObligationType]Schema{}
	for _, o := range obs {
		s, ok := reg.Lookup(o.Type, o.SchemaVersion)
		if !ok {
			return nil, fmt.Errorf("phase order: no schema for %s", o.CapabilityOf())
		}
		if s.Owner == "" {
			return nil, fmt.Errorf("phase order: obligation %s has no owning executor", o.Type)
		}
		present[o.Type] = s
	}

	// Kahn's algorithm over the present subgraph, with ties broken by type
	// name so the order is deterministic and a trace is diffable.
	indeg := map[contract.ObligationType]int{}
	edges := map[contract.ObligationType][]contract.ObligationType{} // dep -> dependents
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

	ready := make([]contract.ObligationType, 0, len(indeg))
	for t, d := range indeg {
		if d == 0 {
			ready = append(ready, t)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i] < ready[j] })

	out := make([]contract.ObligationType, 0, len(indeg))
	for len(ready) > 0 {
		t := ready[0]
		ready = ready[1:]
		out = append(out, t)
		next := append([]contract.ObligationType(nil), edges[t]...)
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
		remaining := map[contract.ObligationType]struct{}{}
		for t, d := range indeg {
			if d > 0 {
				remaining[t] = struct{}{}
			}
		}
		return nil, fmt.Errorf("phase order: dependency cycle through %s; no discharge order exists",
			strings.Join(sortedTypes(remaining), ","))
	}
	return out, nil
}
