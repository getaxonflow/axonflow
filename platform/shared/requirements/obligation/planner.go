// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"
	"strings"
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
	ReasonApplicabilityUnknown  = "mandatory_obligation_applicability_unknown"
	ReasonSchemaUnknown         = "mandatory_obligation_schema_unknown"
	ReasonSchemaInvalid         = "mandatory_obligation_schema_invalid"
	ReasonCapabilityUnsupported = "mandatory_obligation_capability_unsupported"
	ReasonConflict              = "mandatory_obligation_conflict"
	ReasonDischargeFailed       = "mandatory_obligation_discharge_failed"
	ReasonEvidenceMissing       = "mandatory_obligation_awaiting_completion_evidence"
	ReasonDeliveryNotDurable    = "mandatory_out_of_band_obligation_not_durable"
	ReasonAdvisoryCannotSatisfy = "mandatory_requirement_has_only_an_advisory_obligation"
	ReasonRequirementMissing    = "mandatory_requirement_absent_from_plan"
	ReasonLegacyActionUnmapped  = "legacy_action_has_no_typed_obligation"
	ReasonMalformedInput        = "obligation_planner_input_malformed"
)

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
	// Registry is the sealed obligation registry. Required.
	Registry *Registry
	// Leaves normalizes disclosure field paths. Required whenever a
	// disclosure obligation is present; its absence is a DENY, not a skip.
	Leaves LeafResolver
	// Obligations are the candidate obligations produced by the requirement
	// policies, INCLUDING the ones whose applicability is unknown. Filtering
	// them out before the planner sees them is precisely the source-spec bug.
	Obligations []Obligation
	// PEP is the enforcement plane's capability advertisement.
	PEP PEPCapabilities
	// Evidence maps a capability to what is known about its discharge.
	// A release-gating mandatory obligation absent from this map is treated as
	// EvidenceMissing (CHALLENGE), never as satisfied.
	Evidence map[Capability]EvidenceState
	// RequiredMandatory names obligation types that MUST be present as
	// applicable mandatory obligations. It is how "advisory obligations cannot
	// satisfy a mandatory requirement" becomes checkable: an advisory
	// field_redaction does not discharge a required mandatory field_redaction.
	RequiredMandatory []Type
	// UnmappedLegacyActions are legacy action strings the adapter could not
	// map to a typed obligation. A non-empty list DENIES: an enforcement
	// instruction that survived into the new plane as an unrecognised string
	// must not be silently dropped, which is what the legacy engine's
	// default-case did.
	UnmappedLegacyActions []string
}

// Dropped records one obligation the planner did not carry into the plan, and
// why. Every drop is recorded; nothing leaves the planner silently, because
// the whole class of bug ADR-065 is correcting is a silent drop.
type Dropped struct {
	Type    Type
	Version int
	// Enforcement of the dropped obligation, so a trace reader can see at a
	// glance that only advisory obligations were dropped for soft reasons.
	Enforcement Enforcement
	Reason      string
	Detail      string
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
	// plan.
	Applied []Obligation
	// Advisory lists the applicable advisory obligations that reached the plan.
	Advisory []Obligation
	// Dropped is every obligation that did not reach the plan, with a reason.
	Dropped []Dropped
	// AwaitingEvidence lists the capabilities a CHALLENGE is waiting on.
	AwaitingEvidence []Capability
}

func (r *PlanResult) addReason(code, detail string) {
	r.Reasons = append(r.Reasons, code)
	if detail != "" {
		r.Details = append(r.Details, detail)
	}
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
func Plan(in PlanInput) PlanResult {
	res := &PlanResult{}

	if in.Registry == nil {
		res.addReason(ReasonMalformedInput, "no obligation registry supplied")
		return res.finish(OutcomeError)
	}
	if err := in.PEP.Validate(); err != nil {
		res.addReason(ReasonMalformedInput, err.Error())
		return res.finish(OutcomeError)
	}
	pep := in.PEP.Normalize()

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
			if o.Enforcement == Mandatory {
				deny = true
				res.addReason(ReasonApplicabilityUnknown, fmt.Sprintf(
					"mandatory obligation %s (policy %s) has unknown applicability: %s",
					o.Type, policyLabel(o.SourcePolicyID), o.ApplicabilityReason))
				res.Dropped = append(res.Dropped, Dropped{
					Type: o.Type, Version: o.Version, Enforcement: o.Enforcement,
					Reason: ReasonApplicabilityUnknown, Detail: o.ApplicabilityReason,
				})
				continue
			}
			// Advisory: dropped and recorded. An advisory obligation cannot
			// deny, and an advisory obligation whose applicability is unknown
			// is not evidence of anything.
			res.Dropped = append(res.Dropped, Dropped{
				Type: o.Type, Version: o.Version, Enforcement: o.Enforcement,
				Reason: "advisory_applicability_unknown", Detail: o.ApplicabilityReason,
			})
		case NotApplicable:
			res.Dropped = append(res.Dropped, Dropped{
				Type: o.Type, Version: o.Version, Enforcement: o.Enforcement,
				Reason: "not_applicable", Detail: "the requirement policy's condition did not match",
			})
		case Applicable:
			candidates = append(candidates, o)
		}
	}

	// --- Proof 2: schema and version -------------------------------------
	var known []Obligation
	for _, o := range candidates {
		if err := in.Registry.ValidateObligation(o); err != nil {
			code := ReasonSchemaInvalid
			if _, ok := in.Registry.Lookup(o.Type, o.Version); !ok {
				code = ReasonSchemaUnknown
			}
			if o.Enforcement == Mandatory {
				deny = true
				res.addReason(code, err.Error())
				res.Dropped = append(res.Dropped, Dropped{
					Type: o.Type, Version: o.Version, Enforcement: o.Enforcement,
					Reason: code, Detail: err.Error(),
				})
				continue
			}
			res.Dropped = append(res.Dropped, Dropped{
				Type: o.Type, Version: o.Version, Enforcement: o.Enforcement,
				Reason: "advisory_" + code, Detail: err.Error(),
			})
			continue
		}
		known = append(known, o)
	}

	// --- Proof 3: PEP capability -----------------------------------------
	var supported []Obligation
	for _, o := range known {
		if pep.Supports(o.Capability()) {
			supported = append(supported, o)
			continue
		}
		detail := fmt.Sprintf("PEP %q does not advertise %s (it advertises versions %v of that type)",
			pep.PEPID, o.Capability(), pep.SupportedVersionsOf(o.Type))
		if o.Enforcement == Mandatory {
			deny = true
			res.addReason(ReasonCapabilityUnsupported, detail)
			res.Dropped = append(res.Dropped, Dropped{
				Type: o.Type, Version: o.Version, Enforcement: o.Enforcement,
				Reason: ReasonCapabilityUnsupported, Detail: detail,
			})
			continue
		}
		res.Dropped = append(res.Dropped, Dropped{
			Type: o.Type, Version: o.Version, Enforcement: o.Enforcement,
			Reason: "advisory_" + ReasonCapabilityUnsupported, Detail: detail,
		})
	}

	// --- "advisory cannot satisfy a mandatory requirement" ----------------
	//
	// Checked over `supported` - the obligations that actually reached the
	// plan - and it deliberately looks for a MANDATORY instance. An advisory
	// obligation of the required type is present, discharged and recorded, and
	// still does not satisfy the requirement.
	for _, want := range sortedUnique(typeStrings(in.RequiredMandatory)) {
		wantType := Type(want)
		var haveMandatory, haveAdvisory bool
		for _, o := range supported {
			if o.Type != wantType {
				continue
			}
			if o.Enforcement == Mandatory {
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
	for _, o := range supported {
		if o.Enforcement == Mandatory {
			res.Applied = append(res.Applied, o)
		} else {
			res.Advisory = append(res.Advisory, o)
		}
	}

	// --- Proof 4: no unresolved conflict ---------------------------------
	plan, err := Compose(in.Registry, in.Leaves, supported)
	if err != nil {
		var conflict *ConflictError
		if asConflict(err, &conflict) {
			// A conflict is a governance verdict: two requirement policies
			// disagree and the operator must resolve it.
			res.addReason(ReasonConflict, conflict.Error())
			return res.finish(OutcomeDeny)
		}
		res.addReason(ReasonMalformedInput, err.Error())
		return res.finish(OutcomeError)
	}
	res.Plan = plan

	// --- Proofs 5 and 6: evidence and delivery ----------------------------
	challenge := false
	for _, o := range supported {
		s, _ := in.Registry.Lookup(o.Type, o.Version)
		gates := false
		outOfBand := false
		for _, p := range s.Phases {
			if p.GatesRelease() {
				gates = true
			}
			if p == PhaseOutOfBand {
				outOfBand = true
			}
		}

		if gates {
			state, present := in.Evidence[o.Capability()]
			if !present {
				state = EvidenceMissing
			}
			switch state {
			case EvidenceSatisfied:
			case EvidenceFailed:
				if o.Enforcement == Mandatory {
					deny = true
					res.addReason(ReasonDischargeFailed, fmt.Sprintf(
						"mandatory obligation %s failed to discharge; its schema's failure behaviour is %q", o.Capability(), s.OnFailure))
				}
			case EvidenceMissing:
				if o.Enforcement == Mandatory {
					challenge = true
					res.addReason(ReasonEvidenceMissing, fmt.Sprintf(
						"mandatory obligation %s has not produced its completion evidence (%s)", o.Capability(), s.CompletionEvidence))
					res.AwaitingEvidence = append(res.AwaitingEvidence, o.Capability())
				}
			default:
				res.addReason(ReasonMalformedInput, fmt.Sprintf("unknown evidence state %q for %s", state, o.Capability()))
				return res.finish(OutcomeError)
			}
		}

		if outOfBand && o.Enforcement == Mandatory && s.Delivery != DeliveryAtLeastOnceDurable {
			deny = true
			res.addReason(ReasonDeliveryNotDurable, fmt.Sprintf(
				"mandatory out-of-band obligation %s declares delivery %q; ADR-065 requires a durable delivery contract",
				o.Capability(), s.Delivery))
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
		sort.Slice(res.AwaitingEvidence, func(i, j int) bool {
			if res.AwaitingEvidence[i].Type != res.AwaitingEvidence[j].Type {
				return res.AwaitingEvidence[i].Type < res.AwaitingEvidence[j].Type
			}
			return res.AwaitingEvidence[i].Version < res.AwaitingEvidence[j].Version
		})
		return res.finish(OutcomeChallenge)
	}
	return res.finish(OutcomeAllow)
}

func policyLabel(id string) string {
	if id == "" {
		return "<unattributed>"
	}
	return id
}

func typeStrings(ts []Type) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}

// asConflict is errors.As specialised to *ConflictError. Written out rather
// than importing errors for one call so the unwrap chain this package
// constructs stays visible: Compose returns a *ConflictError directly or wraps
// a formatting error, and nothing in between wraps a conflict.
func asConflict(err error, target **ConflictError) bool {
	for err != nil {
		if c, ok := err.(*ConflictError); ok {
			*target = c
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
