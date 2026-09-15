// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"axonflow/platform/decision/contract"
)

// InitialRegistryVersion is the snapshot version of the initial registry. It
// is bound into every decision proof; bump it whenever a schema in
// NewInitialRegistry changes in ANY way, including a parameter validator,
// because a proof issued under the old meaning must not verify under the new
// one.
//
// v2 (2026-09-10, #3891): the registry now registers every type of the ONE
// canonical vocabulary rather than the nine ADR-065 named in prose, under the
// canonical spellings; a proof bound to the v1 snapshot named types that no
// longer exist under those names.
const InitialRegistryVersion = "obligations-2026-09-10.v2"

// NewInitialRegistry returns an executor registration for EVERY type in the
// canonical vocabulary, with NO subsumption rules.
//
// Every type, and not the nine ADR-065 lists in prose, because the PDP emits
// the whole vocabulary (a policy may attach field_mask or field_hash today)
// and a registry with no executor for a type the decision can carry would
// deny every such decision at proof 2 for want of a schema nobody had thought
// to write. TestInitialRegistryDefinesEveryCanonicalType pins the coverage in
// both directions.
//
// The empty subsumption set is a deliberate shipped state, not an oversight:
// ADR-065 makes incomparable disclosure transforms DENY unless a reviewed rule
// says otherwise, and no rule has been reviewed.
// TestInitialRegistryShipsNoSubsumptionRules fails if one is added without
// that review, which is what keeps the escape hatch from quietly becoming the
// norm.
func NewInitialRegistry() (*Registry, error) {
	b := NewRegistryBuilder(InitialRegistryVersion)

	// approval_challenge - the only obligation whose executor is a stateful
	// authority rather than a transform. Request phase: it gates execution.
	b.Add(Schema{
		Type:               contract.ObApprovalChallenge,
		Version:            1,
		Owner:              "approval_authority",
		Phases:             []Phase{PhaseRequest},
		Idempotent:         true,
		CompletionEvidence: "approval_decision_record",
		OnFailure:          FailClosed,
		// NO ValidateParams HOOK, AND ITS ABSENCE IS THE POINT.
		//
		// An earlier version of this schema re-implemented ADR-065's
		// coordinated approval-and-reservation ceiling here, with its own
		// 7-day literal. An independent review named it as exactly the "second
		// parameter model" this consolidation's reuse census claims does not
		// exist - and it could never run: the ceiling belongs on the live
		// composition path, which no caller reaches through this registry.
		// It now lives once, in contract.MaxApprovalExpirySeconds, where the
		// algebra enforces it on every deployment.
	})

	// The field transforms share ONE executor, the redaction engine, in both
	// phases: the target names which payload the field belongs to. Each is
	// its own capability because a PEP advertises which transforms it can
	// perform, and a point that can redact cannot necessarily tokenize.
	for _, t := range []contract.ObligationType{
		contract.ObFieldRemove, contract.ObFieldRedact, contract.ObFieldHash,
		contract.ObFieldMask, contract.ObFieldAnnotate, contract.ObFieldTokenize,
	} {
		b.Add(Schema{
			Type:               t,
			Version:            1,
			Owner:              "redaction_engine",
			Phases:             []Phase{PhaseRequest, PhaseResponse},
			Idempotent:         true,
			CompletionEvidence: "engine_redaction_receipt",
			OnFailure:          FailClosed,
		})
	}

	// schema_transform - a declared transform validated against the action's
	// field schema. Same family as redaction: it changes what a reader learns
	// from a leaf, so it composes on the same order (as an incomparable).
	b.Add(Schema{
		Type:               contract.ObSchemaTransform,
		Version:            1,
		Owner:              "transform_engine",
		Phases:             []Phase{PhaseRequest, PhaseResponse},
		Idempotent:         true,
		CompletionEvidence: "engine_transform_receipt",
		OnFailure:          FailClosed,
	})

	// response_filter - response-phase row filter. It gates the release of the
	// response, so it carries completion evidence.
	b.Add(Schema{
		Type:               contract.ObResponseFilter,
		Version:            1,
		Owner:              "response_filter",
		Phases:             []Phase{PhaseResponse},
		Idempotent:         true,
		CompletionEvidence: "engine_filter_receipt",
		OnFailure:          FailClosed,
	})

	// route_restriction.
	b.Add(Schema{
		Type:               contract.ObRouteRestriction,
		Version:            1,
		Owner:              "egress_router",
		Phases:             []Phase{PhaseRequest},
		Idempotent:         true,
		CompletionEvidence: "route_selection_record",
		OnFailure:          FailClosed,
	})

	// immutable_audit - out-of-band, and mandatory audit is exactly the case
	// ADR-065's pre-permit proof 6 exists for: its EXECUTOR must provide a
	// DURABLE delivery contract or the decision denies.
	b.Add(Schema{
		Type:       contract.ObImmutableAudit,
		Version:    1,
		Owner:      "audit_sink",
		Phases:     []Phase{PhaseOutOfBand},
		Idempotent: true,
		Delivery:   contract.DeliveryDurable,
		OnFailure:  FailClosed,
	})

	// notification - out-of-band. Ships DURABLE as well: a notification
	// obligation that a policy made mandatory and that is dropped on the first
	// transient failure is a governance control that silently did not happen.
	// An advisory instance of the same schema is still free to be lost, which
	// is what the mandatory flag, not the executor's delivery, decides.
	b.Add(Schema{
		Type:       contract.ObNotification,
		Version:    1,
		Owner:      "notification_service",
		Phases:     []Phase{PhaseOutOfBand},
		Idempotent: false, // resending a notification is visible to a human
		Delivery:   contract.DeliveryDurable,
		OnFailure:  FailClosed,
	})

	// quota_reservation.
	b.Add(Schema{
		Type:               contract.ObQuotaReservation,
		Version:            1,
		Owner:              "reservation_service",
		Phases:             []Phase{PhaseRequest},
		Idempotent:         true, // by reservation key; that is the contract
		CompletionEvidence: "reservation_receipt",
		OnFailure:          FailClosed,
	})

	// step_up_authentication - gates the request, and the approval challenge
	// depends on it: challenging a human for approval before the session has
	// reached the required assurance would collect an approval from a
	// weakly-authenticated principal.
	b.Add(Schema{
		Type:               contract.ObStepUpAuth,
		Version:            1,
		Owner:              "authn_service",
		Phases:             []Phase{PhaseRequest},
		Idempotent:         true,
		CompletionEvidence: "assurance_attestation",
		OnFailure:          FailClosed,
	})

	return b.Build()
}

// initialDependencies wires the cross-type ordering that the schemas above
// declare as data.
//
// It is applied by NewInitialRegistryWithOrdering rather than being inlined in
// the DependsOn fields, so that the dependency GRAPH is visible in one place.
// A reviewer checking "is this DAG acyclic and does every edge have a reason"
// reads this function, not fourteen scattered fields.
// Two edges, each with its reason:
//
//   - approval_challenge <- step_up_authentication: approval is collected only
//     from a session that has already reached the required assurance.
//     Challenging a human before step-up would record an approval from a
//     weakly-authenticated principal.
//   - approval_challenge <- quota_reservation: capacity is reserved BEFORE the
//     human is asked, so the approval window holds real capacity rather than
//     an option on capacity another request may take meanwhile. This is the
//     ordering the measured two-concurrent-approvals race requires; see
//     platform/shared/requirements/reservation.
var initialDependencies = map[contract.ObligationType][]contract.ObligationType{
	contract.ObApprovalChallenge: {contract.ObStepUpAuth, contract.ObQuotaReservation},
}

// NewInitialRegistryWithOrdering returns the initial registry with the
// cross-type dependency edges applied.
func NewInitialRegistryWithOrdering() (*Registry, error) {
	base, err := NewInitialRegistry()
	if err != nil {
		return nil, err
	}
	b := NewRegistryBuilder(InitialRegistryVersion)
	for _, c := range base.Capabilities() {
		s, _ := base.Lookup(c.Type, c.Version)
		if deps, ok := initialDependencies[s.Type]; ok && len(deps) > 0 {
			s.DependsOn = append([]contract.ObligationType(nil), deps...)
		}
		b.Add(s)
	}
	for _, r := range base.SubsumptionRules() {
		b.AddSubsumption(r)
	}
	return b.Build()
}
