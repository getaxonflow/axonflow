// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import "fmt"

// InitialRegistryVersion is the snapshot version of the initial registry. It
// is bound into every decision proof; bump it whenever a schema in
// NewInitialRegistry changes in ANY way, including a parameter validator,
// because a proof issued under the old meaning must not verify under the new
// one.
const InitialRegistryVersion = "obligations-2026-08-30.v1"

// NewInitialRegistry returns the nine initial obligation types from ADR-065
// with NO subsumption rules.
//
// The empty subsumption set is a deliberate shipped state, not an oversight:
// ADR-065 makes incomparable disclosure transforms DENY unless a reviewed rule
// says otherwise, and no rule has been reviewed. TestInitialRegistryShipsNoSubsumptionRules
// fails if one is added without that review, which is what keeps the escape
// hatch from quietly becoming the norm.
func NewInitialRegistry() (*Registry, error) {
	b := NewRegistryBuilder(InitialRegistryVersion)

	// 1. approval_challenge - the only obligation whose executor is a stateful
	// authority rather than a transform. Request phase: it gates execution.
	b.Add(Schema{
		Type:               TypeApprovalChallenge,
		Version:            1,
		Family:             FamilyApproval,
		Owner:              "approval_authority",
		Phases:             []Phase{PhaseRequest},
		Idempotent:         true,
		CompletionEvidence: "approval_decision_record",
		OnFailure:          FailClosed,
		ValidateParams: func(p Params) error {
			ap, ok := p.(ApprovalParams)
			if !ok {
				return fmt.Errorf("expected ApprovalParams, got %T", p)
			}
			// Schema-level check the generic validator cannot make: an
			// approval whose expiry exceeds the reservation hold window would
			// leave capacity pinned longer than the reservation service will
			// hold it, and the two lifetimes must be coordinated (ADR-065
			// "coordinated approval and reservation expiry"). 7 days is the
			// outer bound the reservation service commits to.
			const maxExpirySeconds = 7 * 24 * 60 * 60
			if ap.ExpirySeconds > maxExpirySeconds {
				return fmt.Errorf("expiry_seconds %d exceeds the %d-second maximum an approval hold can be coordinated with a reservation",
					ap.ExpirySeconds, maxExpirySeconds)
			}
			return nil
		},
	})

	// 2. field_redaction - request-phase disclosure transform.
	b.Add(Schema{
		Type:               TypeFieldRedaction,
		Version:            1,
		Family:             FamilyDisclosure,
		Owner:              "redaction_engine",
		Phases:             []Phase{PhaseRequest},
		Idempotent:         true,
		CompletionEvidence: "engine_redaction_receipt",
		OnFailure:          FailClosed,
	})

	// 3. schema_constrained_transform - a declared transform validated against
	// the action's field schema. Same family as redaction: it changes what a
	// reader learns from a leaf, so it composes on the same lattice.
	b.Add(Schema{
		Type:               TypeSchemaConstrainedTransform,
		Version:            1,
		Family:             FamilyDisclosure,
		Owner:              "transform_engine",
		Phases:             []Phase{PhaseRequest, PhaseResponse},
		Idempotent:         true,
		CompletionEvidence: "engine_transform_receipt",
		OnFailure:          FailClosed,
	})

	// 4. route_restriction.
	b.Add(Schema{
		Type:               TypeRouteRestriction,
		Version:            1,
		Family:             FamilyRouting,
		Owner:              "egress_router",
		Phases:             []Phase{PhaseRequest},
		Idempotent:         true,
		CompletionEvidence: "route_selection_record",
		OnFailure:          FailClosed,
	})

	// 5. immutable_audit - out-of-band, and mandatory audit is exactly the
	// case ADR-065's pre-permit proof 6 exists for: it must have a DURABLE
	// delivery contract or the decision denies.
	b.Add(Schema{
		Type:       TypeImmutableAudit,
		Version:    1,
		Family:     FamilyAuditNotification,
		Owner:      "audit_sink",
		Phases:     []Phase{PhaseOutOfBand},
		Idempotent: true,
		Delivery:   DeliveryAtLeastOnceDurable,
		OnFailure:  FailClosed,
	})

	// 6. notification - out-of-band. Ships DURABLE as well: a notification
	// obligation that a policy made mandatory and that is dropped on the first
	// transient failure is a governance control that silently did not happen.
	// An advisory instance of the same schema is still free to be lost, which
	// is what Enforcement, not Delivery, decides.
	b.Add(Schema{
		Type:       TypeNotification,
		Version:    1,
		Family:     FamilyAuditNotification,
		Owner:      "notification_service",
		Phases:     []Phase{PhaseOutOfBand},
		Idempotent: false, // resending a notification is visible to a human
		Delivery:   DeliveryAtLeastOnceDurable,
		OnFailure:  FailClosed,
	})

	// 7. quota_reservation.
	b.Add(Schema{
		Type:               TypeQuotaReservation,
		Version:            1,
		Family:             FamilyBudget,
		Owner:              "reservation_service",
		Phases:             []Phase{PhaseRequest},
		Idempotent:         true, // by reservation key; that is the contract
		CompletionEvidence: "reservation_receipt",
		OnFailure:          FailClosed,
	})

	// 8. step_up_authentication - gates the request, and the approval
	// challenge depends on it: challenging a human for approval before the
	// session has reached the required assurance would collect an approval
	// from a weakly-authenticated principal.
	b.Add(Schema{
		Type:               TypeStepUpAuthentication,
		Version:            1,
		Family:             FamilyStepUp,
		Owner:              "authn_service",
		Phases:             []Phase{PhaseRequest},
		Idempotent:         true,
		CompletionEvidence: "assurance_attestation",
		OnFailure:          FailClosed,
	})

	// 9. response_filtering - response-phase disclosure transform. It gates
	// the release of the response, so it carries completion evidence.
	b.Add(Schema{
		Type:               TypeResponseFiltering,
		Version:            1,
		Family:             FamilyDisclosure,
		Owner:              "response_filter",
		Phases:             []Phase{PhaseResponse},
		Idempotent:         true,
		CompletionEvidence: "engine_filter_receipt",
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
// reads this function, not nine scattered fields.
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
var initialDependencies = map[Type][]Type{
	TypeApprovalChallenge: {TypeStepUpAuthentication, TypeQuotaReservation},
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
			s.DependsOn = append([]Type(nil), deps...)
		}
		b.Add(s)
	}
	for _, r := range base.SubsumptionRules() {
		b.AddSubsumption(r)
	}
	return b.Build()
}
