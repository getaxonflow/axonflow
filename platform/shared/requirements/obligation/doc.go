// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package obligation is the typed obligation registry, family composition
// algebras and pre-permit planner from ADR-065 (issue #3559, epic #3551).
//
// # What an obligation is, and what it is not
//
// An obligation is a typed instruction owned by a named enforcement component.
// It is NOT a point on a severity scale. The legacy policy engine treats
// block, redact, warn, log, route and require_approval as a partial order
// (`block > redact > warn > log`) and picks the "most severe" match. ADR-065
// deletes that ranking: redaction, logging, warning, routing, step-up and
// approval are different enforcement OPERATIONS with different owners,
// different phases and different failure behaviour. Nothing here ever compares
// two obligations of different families by rank, and
// TestNoNumericRankingAcrossFamilies pins that.
//
// # The correction this package exists for
//
// In the source proposal an obligations-only ceiling whose condition cannot be
// evaluated resolves "cleanly" - it contributes no deny, so the whole ceiling
// is discarded, and the mandatory redaction it carried is discarded with it.
// That is a fail-OPEN on the exact input where the system knows least. ADR-065
// reverses it: a mandatory obligation whose APPLICABILITY is unknown denies,
// even when the authorization half of the same policy resolved to nothing.
// See Applicability and Planner.Plan; the shape is pinned by
// TestUnknownApplicabilityOfMandatoryObligationDenies and by the compiling
// mutant in platform/shared/requirements/mutationgate.
//
// # Composition
//
// Obligations normalize to canonical atomic targets first, then compose
// through exactly one algebra per FAMILY (see the table in ADR-065
// "Obligations"). A schema validates its own parameters; it can never supply,
// select or override its family's algebra, and it can never declare a pairwise
// precedence exception. That is structural, not conventional: Schema has no
// composition hook, familyAlgebras is an unexported closed map, and
// TestSchemaCannotCarryACompositionHook fails if a func-typed field is ever
// added to Schema beyond the single parameter validator.
//
// # Edition
//
// This package is community-visible, deliberately. The obligation SCHEMA
// surface describes the same class of instruction the shipped redaction
// surface already describes in platform/shared/policy, which is itself
// community-visible; keeping the type vocabulary behind a build tag would mean
// a community PEP could not even name the obligation it is being asked to
// discharge. The stateful ENFORCEMENT components - approval authority, signed
// decision proofs and the reservation service - are Enterprise and live in
// sibling packages under //go:build enterprise.
package obligation
