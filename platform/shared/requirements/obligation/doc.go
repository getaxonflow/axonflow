// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package obligation is the STATEFUL obligation planner from ADR-065 (issue
// #3559, epic #3551; consolidated under #3891): executor registration, the six
// pre-permit proofs, completion evidence, the discharge-order DAG, and the
// legacy row adapter.
//
// # What this package does not own
//
// It owns NO vocabulary and NO composition. The obligation types, families,
// parameter keys, the fixed disclosure order, the reviewed subsumption rules,
// the delivery guarantees and the assurance levels are declared once, in
// platform/decision/contract, and composed once, by contract.ComposeObligations
// - the same call the PDP makes on the live decision path. v10.2.0 shipped a
// second algebra here with its own spellings (`field_redaction`,
// `response_filtering`, `schema_constrained_transform`, `audit_notification`,
// `at_least_once_durable`); the two had already drifted, and on the one input
// #3891 reproduces they disagreed. This package now CONSUMES the canonical
// outcome. Two BEHAVIOURAL tests hold that, because they read results rather
// than source: composing one obligation of every family must retain all of
// them, and this package's own tests assert the same literal composed results
// the decision contract's golden table pins - driven by mutation, dropping a
// family from the algebra fails both. TestEveryFamilyHasExactlyOneAlgebra
// additionally refuses an enumerated set of family-dispatch shapes in this
// package's source as a TRIPWIRE against accidental reintroduction; it is not
// a gate, because an AST heuristic cannot prove the absence of a dispatch
// someone is willing to spell differently, and it sleeps through the mutation
// the two behavioural tests catch.
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
// See Applicability and Plan; the shape is pinned by
// TestUnknownApplicabilityOfMandatoryObligationDenies and by the compiling
// mutant in platform/shared/requirements/mutationgate.
//
// # Absent is not unknown
//
// The same tri-state applies one level down, to a disclosure transform's
// TARGET. A target that names no leaf of a KNOWN payload schema is absent from
// it: the instruction is vacuously satisfied, the algebra reports it as
// Unplaced, and the planner excludes it from the completion-evidence proof so
// that nothing waits forever on a receipt for a field that does not exist. A
// target against an UNKNOWN schema cannot be resolved and denies. The two
// shipped algebras collapsed these two facts in opposite directions; the
// planner now hands the algebra an explicit contract.PayloadLeaves and reads
// the answer.
//
// # Edition
//
// This package is community-visible, deliberately, as is the contract it
// consumes. The stateful ENFORCEMENT components - approval authority, signed
// decision proofs and the reservation service - are Enterprise and live in
// sibling packages under //go:build enterprise.
package obligation
