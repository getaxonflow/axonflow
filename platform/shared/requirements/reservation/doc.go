// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package reservation is the ADR-065 atomic quota and budget reservation
// service: contract, lifecycle and an in-memory reference implementation
// (issue #3561, epic #3551).
//
// # Edition
//
// Every file except this one carries `//go:build enterprise`, and that
// placement is a FLAGGED decision rather than a settled one. The shipped cost
// API is registered unconditionally in the community repo, so "budgets" is not
// straightforwardly Enterprise; but the machinery here - linearizable
// admission, fencing, approval-coordinated holds - is new and is the
// enforcement half rather than the reporting half. The brief's rule for
// ambiguity is Enterprise plus a flag, so: Enterprise, flagged, and the
// decision is the operator's to reverse. Moving it is a build-tag change and
// nothing else; nothing in this package touches a licence tier.
//
// # Why this cannot be a counter
//
// Budget policy is stateful and cannot be made correct through a parameter
// hash or an eventually consistent counter. Two concurrent approvals against
// one budget both passed in the current system - that is a MEASURED result,
// not a theoretical one - because the check and the charge were two
// operations. Admission here is ONE linearizable conditional transaction
// across every required counter, and TestConcurrentReservationsAdmitExactlyOne
// runs the race.
//
// # The reservation key, and what is deliberately absent from it
//
// ADR-065: "Hashing tool arguments alone is prohibited as an idempotency or
// reservation key." That line encodes the #3483 replay finding, where a
// user-blind cache key replayed a non-member's allow for a segment member.
//
// So Key has NO arguments-digest field at all. An arguments-only key is not
// rejected at runtime, it is UNREPRESENTABLE, and
// TestKeyCannotBeBuiltFromArgumentsAlone pins the absence. Organization,
// actor scope and decision id are required, so a key can never be less
// specific than the principal it is charging.
//
// # Store selection
//
// The implementation here is IN-MEMORY and is a reference, not a deployment.
// It is correct for one process and wrong for more than one: two processes
// each hold their own counters, so a budget of 100 admits 200. The durable
// store is a written recommendation for the operator in
// technical-docs/RESERVATION_STORE_SELECTION.md, NOT a unilateral choice, and
// no migration ships with this package - the migration number is the
// operator's to allocate once the store is chosen.
package reservation
