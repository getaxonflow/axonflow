// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package approval is the ADR-065 approval authority: a conjunction of
// immutable threshold clauses, with separation of duties, self-exclusion,
// duplicate prevention, expiry, cancellation, revocation and epoch binding
// (issue #3560, epic #3551).
//
// # Edition
//
// EVERY file in this package except this one carries `//go:build enterprise`.
// HITL approval is Enterprise (operator decision, 2026-08-26: the entitled
// tiers are Professional, Enterprise and Enterprise Plus), so the community
// mirror ships this package with no symbols in it. This doc file is
// deliberately untagged so that the package still exists on the mirror and
// `go build ./...` behaves identically on both editions rather than depending
// on how the toolchain treats a directory whose every file is excluded.
//
// # The correction this package exists for
//
// The source proposal treats approval as a value in a flattened permission
// lattice and combines two threshold requirements by intersecting their
// approver pools. That is mathematically wrong for compound thresholds:
//
//	2-of-{A,B}  MEET  2-of-{B,C}   ==(intersection)==>  2-of-{B}
//
// which no set of approvers can satisfy, so the system denies a request that
// {A,B,C} plainly should be able to approve. ADR-065 keeps the clauses as a
// CONJUNCTION. They are never flattened, never intersected and never unioned;
// identical clauses deduplicate, and that is the only reduction there is.
//
// # Two things that are unrepresentable rather than merely forbidden
//
//   - `on_timeout=permit`. There is no timeout-disposition field anywhere in
//     Requirement. Timeout is always deny, and the way to guarantee that is to
//     give a permissive timeout nowhere to live.
//   - A mutable Requirement. NewRequirement returns a value with unexported
//     fields and no setters, so a clause cannot be widened after approvers
//     have been collected against the narrower version.
//
// # Self-exclusion changes outcomes, and the trace has to say so
//
// Nobody in the request's own actor chain may approve it. That is not
// conditional on the separation-of-duties flag - a requester approving their
// own request is not oversight under any configuration. The consequence is
// counter-intuitive in a way that reads as a bug unless it is surfaced: a
// SENIOR approver who initiated the request is excluded and their approval
// does not count, while a JUNIOR colleague who escalates it is not in the
// chain and theirs does. Every exclusion is therefore reported in the verdict
// with its reason, and Verdict.Exclusions is not optional output.
//
// # Identity
//
// Principals are opaque canonical strings in the ADR-065 wire form
// `<SubjectType>::<realm_id>:<subject_id>`. This package does NOT own
// identity: group closure, nesting and realm qualification are resolved
// through the injected EligibilityResolver, which #3556/#3557 own. The only
// string surgery here is the syntactic check in principal.go, and it is
// explicitly temporary.
package approval
