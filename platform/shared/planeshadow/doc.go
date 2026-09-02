// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package planeshadow dual-evaluates every ADR-065 enforcement plane in
// production and records the semantic difference. It never enforces anything.
//
// ADR-065 Phase 2 is "dual-evaluate every plane and store semantic diffs", and
// acceptance gate 18 - "shadow migration has no unexplained fail-open
// difference for the agreed window" - is what v11's cutover is gated on. #3577
// built the measurement half OFFLINE: a compiler, a classifier and a twelve-
// plane harness over captured policy rows. Nothing consulted the PDP at
// runtime, so the window had no production evidence to accumulate. This
// package is the production half.
//
// # THE ONE-WAY GUARANTEE, AND WHY IT IS A PROPERTY OF THE SIGNATURE
//
// Observe returns NOTHING.
//
// #3582's identity adapter proves non-enforcement with a predicate: enforces()
// is positive membership on the single enforcing mode, and every refusal is
// built in one function under it. That is a good guarantee and this package
// keeps its equivalent (ShadowMode.records(), and "enforce" refused at parse -
// see identity.ParseDecisionShadowMode). But it is a guarantee about what the
// package DOES with a value it hands back, and the identity adapter's own file
// doc concedes the residue: CompatOutcome.Subject is exported, a call site
// COULD read it, and nothing structural stops one.
//
// Here there is no value. Observe's signature is
//
//	func Observe(ctx context.Context, obs Observation)
//
// so "no code path from the recorded outcome to the response" is not a
// discipline every call site has to keep - it is arithmetic. There is nothing
// to return, nothing to read, and nothing to branch on. A call site that
// wanted to enforce on the shadow's opinion would have to be given a new API
// to do it with, which is a visible change in a diff rather than a quiet one.
//
// The second half of the same guarantee is TIME. The PDP evaluation does not
// happen on the request path at all: Observe resolves the organization's mode,
// builds a case, hands it to a bounded queue and returns. (That mode read is
// the one part of Observe with a real cost - a memoized store read, and a
// bounded database round trip once per organization per TTL window. It is
// measured by axonflow_decision_shadow_enqueue_seconds and stated in the
// operator documentation; it is not free and is not described as free.)
//
// Compilation, OPA evaluation, classification and recording all run on a
// worker AFTER the plane's response has already been decided and, in the
// ordinary case, already been written. A verdict that does not exist yet
// cannot influence a response that has already gone out.
//
// # THE LEGACY SIDE IS THE VERDICT THE PLANE ALREADY COMPUTED
//
// Never a second evaluation. CAPTURE.md states the rule and it is right: "a
// second evaluation is a second answer, not the same one". A plane hands over
// what it actually decided - blocked or not, which rows matched, which action
// each resolved to - and this package normalizes THAT into shadow.Verdict
// using the legacy vocabulary (shadow.LegacyEffect over row keys), never into
// obligations. The classifier's correspondence table is the second,
// independent statement of the compiler's mapping, and an adapter that emitted
// obligations would collapse the two sides of the diff into one.
//
// It also removes the largest item in shadow.ModelLimitations from the runtime
// path by construction. Item 1 is that DEPLOYMENT_MODE=community turns
// require_approval into ALLOW while the offline model reports a deny - wrong
// in the fail-open direction for an entire deployment mode. Here Executable
// comes off the real result, so the model cannot be wrong about it. Where
// community mode really does admit what ADR-065 would refuse, that is a
// genuine legacy_permitted_new_denied: the SAFE direction, visible instead of
// modelled.
//
// # ONE OBSERVATION SITE PER EVALUATOR, NOT ONE PER PLANE
//
// The twelve planes reach nineteen call sites (see
// platform/decision/legacycompile/legacy_call_sites.tsv, which
// legacy_call_site_census_test.go pins to the tree in both directions) but
// only THREE evaluator entry points. The observation happens inside those
// three, which is the function the call sites share - a call site that forgets
// to observe cannot exist, because there is nothing at the call site to
// forget. This is compat.go's argument and
// [[feedback_a_guard_at_the_callers_is_not_a_guard]].
//
// What a call site does supply is which plane it is, as EvalOptions.Plane. That
// is data, not a decision, and its zero value is refused rather than defaulted:
// an unset plane is recorded under its own reason and never attributed to some
// plane. TestEveryPolicyCallSiteNamesItsPlane derives the required set from the
// census artifact, so a new call site fails on the PR that adds it.
//
// # THE MODE, THE PER-ORGANIZATION AXIS, AND THE ONE READ
//
// Two inputs, one read, exactly as #3596 arranged for the identity axis:
//
//	AXONFLOW_DECISION_SHADOW_MODE      deployment-wide (off | shadow)
//	identity_org_settings.decision_shadow_mode   per organization
//
// composed by identity.EffectiveMode - the SAME exported function
// CompatAdapter.effectiveMode calls, not a copy of its rule. The record wins in
// both directions; an absent record means the process flag; an unreadable one
// means the process flag and is counted. #3596 made that argument once, and a
// second axis restating it is one edit away from disagreeing with it.
//
// The vocabulary is identity.CompatMode, so "shadow" means the same thing to an
// operator on both axes, and "enforce" is refused three times over: at parse,
// by the column's CHECK, and again at the single read site - because a CHECK
// installed by one migration is not evidence about a row a restore or a later
// migration might write.
//
// # WHY THE DENOMINATOR IS A FIRST-CLASS OUTPUT
//
// Zero unexplained differences out of zero comparisons passes forever, passes
// hardest when the harness is broken, and passes silently. The offline gate
// refuses a vacuous corpus for exactly that reason. The production window had
// no equivalent guard, which is what the 2026-08-31 observation-window read
// found for the identity axis and why the v11 clock has not started.
//
// So every hole in the denominator is counted and exported, not inferred:
// observations attempted, sampled out, dropped by backpressure, refused for a
// missing plane, and - the subtle one - NOT COMPARABLE, where the bundle was
// compiled from a different policy snapshot than the one the plane evaluated
// against. A not-comparable pair is never a match (which would inflate
// agreement) and never unexplained (which would red the gate on an ordinary
// cache refresh). It is its own counter, and a rising one is a defect in this
// package rather than in the migration.
package planeshadow
