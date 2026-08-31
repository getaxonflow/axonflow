// Package registry is the ADR-065 action, tool, resource-type and PEP
// registry: the catalog every governed operation resolves against before a
// policy runs.
//
// ADR-065 "Tool, action, and resource registry" makes two things structural
// that were previously inferred per plane. The first is that an operation with
// no registered action is refused at admission rather than evaluated: an
// unregistered surface has no declared behaviour to consult, so there is
// nothing for a policy to be about. The second is that the failure semantics of
// a registered action are DECLARED rather than defaulted, which is what this
// package's posture rules exist for.
//
// # WHAT LIVES WHERE, AND WHY THIS IS NOT A SECOND CATALOG
//
// platform/decision/pdp already carries an admission-time Registry: the map the
// evaluator consults for the action entry and the declared realm set. This
// package does not replace it and does not restate it. It is the REGISTRATION
// and GOVERNANCE layer whose output IS that map, produced by PDPRegistry. A
// catalog that cannot be validated cannot be projected, so a record that fails
// a registration rule never reaches an evaluator at all rather than reaching it
// with a field nobody filled in.
//
// The same applies in the other direction: the tags, argument schema, payload
// leaves and risk classes on an action are declared here ONCE and projected
// into pdp.ActionEntry. A second declaration is a second thing to drift.
//
// # TOOL VERSUS ACTION, AND WHERE POSTURE LIVES
//
// The source specification has a single governed object, Tool, keyed by the
// name the caller passed, and hangs posture on it. ADR-065 splits that in two:
// a canonical ACTION with aliases, and the concrete callable surfaces that
// resolve to it. That split is the reason "every governed operation resolves to
// one registered action or fails closed" is expressible at all, because two
// connectors exposing the same operation under two names must not be two
// governed things.
//
// Posture therefore lives on the ACTION and a tool cannot override it. A tool
// carrying its own posture would be a second authority for one fact, and the
// resolution between them would be a rule nobody reads. A tool is still
// unregisterable without a fully declared posture, because a tool is
// unregisterable unless it binds to a registered action and an action is
// unregisterable unless both posture axes are declared. That is the same
// property the brief asks for, enforced one level down where the fact lives.
//
// # POSTURE: TWO AXES, BOTH MANDATORY, NEITHER DEFAULTED
//
// A posture declares what happens on the two ways a decision can fail to be a
// permit: no permission matched (Unmatched) and the evaluation could not
// complete (OnError). Both are mandatory and neither has a default, an
// inference or a global fallback. A registration that omits one is refused.
//
// The legal VALUES are narrower than the source proposal's, and deliberately:
//
//   - Unmatched is not_applicable or permit. It is NOT deny. Under ADR-065's
//     four-valued outcome, deny means an explicit constraint matched, and
//     seeding the fold with deny would report a constraint that never fired.
//     Both land on the PEP state DENY through contract.StateFor; the difference
//     is that the operator is told which of the two happened, which EX-36 turns
//     into an executable requirement.
//   - OnError is indeterminate or permit. Same argument: an evaluation error is
//     not an explicit constraint.
//   - permit on either axis is the source proposal's fail-open, which ADR-065
//     reverses as an owned product and security decision. Unmatched=permit is
//     accepted ONLY where the action carries a live compatibility exception and
//     is not privileged, irreversible or data-egress. OnError=permit is refused
//     outright, with no exception available, because an on_error permit turns
//     every dependency outage into a widening of access.
//
// # GOVERNED TAGS ARE A POLICY CHANNEL
//
// A policy selects actions by tag, so a tag edit is a policy edit reaching the
// evaluator without touching a policy document. Tags are therefore a declared
// vocabulary here, and a change to a governed tag is a registry EVENT carrying
// an approval reference rather than a field somebody overwrites. Registration
// is create-only for the same reason: re-registering an action with a different
// tag set would be the bypass that makes the change path advisory.
//
// Both directions of a governed-tag change raise an alarm. Removal disarms
// every constraint selecting on that tag; addition arms every permission
// selecting on it, and neither shows up as an edit to any policy document.
//
// # EDITION IS A PROPERTY OF THE ENFORCEMENT POINT, NOT OF THIS BINARY
//
// Whether a Policy Enforcement Point can discharge an obligation depends on the
// build and licence of THAT enforcement point, which is frequently not this
// process: a community gateway, an SDK interceptor or a plugin can enforce
// decisions taken by an Enterprise PDP. Edition is therefore a field on the PEP
// record and an input to the capability check, not a compile-time build tag.
// A build tag would state a fact about the wrong machine, and in this module it
// would also state it in a file that no CI lane compiles.
package registry
