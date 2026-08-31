// Package legacycompile compiles the LEGACY policy substrate - the
// static_policies and dynamic_policies tables - into ADR-065 typed policy
// documents, and records what happened to every single row.
//
// # What this package is for
//
// ADR-065 Phase 2 is shadow mode: dual-evaluate every plane and classify every
// semantic difference before anything cuts over. A diff is only meaningful if
// the two sides are evaluating the same policy set, so the first half of the
// work is a compiler that turns a legacy row into typed ADR-065 policies. This
// package is that compiler. The shadow subpackage is the diffing half.
//
// # The rule that shapes the whole design: never fix legacy semantics here
//
// The legacy substrate has defects. Three condition fields the policy editor
// offers have no resolver case and silently resolve to nothing (#3515). A
// scan failure drops a policy and still reports a successful load (#3397). An
// an override's ACTION is accepted and persisted against a dynamic policy and
// then never resolved (#3401 - the ADR-044 break-glass allow-flip is a
// different mechanism and IS enforced there). A compiler that "corrected" any of these would make the
// shadow diff report a difference that the running system does not have, and
// the entire point of the exercise is to find the differences it DOES have.
//
// So a legacy defect is REPRODUCED and RECORDED, never repaired. Each one
// produces a Reason on the row's Record naming the issue, and the shadow
// harness carries those reasons onto every diff record as CONTEXT for whoever
// triages it. They deliberately do NOT explain a difference: a faithfully
// preserved defect makes both sides behave identically, so it can never be the
// observable cause of one, and a classifier that let it be would silence
// whatever really was. See the note on the classification constants in the
// shadow subpackage. Repairing legacy behaviour is #3564's and #3565's job, on
// the new path, after the diffs are clean.
//
// # Zero silent drops
//
// Every input row produces exactly one Record. A row that cannot be decoded,
// cannot be compiled, or would have been dropped by the legacy reader itself
// still produces a Record - with a status and a reason. There is no branch in
// this package that consumes a row and emits nothing, because that is the
// #3397 defect class and reproducing it in the migration tooling would hide
// exactly the rows most likely to matter.
//
// # Two disjoint read paths
//
// static_policies is read two different ways and the two column sets do not
// overlap where it counts:
//
//   - the RUNTIME path (platform/shared/policy/loader.go's loadFromDatabase,
//     LoadSystemPolicies and GetPolicyByID) selects phase, action_request and
//     action_response, and never selects action;
//   - the EFFECTIVE path (the same file's effectivePolicyColumns, used by the
//     agent's StaticPolicyRepository.GetEffective for the proxy tier engine)
//     selects action and none of the phase columns.
//
// A compiler that read one path would mistranslate every row whose columns
// disagree, and rows whose columns disagree are precisely the population this
// migration exists to find. Both paths are compiled, per plane, and a row
// whose two paths resolve to different actions is recorded as such.
//
// # This package does not talk to a database
//
// It takes rows. Capture is a separate, lossless step (see
// scripts/legacy-policy-capture.sh and CAPTURE.md) for three reasons: the
// decision module deliberately carries no database driver; a captured corpus
// can be pinned, replayed and diffed against a later capture; and the capture
// step is where the RLS scoping that the legacy readers use has to be
// reproduced faithfully, which is a property of the read, not of the compiler.
package legacycompile
