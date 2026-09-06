// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package replay reproduces a recorded decision offline, from normalized input
// against a pinned bundle, with no stack running.
//
// ADR-065 acceptance gate 16: "replay reproduces sampled decisions from pinned
// inputs and bundles". It is the incident tool - given a decision anyone
// disputes, reproduce it on a laptop from an artifact - and it is also the
// strongest executable form of the determinism claim, because a replay that
// reproduces a decision months later has proved that nothing outside the
// recorded artifact was an input.
//
// # WHAT HAS TO BE PINNED, AND WHY IT IS MORE THAN THE BUNDLE
//
// The gate's sentence names the bundle, and the bundle alone is not enough. A
// decision is a function of the request, the signed policy bundles, AND the
// evaluation environment the engine was configured with: the action registry
// (an action's declared delegation depth and argument schema decide admission
// before any policy runs), the enforcement point's advertised capability
// profile (a mandatory obligation a PEP cannot discharge denies), and the
// approval lifetime stamped on a challenge. Change any of those and the same
// request against the same bundle produces a different decision.
//
// So an Environment carries all of it, and a Record pins the environment by
// digest as well as each bundle by digest. Two levels rather than one, because
// they fail differently: a bundle-digest mismatch means someone replayed
// against a different policy set, and an environment-digest mismatch with
// matching bundles means the policy set is right and the surface around it is
// not. Collapsing them would leave the second invisible.
//
// # REFUSAL, NEVER FALLBACK
//
// Every mismatch is an error and no decision is returned. A replay tool that
// "did its best" against a nearly-matching artifact produces a decision that
// looks authoritative and answers a different question, which in an incident
// is worse than no answer. The command exits non-zero and prints what did not
// match.
//
// # WHAT THIS PACKAGE IS NOT
//
// It is not a second evaluator. Replay builds a pdp.Engine from the pinned
// artifacts and calls Decide, so the decision it reproduces comes from the
// shipped evaluator through the shipped activation path - signature
// verification, provenance checks, document-to-bundle binding and all. A
// reimplementation would reproduce its own bugs and agree with nothing.
package replay
