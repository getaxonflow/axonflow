// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "axonflow/platform/agent/license"

// orchestratorLicenseTier is the licence tier for GET /health.
//
// WHY IT EXISTS RATHER THAN AN INLINE tierChecker.Tier() CALL: tierChecker is a
// package global assigned during Run(), and /health is registered BEFORE the
// rest of initialization so a load balancer can probe a starting process. A
// bare call would panic on a nil interface for exactly the window the endpoint
// is there to serve.
//
// The "starting" sentinel matches what the agent's currentLicenseTier() returns
// in the same window (platform/agent/run.go), because the two planes answering
// a probe differently is the divergence #3901 §3 is about - including when the
// answer is "I do not know yet".
func orchestratorLicenseTier() string {
	// NO SPECIAL CASE FOR A NIL tierChecker, and the comment that used to be
	// here was wrong about why one was needed. It said converting a nil
	// LicenseChecker to a tierReader "would produce a NON-nil interface holding
	// a nil value". It does not: `tierChecker` is an INTERFACE, and converting
	// a nil interface value to another interface type yields nil. Go boxes a
	// concrete value in an interface, never an interface in an interface.
	//
	// The trap that DOES exist is the other one, and neither version handles
	// it: a TYPED NIL POINTER stored in tierChecker makes `tierChecker == nil`
	// false, so it arrives as a non-nil tierReader and panics on c.Tier().
	// Nothing in this tree assigns one - run.go:1412 assigns the value returned
	// by NewEnvLicenseChecker - so this is left as it is rather than guarded
	// against a case that cannot arise, which would be a second false claim in
	// the same place.
	return licenseTierFrom(tierChecker)
}

// tierReader is the one method licenseTierFrom needs. LicenseChecker has 24,
// and a test stubbing all of them to reach one branch is a test nobody writes -
// which is how both production branches came to be unreachable.
type tierReader interface {
	Tier() license.Tier
}

// licenseTierFrom is the logic, separated from the global so it can be driven.
//
// R3 FOUND THAT THE ONLY BRANCH A TEST COULD REACH WAS THE SENTINEL. With the
// logic reading `tierChecker` directly, a unit test always saw a nil global and
// therefore always saw "starting"; mutating BOTH production returns to garbage
// left TestOrchestratorHealthTierIsTheLicenceVocabulary green. A test that
// exists to pin which vocabulary /health reports, and which cannot reach the
// branch production takes, pins nothing.
//
// The nil case is not a test artefact: /health is registered before the rest of
// initialization so a load balancer can probe a starting process, and
// `tierChecker` is assigned during Run(). "starting" is what the agent's
// currentLicenseTier() answers in the same window, and the two planes
// disagreeing about how to say "I do not know yet" is the divergence #3901 §3
// is about.
func licenseTierFrom(c tierReader) string {
	if c == nil {
		return "starting"
	}
	t := c.Tier()
	if t == "" {
		return string(license.TierCommunity)
	}
	return string(t)
}
