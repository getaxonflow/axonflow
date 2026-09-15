// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package heartbeat

// HealthMembersBothPlanesMustCarry names the /health members the agent and the
// orchestrator are both required to emit.
//
// WHY A SHARED LIST RATHER THAN TWO TESTS THAT HAPPEN TO AGREE.
//
// The orchestrator's own /health comment has stated the rule for two releases -
// "a client that probes whichever port it can reach must get the same answer" -
// and the planes diverged anyway (#3901 §3): the agent carried `tier` and the
// orchestrator did not, and nothing compared them. A rule written as prose
// beside one of the two things it governs is not a rule, it is a hope.
//
// This list is imported by a driven test in EACH plane's package, which is the
// only arrangement available: platform/orchestrator imports platform/agent, so
// no test in platform/agent can reach the orchestrator's handler, and the two
// handlers can never be called from one place. Both tests CALL their handler
// and read the JSON it wrote - neither reads the source.
//
// Adding a member here reds both planes until both emit it, which is the
// property that makes it a contract rather than a comment.
//
// WHAT IS DELIBERATELY NOT HERE: members that are honestly plane-specific.
// `components` and `features` describe subsystems only the orchestrator owns;
// `tier_admission` reports a ledger only the agent runs. Requiring those of
// both planes would force one of them to emit a member it has nothing to put
// in, and a field that is always null is worse than an absent one.
func HealthMembersBothPlanesMustCarry() []string {
	return []string{
		// The identity block. `edition` and `deployment_mode` are omitted when
		// the platform cannot determine them, so they are NOT here - see
		// HealthIdentityMembers. These four are unconditional on both planes.
		"status",
		"service",
		"version",
		"timestamp",
		// The licence tier. The member #3901 §3 found missing on one plane.
		"tier",
		// The compatibility pins an SDK heartbeat relays.
		"capabilities",
		"sdk_compatibility",
		"plugin_compatibility",
	}
}
