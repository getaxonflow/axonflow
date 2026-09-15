// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package deploymode

import "testing"

// TestIsLicenceTransitionAcceptsExactlyTheCommunityToken is the accepting-set
// assertion, written the way IsCommunityPosture's is and for the same reason.
//
// The template writes ONE value onto both the DEPLOYMENT_MODE override and this
// declaration (ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml,
// condition IsLicenceTransition). A predicate that accepted more than that
// token would let a stack be half-transitioned - the enforcement plane in the
// community posture while the declaration says something else - and a
// predicate that accepted ANY non-empty value would turn every unrelated
// spelling into a declared wind-down, which is the permissive direction for a
// value whose whole job is to SUPPRESS a boundary check.
func TestIsLicenceTransitionAcceptsExactlyTheCommunityToken(t *testing.T) {
	if !IsLicenceTransition(ModeCommunity) {
		t.Fatalf("IsLicenceTransition(%q) = false; that is the one value the template writes", ModeCommunity)
	}
	for _, raw := range []string{
		"",                  // unset: the overwhelming majority of deployments
		" community",        // not trimmed, for IsCommunityPosture's reason
		"Community",         // not case-folded
		"community-saas",    // its own mode, never this one
		"disabled",          // the parameter's inert default
		"in-vpc-enterprise", // an entitled mode is not a wind-down
		"true",              // the shape an operator guesses at
		"enterprise",
	} {
		if IsLicenceTransition(raw) {
			t.Errorf("IsLicenceTransition(%q) = true; the accepting set is exactly %q, so an unrecognised value "+
				"must NOT declare a transition - it would suppress the construct boundary on a deployment that "+
				"never said its licence had ended", raw, ModeCommunity)
		}
	}
}

// TestCurrentIsLicenceTransitionReadsItsOwnVariable pins WHICH variable the
// process form reads.
//
// The declaration exists precisely because DEPLOYMENT_MODE cannot carry it: the
// override makes a transitioned deployment and a genuine Community one the same
// nine bytes (#4094). A reader that fell back to DEPLOYMENT_MODE would put that
// hole straight back, and would do it silently - every Community deployment
// would report a wind-down.
func TestCurrentIsLicenceTransitionReadsItsOwnVariable(t *testing.T) {
	t.Setenv(EnvDeploymentMode, ModeCommunity)
	t.Setenv(EnvLicenceTransition, "")
	if CurrentIsLicenceTransition() {
		t.Fatalf("a deployment with %s=%q and no %s reported a licence transition; that is every genuine Community "+
			"deployment, and the boundary would stop being enforced on all of them",
			EnvDeploymentMode, ModeCommunity, EnvLicenceTransition)
	}

	t.Setenv(EnvLicenceTransition, ModeCommunity)
	if !CurrentIsLicenceTransition() {
		t.Fatalf("%s=%q did not report a licence transition", EnvLicenceTransition, ModeCommunity)
	}

	// AND IT IS NOT THE DEPLOYMENT MODE'S VALUE. Without this case a reader
	// spelled os.Getenv(EnvDeploymentMode) would pass both assertions above on
	// a transitioned stack, because the template writes the same token to both.
	t.Setenv(EnvDeploymentMode, "in-vpc-enterprise")
	if !CurrentIsLicenceTransition() {
		t.Fatal("the transition declaration stopped being read when DEPLOYMENT_MODE changed; it is reading the " +
			"wrong variable, and on a real stack the two carry the same token so nothing else would notice")
	}
}
