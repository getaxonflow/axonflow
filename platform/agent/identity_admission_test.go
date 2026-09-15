// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "testing"

// TestTheIdentityPlaneHoldsTheSubjectAdmission pins the hand-off between the
// identity bootstrap and the enforcing planes: run.go installs the anchored
// enforcer from identityAdmission, so an initIdentityPlane that assembled the
// admission without holding it would refuse every boot that has a database.
//
// It runs initIdentityPlane as boot does, which also installs the process
// comparison adapter in the mode the environment names. Unset, that mode is
// off, and an off adapter evaluates nothing and refuses nothing: the answer
// every later test in this package already gets with no adapter installed.
func TestTheIdentityPlaneHoldsTheSubjectAdmission(t *testing.T) {
	prior := identityAdmission
	t.Cleanup(func() { identityAdmission = prior })
	identityAdmission = nil

	initIdentityPlane()

	if identityAdmission == nil || identityAdmission.Admitter == nil || identityAdmission.Registry == nil {
		t.Fatalf("initIdentityPlane did not hold a complete subject admission: %+v", identityAdmission)
	}
}
