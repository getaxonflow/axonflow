// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import "testing"

// TestSyntheticProbeHeaderIsAPositiveMembershipTest pins the header parser.
//
// "Non-empty" would make a proxy that echoes the header, and a caller who set
// it to "false" meaning to turn it OFF, both read as synthetic - which would
// label that traffic as the canary's.
func TestSyntheticProbeHeaderIsAPositiveMembershipTest(t *testing.T) {
	for _, yes := range []string{"1", "true", "TRUE", " true ", "True"} {
		if !IsSyntheticProbeHeader(yes) {
			t.Errorf("IsSyntheticProbeHeader(%q) = false, want true", yes)
		}
	}
	for _, no := range []string{"", "0", "false", "FALSE", "yes", "on", "2", "synthetic", "-1"} {
		if IsSyntheticProbeHeader(no) {
			t.Errorf("IsSyntheticProbeHeader(%q) = true, want false", no)
		}
	}
}
