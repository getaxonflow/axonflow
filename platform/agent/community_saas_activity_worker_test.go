// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "testing"

// TestActivityUpdateWorkerStartsExactlyOnce pins the fix for a data race that
// lived on main and that no CI job could see.
//
// startActivityUpdateWorker's doc always said "call once at startup", and
// nothing enforced it: RegisterCommunityRegistrationHandler calls it, and every
// call REPLACED the package-level activityUpdateChan while the goroutine from
// the previous call was still ranging over the old one. That is a write to a
// package variable racing a read of it, reported by `go test -race ./agent/` on
// origin/main.
//
// It survived because platform/agent is never run under the race detector in
// CI: the race-detector job covers platform/orchestrator, and the full-module
// race job covers platform/decision.
//
// The assertion is on the CHANNEL IDENTITY rather than on the absence of a
// race, because a test cannot assert the absence of a race - only the detector
// can, and only on the runs where the window is hit. Channel identity is the
// thing the race was about and it is deterministic.
func TestActivityUpdateWorkerStartsExactlyOnce(t *testing.T) {
	startActivityUpdateWorker()
	first := activityUpdateChan
	if first == nil {
		t.Fatalf("the first call started no worker channel")
	}
	for i := 0; i < 5; i++ {
		startActivityUpdateWorker()
		if activityUpdateChan != first {
			t.Fatalf("call %d replaced the activity channel; the previous worker is still ranging over the old one, which is the race this pins", i+2)
		}
	}
}
