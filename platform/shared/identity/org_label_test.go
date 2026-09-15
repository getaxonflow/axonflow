// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"fmt"
	"testing"
)

// resetOrgLabelState empties the process-wide admission set for one test and
// puts the prior set back afterwards, so the test sees a fresh cap and leaves
// the process as it found it.
func resetOrgLabelState(t *testing.T) {
	t.Helper()
	orgLabelState.mu.Lock()
	prior := orgLabelState.seen
	orgLabelState.seen = nil
	orgLabelState.mu.Unlock()
	t.Cleanup(func() {
		orgLabelState.mu.Lock()
		orgLabelState.seen = prior
		orgLabelState.mu.Unlock()
	})
}

// TestBoundedOrgLabelIsCappedAndNeverEvicts is the cardinality guard for
// every per-organization metric label in the process.
//
// The assertion is on the NUMBER OF DISTINCT LABEL VALUES rather than on the
// presence of the overflow bucket: a version that passed every organization
// through would also produce a "__over_cap__" value for an organization
// literally named that, and would still pass a presence check.
func TestBoundedOrgLabelIsCappedAndNeverEvicts(t *testing.T) {
	resetOrgLabelState(t)
	const over = MaxOrgLabelValues + 37
	distinct := map[string]bool{}
	overflow := 0
	for i := 0; i < over; i++ {
		got := BoundedOrgLabel(fmt.Sprintf("tenant-%d", i))
		distinct[got] = true
		if got == labelOverflowOrg {
			overflow++
		}
	}
	// MaxOrgLabelValues named organizations plus exactly one overflow bucket.
	if len(distinct) != MaxOrgLabelValues+1 {
		t.Fatalf("%d organizations produced %d label values, want %d (the cap plus one overflow bucket)",
			over, len(distinct), MaxOrgLabelValues+1)
	}
	if overflow != over-MaxOrgLabelValues {
		t.Fatalf("%d organizations landed in the overflow bucket, want %d", overflow, over-MaxOrgLabelValues)
	}
	// The named ones are the FIRST seen, and they are not evicted: an evicted
	// organization's series would stop moving while its traffic continued.
	if got := BoundedOrgLabel("tenant-0"); got != "tenant-0" {
		t.Fatalf("the first organization seen lost its label: %q", got)
	}
	if got := BoundedOrgLabel(fmt.Sprintf("tenant-%d", over-1)); got != labelOverflowOrg {
		t.Fatalf("an organization past the cap was admitted later: %q", got)
	}
	// An event with no organization gets its own bucket, distinct from the
	// overflow one: "we stopped naming organizations" and "this event had no
	// organization to name" are different facts.
	if got := BoundedOrgLabel("  "); got != labelUnattributedOrg {
		t.Fatalf("a blank organization got %q, want %q", got, labelUnattributedOrg)
	}
}
