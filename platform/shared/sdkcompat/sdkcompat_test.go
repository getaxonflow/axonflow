// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package sdkcompat

import "testing"

// TestPinnedToReleaseTrain makes a version bump a deliberate, reviewed edit in
// one place. It is the successor to the orchestrator-side
// TestSDKCompatibilityPinnedToReleaseTrain, which guarded only one of the two
// former copies -- and which, being a literal pinned beside a literal, agreed
// with a stale value just as happily as with a current one on the plane it did
// not read.
func TestPinnedToReleaseTrain(t *testing.T) {
	wantMin := map[string]string{
		"python": "8.0.0", "typescript": "8.0.0", "go": "8.0.0",
		"java": "8.0.0", "rust": "0.7.0",
	}
	wantRecommended := map[string]string{
		"python": "9.3.0", "typescript": "9.3.0", "go": "9.3.0",
		"java": "9.3.0", "rust": "0.10.0",
	}
	for id, want := range wantMin {
		if got := MinVersions()[id]; got != want {
			t.Errorf("MinVersions()[%q] = %q; want %q", id, got, want)
		}
	}
	for id, want := range wantRecommended {
		if got := RecommendedVersions()[id]; got != want {
			t.Errorf("RecommendedVersions()[%q] = %q; want %q", id, got, want)
		}
	}
	if len(MinVersions()) != len(wantMin) || len(RecommendedVersions()) != len(wantRecommended) {
		t.Errorf("entry counts drifted: min=%d recommended=%d", len(MinVersions()), len(RecommendedVersions()))
	}
	if len(IDs()) != len(wantRecommended) {
		t.Errorf("IDs() returned %d ids, want %d", len(IDs()), len(wantRecommended))
	}
}

// TestCopyOfEmptyIsNotNil pins that an empty source yields {} and never null on
// the wire.
func TestCopyOfEmptyIsNotNil(t *testing.T) {
	got := copyOf(map[string]string{})
	if got == nil {
		t.Fatal("copyOf returned nil for an empty source; the JSON shape would change from {} to null")
	}
	if len(got) != 0 {
		t.Errorf("expected an empty map, got %d entries", len(got))
	}
}

// TestReturnedMapsAreCopies pins that a caller mutating what it was handed
// cannot reach the package-level maps. Both planes serve these on /health in the
// same process.
func TestReturnedMapsAreCopies(t *testing.T) {
	for name, get := range map[string]func() map[string]string{
		"MinVersions":         MinVersions,
		"RecommendedVersions": RecommendedVersions,
	} {
		first := get()
		if len(first) == 0 {
			t.Fatalf("%s returned an empty map; mutating an empty map proves nothing", name)
		}
		const sentinel = "0.0.0-mutated-by-a-caller"
		for k := range first {
			first[k] = sentinel
		}
		for k, v := range get() {
			if v == sentinel {
				t.Errorf("%s: key %q reads back the caller's mutation; the source of truth is shared, not copied", name, k)
			}
		}
	}
}
